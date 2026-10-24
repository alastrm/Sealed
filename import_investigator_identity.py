"""Import a browser-generated encrypted v2 identity; archive the previous identity."""
import argparse
import json
from pathlib import Path

from fastapi import HTTPException
from sqlalchemy import select, update

from database import SessionLocal
from message_protocol import validate_identity
from migrate_v2 import require_schema
from database import engine
from models import Investigator, InvestigatorIdentity
from seed import TEST_INVESTIGATOR


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--username', required=True)
    parser.add_argument('--file', required=True, help='Encrypted JSON exported by /investigator/setup')
    args = parser.parse_args()
    require_schema(engine)
    try:
        path = Path(args.file)
        if path.stat().st_size > 16384:
            parser.error('Identity file is too large.')
        packet = json.loads(path.read_text(encoding='utf-8'))
        validate_identity(packet)
    except (OSError, ValueError, HTTPException) as error:
        parser.error(getattr(error, 'detail', 'Cannot read identity bundle.'))
    if packet['publicKey'] == TEST_INVESTIGATOR['public_key']:
        parser.error('The public demonstration encryption identity cannot be used for v2.')
    with SessionLocal() as db:
        owner = db.execute(select(Investigator).where(Investigator.username == args.username)).scalars().first()
        if owner is None:
            parser.error('Unknown existing investigator. Configure the account/access separately.')
        if db.get(InvestigatorIdentity, packet['signingPublicKey']) is not None:
            parser.error('Identity already exists; refusing to replace encrypted key material.')
        db.execute(update(InvestigatorIdentity).where(InvestigatorIdentity.investigator_id == owner.id).values(active=0))
        db.add(InvestigatorIdentity(
            signing_public_key=packet['signingPublicKey'], public_key=packet['publicKey'],
            investigator_id=owner.id, identity_signature=packet['identitySignature'],
            encrypted_bundle=json.dumps(packet), active=1,
        ))
        db.commit()
    print('Identity imported. Previous identities/cases are archived, not overwritten.')
    print('Install the signing-key pin directly from the trusted browser export in frontend/.env.local.')
    print('Restart/rebuild the frontend after changing its explicit pin allowlist.')


if __name__ == '__main__':
    main()
