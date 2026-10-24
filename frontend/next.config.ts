import type { NextConfig } from "next";

const backendUrl = process.env.BACKEND_INTERNAL_URL || 'http://127.0.0.1:8000';

const nextConfig: NextConfig = {
  output: 'standalone',
  // The encrypted 10 MiB padding bucket has a 16-byte MAC plus multipart headers.
  // FastAPI still enforces the exact ciphertext limit per file.
  experimental: { proxyClientMaxBodySize: 12 * 1024 * 1024 },
  async rewrites() {
    return [
      {
        source: '/api/:path*',
        destination: `${backendUrl}/api/:path*`,
      },
    ];
  },
};

export default nextConfig;
