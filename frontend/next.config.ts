import type { NextConfig } from "next";

const nextConfig: NextConfig = {
  reactStrictMode: true,
  async rewrites() {
    const backendBase = process.env.BACKEND_URL || "http://127.0.0.1:8080";
    return [
      {
        source: "/api/backend/:path*",
        destination: `${backendBase}/api/v1/:path*`,
      },
      {
        source: "/mcp",
        destination: `${backendBase}/mcp`,
      },
      {
        source: "/actuator/:path*",
        destination: `${backendBase}/actuator/:path*`,
      },
    ];
  },
};

export default nextConfig;
