/** @type {import('next').NextConfig} */
const nextConfig = {
  reactStrictMode: true,
  // @catdef/shared workspace paketini Next derlemesine dahil et.
  transpilePackages: ["@catdef/shared"],
};

export default nextConfig;
