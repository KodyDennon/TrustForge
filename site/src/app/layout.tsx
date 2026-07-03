import type { Metadata } from "next";
import { Inter } from "next/font/google";
import "./globals.css";

const inter = Inter({ subsets: ["latin"] });

export const metadata: Metadata = {
  title: "TrustForge | Open-Source Trust Fabric for AI-Native Software",
  description:
    "TrustForge is the next-generation protocol for zero-trust verifiable action. Secure devices, authenticate live systems, and mint verifiable credentials.",
  keywords: ["trustforge", "zero trust", "AI security", "verifiable action", "authentication", "authorization", "cryptography"],
  openGraph: {
    title: "TrustForge Protocol",
    description: "The next era of security is verifiable action. Build secure, AI-native software.",
    url: "https://trustforge.dev",
    siteName: "TrustForge",
    images: [
      {
        url: "https://trustforge.dev/og-image.png",
        width: 1200,
        height: 630,
      },
    ],
    locale: "en_US",
    type: "website",
  },
  twitter: {
    card: "summary_large_image",
    title: "TrustForge",
    description: "Open-Source Trust Fabric for AI-Native Software.",
  },
};

export default function RootLayout({
  children,
}: Readonly<{
  children: React.ReactNode;
}>) {
  return (
    <html lang="en">
      <body className={inter.className}>{children}</body>
    </html>
  );
}
