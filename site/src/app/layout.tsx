import type { Metadata } from "next";
import { Inter } from "next/font/google";
import "./globals.css";
import Header from "../components/Header";
import Footer from "../components/Footer";

const inter = Inter({ subsets: ["latin"] });

export const metadata: Metadata = {
  title: "TrustForge | Verifiable Action at the Edge",
  description:
    "TrustForge is a high-performance open-source trust fabric designed for AI agents and distributed systems. Generate cryptographic proofs, negotiate stateless boundaries, and enforce policies on the edge.",
  keywords: ["trustforge", "zero trust", "AI security", "verifiable action", "authentication", "authorization", "cryptography"],
  openGraph: {
    title: "TrustForge Protocol",
    description: "The next era of security is verifiable action.",
    url: "https://trustforge.dev",
    siteName: "TrustForge",
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
      <body className={inter.className}>
        <Header />
        {children}
        <Footer />
      </body>
    </html>
  );
}
