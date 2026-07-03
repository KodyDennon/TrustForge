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
  const jsonLd = {
    "@context": "https://schema.org",
    "@type": "SoftwareSourceCode",
    name: "TrustForge",
    description: "Open-Source Trust Fabric for AI-Native Software and zero-trust cryptographic protocols.",
    url: "https://trustforge.dev",
    programmingLanguage: ["TypeScript", "Rust"],
    license: "https://opensource.org/licenses/Apache-2.0",
    publisher: {
      "@type": "Organization",
      name: "TrustForge Protocol",
      logo: {
        "@type": "ImageObject",
        url: "https://trustforge.dev/icon.jpg"
      }
    }
  };

  return (
    <html lang="en">
      <head>
        <script
          type="application/ld+json"
          dangerouslySetInnerHTML={{ __html: JSON.stringify(jsonLd) }}
        />
      </head>
      <body className={inter.className}>{children}</body>
    </html>
  );
}
