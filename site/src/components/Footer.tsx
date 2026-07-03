import React from 'react';
import Link from 'next/link';

export const Footer = () => {
  return (
    <footer>
      <div className="container footer-grid">
        <div className="footer-brand">
          <strong>TrustForge Protocol</strong>
          <p>Verifiable Action at the Edge. Open-source under Apache 2.0.</p>
        </div>
        <div className="footer-nav">
          <strong>Resources</strong>
          <Link href="/docs">Documentation</Link>
          <Link href="/architecture">Architecture</Link>
          <Link href="/agents">AI Agents</Link>
        </div>
        <div className="footer-nav">
          <strong>Links</strong>
          <a href="https://github.com/KodyDennon/TrustForge" target="_blank" rel="noopener noreferrer">GitHub</a>
          <a href="https://crates.io/crates/trustforge-core" target="_blank" rel="noopener noreferrer">Crates.io</a>
        </div>
      </div>
    </footer>
  );
};

export default Footer;
