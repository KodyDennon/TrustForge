import React from 'react';
import Link from 'next/link';

export const Footer = () => {
  return (
    <footer>
      <div className="container footer-container">
        <div>
          <strong>TrustForge Protocol</strong>
          <p style={{ marginTop: '0.5rem' }}>Verifiable Action at the Edge. Open-source under Apache 2.0.</p>
        </div>
        <div style={{ display: 'flex', gap: '2rem' }}>
          <div style={{ display: 'flex', flexDirection: 'column', gap: '0.5rem' }}>
            <span style={{ color: 'var(--text)', fontWeight: 600 }}>Resources</span>
            <Link href="/docs">Documentation</Link>
            <Link href="/architecture">Architecture</Link>
            <Link href="/agents">AI Agents</Link>
          </div>
          <div style={{ display: 'flex', flexDirection: 'column', gap: '0.5rem' }}>
            <span style={{ color: 'var(--text)', fontWeight: 600 }}>Links</span>
            <a href="https://github.com/KodyDennon/TrustForge" target="_blank" rel="noopener noreferrer">GitHub</a>
            <a href="https://crates.io/crates/trustforge-core" target="_blank" rel="noopener noreferrer">Crates.io</a>
          </div>
        </div>
      </div>
    </footer>
  );
};

export default Footer;
