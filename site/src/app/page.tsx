import React from 'react';

export default function Home() {
  return (
    <main>
      <header className="nav-header">
        <div className="logo gradient-text">TrustForge</div>
        <nav className="nav-links">
          <a href="#features">Features</a>
          <a href="https://github.com/KodyDennon/TrustForge" target="_blank" rel="noopener noreferrer">GitHub</a>
          <a href="https://docs.trustforge.dev" target="_blank" rel="noopener noreferrer">Docs</a>
        </nav>
      </header>

      <section className="hero container">
        <h1>
          The Next Era of Security is <br />
          <span className="gradient-text">Verifiable Action.</span>
        </h1>
        <p className="subtitle">
          TrustForge is the open-source trust fabric for AI-native software. Secure devices, authenticate live systems, and mint verifiable credentials with zero-trust architectures.
        </p>
        <div style={{ display: 'flex', gap: '1rem', flexWrap: 'wrap', justifyContent: 'center' }}>
          <a href="https://github.com/KodyDennon/TrustForge" className="cta-button">
            View on GitHub
          </a>
          <a href="#features" className="cta-button cta-secondary">
            Explore Protocol
          </a>
        </div>
      </section>

      <section id="features" className="container" style={{ paddingBottom: '8rem' }}>
        <div className="features-grid">
          <div className="glass-panel">
            <h3 style={{ marginBottom: '1rem', fontSize: '1.5rem' }}>AI-Native Security</h3>
            <p style={{ color: '#a5a5b0' }}>
              Designed from the ground up for autonomous agents. Issue capabilities and verify programmatic actions with mathematical certainty.
            </p>
          </div>
          <div className="glass-panel">
            <h3 style={{ marginBottom: '1rem', fontSize: '1.5rem' }}>Cryptographic Proofs</h3>
            <p style={{ color: '#a5a5b0' }}>
              Every action in the TrustForge protocol requires a signed, verifiable packet. Say goodbye to leaked bearer tokens.
            </p>
          </div>
          <div className="glass-panel">
            <h3 style={{ marginBottom: '1rem', fontSize: '1.5rem' }}>Universal Adapters</h3>
            <p style={{ color: '#a5a5b0' }}>
              Seamlessly integrate with Next.js, Axum, Cloudflare Workers, Express, and bare-metal embedded targets via a unified SDK.
            </p>
          </div>
        </div>
      </section>
    </main>
  );
}
