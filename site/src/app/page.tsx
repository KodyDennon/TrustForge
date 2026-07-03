import React from 'react';

export default function Home() {
  return (
    <main>
      <header className="nav-header">
        <div className="logo gradient-text">TrustForge</div>
        <nav className="nav-links">
          <a href="#features">Features</a>
          <a href="#how-it-works">How it Works</a>
          <a href="https://github.com/KodyDennon/TrustForge" target="_blank" rel="noopener noreferrer">GitHub</a>
        </nav>
      </header>

      <section className="hero container">
        <div className="hero-content">
          <div className="badge">v0.1.1 Experimental</div>
          <h1>
            The Next Era of Security is <br />
            <span className="gradient-text">Verifiable Action.</span>
          </h1>
          <p className="subtitle">
            TrustForge is the open-source trust fabric for AI-native software. Secure devices, authenticate live systems, and mint verifiable cryptographic proofs with zero-trust architectures.
          </p>
          <div className="cta-group">
            <a href="https://github.com/KodyDennon/TrustForge" className="cta-button">
              View on GitHub
            </a>
            <a href="https://www.npmjs.com/package/@trustforge-protocol/core" target="_blank" rel="noopener noreferrer" className="cta-button cta-secondary">
              npm install @trustforge-protocol/core
            </a>
          </div>
        </div>
      </section>

      <section id="features" className="container section-padding">
        <div className="section-header">
          <h2>Protocol Surface</h2>
          <p>A unified cryptographic trust fabric deployed across the entire stack.</p>
        </div>
        <div className="features-grid">
          <div className="glass-panel hover-card">
            <div className="icon-wrapper">🛡️</div>
            <h3>AI-Native Security</h3>
            <p>
              Designed from the ground up for autonomous agents. Issue capabilities and verify programmatic actions with mathematical certainty—not just bearer tokens.
            </p>
          </div>
          <div className="glass-panel hover-card">
            <div className="icon-wrapper">🔐</div>
            <h3>Cryptographic Proofs</h3>
            <p>
              Every action requires a signed, verifiable packet. Session logic uses X25519, ChaCha20-Poly1305, and Ed25519 to securely negotiate boundaries.
            </p>
          </div>
          <div className="glass-panel hover-card">
            <div className="icon-wrapper">⚡</div>
            <h3>Universal Adapters</h3>
            <p>
              Seamlessly integrate with Next.js, Cloudflare Workers, Axum, Express, and bare-metal embedded targets (ESP32, RP2040) via a unified SDK.
            </p>
          </div>
        </div>
      </section>

      <section id="how-it-works" className="container section-padding">
        <div className="split-layout">
          <div className="split-text">
            <h2>Stop guessing who is making the request.</h2>
            <p>
              Standard security relies on perimeter defense and leaked API keys. TrustForge requires every actor—human or machine—to cryptographically sign every capability they exercise. 
            </p>
            <ul className="check-list">
              <li>✓ Stateless Verification</li>
              <li>✓ Post-Quantum Ready</li>
              <li>✓ Agent-Contract Guard Policies</li>
              <li>✓ Distributed Edge-Native Architecture</li>
            </ul>
          </div>
          <div className="glass-panel code-block">
            <div className="window-controls">
              <span className="dot red"></span>
              <span className="dot yellow"></span>
              <span className="dot green"></span>
            </div>
            <pre>
              <code>
<span className="keyword">import</span> {'{'} TrustForge {'}'} <span className="keyword">from</span> <span className="string">'@trustforge-protocol/core'</span>;{'\n\n'}
<span className="comment">// Initialize the protocol daemon</span>{'\n'}
<span className="keyword">const</span> tf = <span className="keyword">new</span> TrustForge({'{'}{'\n'}
{'  '}profile: <span className="string">'tf-enterprise-compatible'</span>,{'\n'}
{'  '}keys: loadVaultKeys(),{'\n'}
{'}'});{'\n\n'}
<span className="comment">// Cryptographically verify an incoming packet</span>{'\n'}
<span className="keyword">const</span> packet = <span className="keyword">await</span> tf.verify(req.body);{'\n\n'}
<span className="keyword">if</span> (!packet.hasPermission(<span className="string">'db:write'</span>)) {'{'}{'\n'}
{'  '}<span className="keyword">throw</span> <span className="keyword">new</span> Error(<span className="string">'Invalid Agent Contract'</span>);{'\n'}
{'}'}
              </code>
            </pre>
          </div>
        </div>
      </section>

      <footer className="site-footer container">
        <div className="footer-content">
          <div className="logo gradient-text">TrustForge</div>
          <p>© 2026 TrustForge Protocol. Open-source under Apache-2.0.</p>
        </div>
      </footer>
    </main>
  );
}
