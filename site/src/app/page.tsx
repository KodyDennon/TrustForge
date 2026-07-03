import React from 'react';
import Link from 'next/link';

export default function Home() {
  return (
    <main>
      <section className="container hero">
        <h1>Verifiable Action at the Edge.</h1>
        <p>
          TrustForge is a high-performance open-source trust fabric designed for AI agents and distributed systems. Replace bloated stateful databases with stateless cryptographic proofs.
        </p>
        <div className="button-group">
          <Link href="/docs" className="btn btn-primary">Read Documentation</Link>
          <a href="https://github.com/KodyDennon/TrustForge" target="_blank" rel="noopener noreferrer" className="btn btn-secondary">View GitHub</a>
        </div>
      </section>

      <section className="container section-padding" style={{ borderTop: '1px solid var(--border-subtle)' }}>
        <div className="content-area">
          <h2>Core Capabilities</h2>
          <div className="grid">
            <div className="card">
              <h3>Stateless Verification</h3>
              <p>Capabilities are evaluated directly inside memory boundaries on edge nodes within microseconds. No database lookups or network overhead required.</p>
            </div>
            
            <div className="card">
              <h3>Embedded Compilation</h3>
              <p>Natively support bare-metal target microcontrollers (ESP32, RP2040) directly connecting to the cryptographic fabric using `no_std` Rust.</p>
            </div>

            <div className="card">
              <h3>AI Native API</h3>
              <p>Designed with programmatic schemas and LLM-first documentation, allowing autonomous agents to mint and verify zero-trust proofs seamlessly.</p>
            </div>
          </div>
        </div>
      </section>
    </main>
  );
}
