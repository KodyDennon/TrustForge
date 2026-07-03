import React from 'react';

export const metadata = {
  title: 'Architecture | TrustForge',
  description: 'Technical dive into the stateless TrustForge protocol.',
};

export default function Architecture() {
  return (
    <main className="container section-padding">
      <div className="page-header">
        <h1>Protocol Architecture</h1>
        <p>A technical teardown of the TrustForge implementation.</p>
      </div>

      <div className="content-area">
        <h2>Comparison: Stateful vs. Stateless</h2>
        <p>TrustForge eliminates the need for database round-trips during authorization checks.</p>
        
        <div style={{ overflowX: 'auto', marginBottom: '3rem' }}>
          <table style={{ width: '100%', borderCollapse: 'collapse', marginTop: '1rem', border: '1px solid var(--border-subtle)' }}>
            <thead>
              <tr style={{ background: 'var(--accents-1)', textAlign: 'left' }}>
                <th style={{ padding: '1rem', borderBottom: '1px solid var(--border)' }}>Feature</th>
                <th style={{ padding: '1rem', borderBottom: '1px solid var(--border)' }}>Legacy JWT/OAuth</th>
                <th style={{ padding: '1rem', borderBottom: '1px solid var(--border)' }}>TrustForge Protocol</th>
              </tr>
            </thead>
            <tbody>
              <tr>
                <td style={{ padding: '1rem', borderBottom: '1px solid var(--border-subtle)' }}><strong>Verification Latency</strong></td>
                <td style={{ padding: '1rem', borderBottom: '1px solid var(--border-subtle)', color: 'var(--text-muted)' }}>High (Requires DB Read / Network JWKS)</td>
                <td style={{ padding: '1rem', borderBottom: '1px solid var(--border-subtle)' }}>Low (&lt;1ms in-memory calculation)</td>
              </tr>
              <tr>
                <td style={{ padding: '1rem', borderBottom: '1px solid var(--border-subtle)' }}><strong>Cryptography</strong></td>
                <td style={{ padding: '1rem', borderBottom: '1px solid var(--border-subtle)', color: 'var(--text-muted)' }}>Varied / Implementation dependent</td>
                <td style={{ padding: '1rem', borderBottom: '1px solid var(--border-subtle)' }}>Strict Ed25519 / X25519</td>
              </tr>
              <tr>
                <td style={{ padding: '1rem', borderBottom: '1px solid var(--border-subtle)' }}><strong>IoT / Bare-Metal</strong></td>
                <td style={{ padding: '1rem', borderBottom: '1px solid var(--border-subtle)', color: 'var(--text-muted)' }}>Difficult / OS dependent</td>
                <td style={{ padding: '1rem', borderBottom: '1px solid var(--border-subtle)' }}>Native no_std embedded support</td>
              </tr>
            </tbody>
          </table>
        </div>

        <h2>Cryptographic Boundary</h2>
        <p>Session boundaries in TrustForge are secured via X25519 key agreements, signed with Ed25519 keys, and symmetrically encrypted via ChaCha20-Poly1305.</p>

        <h2>Edge Verification</h2>
        <p>When an agent presents a Capability and Proof to an edge node, the node verifies the signature against the agent's known public key. If valid, the edge node evaluates the Capability against a localized Rego policy schema. If both pass, the action is permitted.</p>
      </div>
    </main>
  );
}
