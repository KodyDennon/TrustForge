"use client";

import React from 'react';
import { Header } from '../../components/Header';
import { Footer } from '../../components/Footer';
import { Shield, Fingerprint, Zap } from 'lucide-react';

export default function Protocol() {
  return (
    <main>
      <div className="grid-overlay" />
      <Header />

      <section className="container section-padding" style={{ paddingTop: '10rem' }}>
        <div className="section-title-wrapper" style={{ textAlign: 'left', margin: '0 0 4rem 0', maxWidth: '800px' }}>
          <div className="badge">Protocol Spec</div>
          <h1 style={{ fontSize: '3.5rem', marginBottom: '1.5rem' }}>Stateless Zero-Trust Architecture</h1>
          <p style={{ fontSize: '1.2rem', color: 'var(--text-muted)' }}>
            TrustForge is structured to eliminate database queries at boundary endpoints. Cryptographic capability envelopes hold authoritative, self-signed permissions verified directly in memory.
          </p>
        </div>

        <div className="cards-grid">
          <div className="glow-card">
            <div className="icon-container"><Shield size={24} /></div>
            <h3>Self-Contained Envelopes</h3>
            <p> डाउनस्ट्रीम microservices decode permission strings from incoming payload envelopes, ensuring strict policy gates are maintained without calling centralized databases or checking blacklists.</p>
          </div>
          
          <div className="glow-card">
            <div className="icon-container"><Fingerprint size={24} /></div>
            <h3>Cryptographic Handshakes</h3>
            <p>Edge nodes dynamically negotiate secure endpoints utilizing ECDH (X25519) key exchange, signing requests via Ed25519, and encrypting with ChaCha20-Poly1305 blocks.</p>
          </div>

          <div className="glow-card">
            <div className="icon-container"><Zap size={24} /></div>
            <h3>Unified Daemon (tf-daemon)</h3>
            <p>The core daemon handles active client keys, imports external credentials (Clerk, Supabase, Auth0), and evaluates authorization constraints statelessly via the Open Policy Agent (OPA) Rego engine.</p>
          </div>
        </div>
      </section>

      <section className="container section-padding" style={{ borderTop: '1px solid rgba(255,255,255,0.03)' }}>
        <h2 style={{ marginBottom: '2rem' }}>Cryptographic Primitive Matrix</h2>
        <div className="comparison-table-wrapper">
          <table className="comparison-table">
            <thead>
              <tr>
                <th>Purpose</th>
                <th>Algorithm</th>
                <th>Crate Reference</th>
              </tr>
            </thead>
            <tbody>
              <tr>
                <td>**Asymmetric Signing**</td>
                <td>Ed25519 (Edwards-curve Digital Signature)</td>
                <td>`tf-session` / `tf-types`</td>
              </tr>
              <tr>
                <td>**Symmetric Encryption**</td>
                <td>ChaCha20-Poly1305 AEAD</td>
                <td>`tf-session`</td>
              </tr>
              <tr>
                <td>**Key Exchange**</td>
                <td>X25519 (ECDH Curve25519)</td>
                <td>`tf-session`</td>
              </tr>
              <tr>
                <td>**Hardware Hashing**</td>
                <td>SHA3-256 (Secure Hash Algorithm 3)</td>
                <td>`tf-embedded-hal`</td>
              </tr>
            </tbody>
          </table>
        </div>
      </section>

      <Footer />
    </main>
  );
}
