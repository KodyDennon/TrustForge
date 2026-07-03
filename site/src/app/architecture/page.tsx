"use client";

import React from 'react';
import { motion } from 'framer-motion';
import { Network, ServerOff, Cpu } from 'lucide-react';

export default function Architecture() {
  const container = {
    hidden: { opacity: 0 },
    show: {
      opacity: 1,
      transition: { staggerChildren: 0.15 }
    }
  };

  const item = {
    hidden: { opacity: 0, y: 20 },
    show: { opacity: 1, y: 0, transition: { type: "spring", stiffness: 300, damping: 24 } }
  };

  return (
    <main className="container section-padding">
      <motion.div 
        className="page-header"
        initial={{ opacity: 0, y: -20 }}
        animate={{ opacity: 1, y: 0 }}
        transition={{ duration: 0.6 }}
      >
        <div style={{ display: 'flex', justifyContent: 'center', marginBottom: '1.5rem' }}>
          <div style={{ background: 'rgba(255, 0, 127, 0.1)', padding: '1rem', borderRadius: '50%', boxShadow: '0 0 30px rgba(255, 0, 127, 0.2)' }}>
            <Network size={48} color="var(--accent)" />
          </div>
        </div>
        <h1>Protocol Architecture</h1>
        <p>A technical teardown of the TrustForge edge-verification implementation.</p>
      </motion.div>

      <motion.div 
        className="content-area"
        variants={container}
        initial="hidden"
        animate="show"
      >
        <motion.div variants={item} className="card" style={{ padding: '2.5rem', marginBottom: '2.5rem' }}>
          <h2 style={{ marginTop: 0, display: 'flex', alignItems: 'center', gap: '0.75rem' }}>
            <ServerOff size={24} color="var(--accent)" />
            Stateful vs. Stateless
          </h2>
          <p>TrustForge fundamentally eliminates the need for database round-trips during authorization checks.</p>
          
          <div style={{ overflowX: 'auto', margin: '2rem 0 0 0' }}>
            <table>
              <thead>
                <tr>
                  <th>Feature</th>
                  <th>Legacy JWT/OAuth</th>
                  <th>TrustForge Protocol</th>
                </tr>
              </thead>
              <tbody>
                <tr>
                  <td>Verification Latency</td>
                  <td style={{ color: 'var(--text-muted)' }}>High (DB Read / Network JWKS)</td>
                  <td style={{ color: 'var(--primary)' }}>&lt;1ms (In-memory Edge)</td>
                </tr>
                <tr>
                  <td>Cryptography</td>
                  <td style={{ color: 'var(--text-muted)' }}>Varied / Implementation dependent</td>
                  <td style={{ color: 'var(--primary)' }}>Strict Ed25519 / X25519</td>
                </tr>
                <tr>
                  <td>IoT / Bare-Metal</td>
                  <td style={{ color: 'var(--text-muted)' }}>Difficult / OS dependent</td>
                  <td style={{ color: 'var(--primary)' }}>Native `no_std` support</td>
                </tr>
              </tbody>
            </table>
          </div>
        </motion.div>
        
        <motion.div variants={item} className="card" style={{ padding: '2.5rem', marginBottom: '2.5rem' }}>
          <h2 style={{ marginTop: 0, display: 'flex', alignItems: 'center', gap: '0.75rem' }}>
            <Network size={24} color="var(--primary)" />
            Cryptographic Boundary
          </h2>
          <p>
            Session boundaries in TrustForge are secured via X25519 key agreements, signed with Ed25519 keys, and symmetrically encrypted via ChaCha20-Poly1305. 
            No sensitive keys are ever transmitted over the wire. Instead, agents mint short-lived capability proofs derived from these keys.
          </p>
        </motion.div>

        <motion.div variants={item} className="card" style={{ padding: '2.5rem' }}>
          <h2 style={{ marginTop: 0, display: 'flex', alignItems: 'center', gap: '0.75rem' }}>
            <Cpu size={24} color="var(--secondary)" />
            Edge Verification
          </h2>
          <p>
            When an agent presents a Capability and Proof to an edge node, the node verifies the signature against the agent's known public key. If valid, the edge node evaluates the Capability against a localized Rego policy schema. If both pass, the action is permitted.
          </p>
        </motion.div>
      </motion.div>
    </main>
  );
}
