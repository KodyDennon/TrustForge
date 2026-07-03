"use client";

import React from 'react';
import { motion } from 'framer-motion';
import { BookOpen, Box, ShieldCheck, Zap } from 'lucide-react';

export default function Docs() {
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
          <div style={{ background: 'rgba(15, 240, 252, 0.1)', padding: '1rem', borderRadius: '50%', boxShadow: '0 0 30px rgba(15, 240, 252, 0.2)' }}>
            <BookOpen size={48} color="var(--primary)" />
          </div>
        </div>
        <h1>Documentation</h1>
        <p>A complete guide to integrating the TrustForge cryptographic protocol into your stack.</p>
      </motion.div>

      <motion.div 
        className="content-area"
        variants={container}
        initial="hidden"
        animate="show"
      >
        <motion.div variants={item} className="card" style={{ padding: '2.5rem', marginBottom: '2.5rem' }}>
          <h2 style={{ marginTop: 0, display: 'flex', alignItems: 'center', gap: '0.75rem' }}>
            <Box size={24} color="var(--primary)" />
            Installation
          </h2>
          <p>TrustForge is distributed via crates.io. Add the core cryptographic library to your Rust project:</p>
          <pre><code>cargo add trustforge-core</code></pre>
        </motion.div>
        
        <motion.div variants={item} className="card" style={{ padding: '2.5rem', marginBottom: '2.5rem' }}>
          <h2 style={{ marginTop: 0, display: 'flex', alignItems: 'center', gap: '0.75rem' }}>
            <Zap size={24} color="var(--secondary)" />
            Quickstart: Generating a Proof
          </h2>
          <p>Initialize a keystore, create a capability, and mint a proof using Ed25519.</p>
          <pre><code>{`use trustforge_core::{Keystore, Capability, Proof};

// 1. Initialize a new Keystore with a fresh Ed25519 keypair
let keystore = Keystore::generate();

// 2. Define the capability (the boundary of action)
let cap = Capability::new("db:write").with_target("users_table");

// 3. Mint the proof
let proof = keystore.mint_proof(&cap).expect("Failed to mint proof");

println!("Proof minted: {}", proof.signature());`}</code></pre>
        </motion.div>

        <motion.div variants={item} className="card" style={{ padding: '2.5rem', marginBottom: '2.5rem' }}>
          <h2 style={{ marginTop: 0, display: 'flex', alignItems: 'center', gap: '0.75rem' }}>
            <ShieldCheck size={24} color="#00ff88" />
            Verifying a Proof
          </h2>
          <p>Verification is stateless and occurs entirely in-memory within microseconds.</p>
          <pre><code>{`use trustforge_core::{Verifier, Proof};

// Assume 'proof' was received via an inbound request
let verifier = Verifier::new();

match verifier.verify(&proof) {
    Ok(_) => println!("Proof is cryptographically valid."),
    Err(e) => println!("Invalid proof: {}", e),
}`}</code></pre>
        </motion.div>
      </motion.div>
    </main>
  );
}
