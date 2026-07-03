import React from 'react';

export const metadata = {
  title: 'Documentation | TrustForge',
  description: 'Learn how to install and use the TrustForge protocol.',
};

export default function Docs() {
  return (
    <main className="container section-padding">
      <div className="page-header">
        <h1>Documentation</h1>
        <p>A complete guide to integrating TrustForge into your stack.</p>
      </div>

      <div className="content-area">
        <h2>Installation</h2>
        <p>TrustForge is distributed via crates.io. Add the core cryptographic library to your Rust project:</p>
        <pre><code>cargo add trustforge-core</code></pre>
        
        <h2>Quickstart: Generating a Proof</h2>
        <p>Initialize a keystore, create a capability, and mint a proof using Ed25519.</p>
        <pre><code>{`use trustforge_core::{Keystore, Capability, Proof};

// 1. Initialize a new Keystore with a fresh Ed25519 keypair
let keystore = Keystore::generate();

// 2. Define the capability (the boundary of action)
let cap = Capability::new("db:write").with_target("users_table");

// 3. Mint the proof
let proof = keystore.mint_proof(&cap).expect("Failed to mint proof");

println!("Proof minted: {}", proof.signature());`}</code></pre>

        <h2>Verifying a Proof</h2>
        <p>Verification is stateless and occurs entirely in-memory within microseconds.</p>
        <pre><code>{`use trustforge_core::{Verifier, Proof};

// Assume 'proof' was received via an inbound request
let verifier = Verifier::new();

match verifier.verify(&proof) {
    Ok(_) => println!("Proof is cryptographically valid."),
    Err(e) => println!("Invalid proof: {}", e),
}`}</code></pre>

        <h2>Rego Policy Engine</h2>
        <p>Beyond signature validation, TrustForge embeds a lightweight WebAssembly Rego engine to enforce complex logical boundaries (e.g., checking expiration times or IP constraints) before executing actions.</p>
      </div>
    </main>
  );
}
