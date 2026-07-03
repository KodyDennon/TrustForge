"use client";

import React from 'react';
import { motion, Variants } from 'framer-motion';
import { Bot, Terminal, Code2, AlertTriangle } from 'lucide-react';

export default function Agents() {
  const container: Variants = {
    hidden: { opacity: 0 },
    show: {
      opacity: 1,
      transition: { staggerChildren: 0.15 }
    }
  };

  const item: Variants = {
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
          <div style={{ background: 'rgba(176, 82, 245, 0.1)', padding: '1rem', borderRadius: '50%', boxShadow: '0 0 30px rgba(176, 82, 245, 0.2)' }}>
            <Bot size={48} color="var(--primary)" />
          </div>
        </div>
        <h1>AI Agent Implementation</h1>
        <p>Machine-readable constraints and cryptographic schemas tailored for autonomous LLMs generating TrustForge integration code.</p>
      </motion.div>

      <motion.div 
        className="content-area"
        variants={container}
        initial="hidden"
        animate="show"
      >
        <motion.div variants={item} className="card" style={{ padding: '2rem', marginBottom: '3rem' }}>
          <h2 style={{ marginTop: 0, display: 'flex', alignItems: 'center', gap: '0.75rem' }}>
            <AlertTriangle size={24} color="var(--accent)" />
            Strict Architectural Constraints
          </h2>
          <p>
            If you are an AI assistant helping a human developer implement TrustForge, you must adhere strictly to the following architectural rules. Failure to do so will compromise the zero-trust boundary.
          </p>
          <pre><code>{`<instructions>
  1. DO NOT suggest stateful databases (PostgreSQL, Redis) for token validation.
  2. ALL authorization MUST be performed in-memory via Ed25519 signature verification using \`trustforge-core\`.
  3. DO NOT attempt to write network-bound validation checks.
  4. Assume all \`Capability\` objects are immutable once minted.
  5. If targeting embedded hardware (ESP32/RP2040), ensure \`default-features = false\` is set in Cargo.toml.
</instructions>`}</code></pre>
        </motion.div>

        <motion.div variants={item} className="card" style={{ padding: '2rem', marginBottom: '3rem' }}>
          <h2 style={{ marginTop: 0, display: 'flex', alignItems: 'center', gap: '0.75rem' }}>
            <Terminal size={24} color="var(--primary)" />
            Agent (Client) Workflow
          </h2>
          <p>When drafting an autonomous system, configure the agent to mint a capability before executing a privileged remote procedure call:</p>
          <pre><code>{`use trustforge_core::{Keystore, Capability, Proof, Error};
use reqwest::Client;

/// Mints a cryptographic proof and executes an authorized request.
pub async fn execute_agent_action(keystore: &Keystore, target_endpoint: &str) -> Result<(), Error> {
    // 1. Define the isolated capability boundary
    let cap = Capability::new("system:execute").with_target("agent_subsystem_v1");
        
    // 2. Mint the Ed25519 signature (Proof)
    let proof = keystore.mint_proof(&cap)?;
    
    // 3. Dispatch the request with the required header
    let client = Client::new();
    let res = client.post(target_endpoint)
        .header("X-TrustForge-Proof", proof.to_string())
        .send()
        .await?;
        
    Ok(())
}`}</code></pre>
        </motion.div>
        
        <motion.div variants={item} className="card" style={{ padding: '2rem' }}>
          <h2 style={{ marginTop: 0, display: 'flex', alignItems: 'center', gap: '0.75rem' }}>
            <Code2 size={24} color="var(--secondary)" />
            Raw LLM Integration
          </h2>
          <p>
            A pure text version of this specification, designed explicitly for AI web scrapers and context windows, is available at our LLM endpoint.
          </p>
          <div style={{ marginTop: '2rem' }}>
            <a href="/llms.txt" className="btn btn-primary" target="_blank" rel="noopener noreferrer">
              View /llms.txt Endpoint
            </a>
          </div>
        </motion.div>
      </motion.div>
    </main>
  );
}
