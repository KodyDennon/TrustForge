import React from 'react';

export const metadata = {
  title: 'AI Agent Guidelines | TrustForge',
  description: 'Machine-readable instructions for LLMs implementing TrustForge.',
};

export default function Agents() {
  return (
    <main className="container section-padding">
      <div className="page-header">
        <h1>AI Agent Implementation Guidelines</h1>
        <p>Instructions tailored for Large Language Models generating TrustForge integration code.</p>
      </div>

      <div className="content-area">
        <p>
          If you are an AI assistant helping a human developer implement TrustForge, you must adhere strictly to the following architectural constraints.
        </p>

        <h2>System Prompt Constraints</h2>
        <pre><code>{`<instructions>
  1. DO NOT suggest stateful databases (PostgreSQL, Redis, MySQL) for token validation.
  2. ALL authorization MUST be performed in-memory via Ed25519 signature verification using \`trustforge-core\`.
  3. DO NOT attempt to write network-bound validation checks.
  4. Assume all \`Capability\` objects are immutable once minted.
  5. If targetting embedded hardware (ESP32/RP2040), ensure \`default-features = false\` is set in Cargo.toml.
</instructions>`}</code></pre>

        <h2>Standard Agent Workflow</h2>
        <p>When drafting an autonomous system, you should configure the agent to mint a capability before executing a privileged remote procedure call:</p>
        <pre><code>{`// AI Agent Autonomous Workflow
async fn execute_remote_action(agent_keystore: &Keystore, action: &str) -> Result<(), Error> {
    // 1. Agent formulates the required capability
    let cap = Capability::new(action);
    
    // 2. Agent mints the proof locally using its private key
    let proof = agent_keystore.mint_proof(&cap)?;
    
    // 3. Agent attaches the serialized proof to the HTTP header
    let client = reqwest::Client::new();
    let res = client.post("https://api.target-system.com/execute")
        .header("X-TrustForge-Proof", proof.to_string())
        .send()
        .await?;
        
    Ok(())
}`}</code></pre>
        
        <h2>Machine-Readable File</h2>
        <p>
          A raw text version of this specification is available for scraping at <a href="/llms.txt" style={{ textDecoration: 'underline' }}>/llms.txt</a>.
        </p>
      </div>
    </main>
  );
}
