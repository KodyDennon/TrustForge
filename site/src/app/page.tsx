"use client";

import React from 'react';
import Link from 'next/link';
import { motion, Variants } from 'framer-motion';
import { ArrowRight, ShieldCheck, Cpu, Database, Key, Zap, Code2, Globe } from 'lucide-react';

export default function Home() {
  const staggerContainer: Variants = {
    hidden: { opacity: 0 },
    show: {
      opacity: 1,
      transition: { staggerChildren: 0.1 }
    }
  };

  const fadeUp: Variants = {
    hidden: { opacity: 0, y: 20 },
    show: { opacity: 1, y: 0, transition: { type: "spring", stiffness: 300, damping: 24 } }
  };

  return (
    <main>
      {/* Hero Section */}
      <section className="container section" style={{ paddingTop: '8rem', paddingBottom: '8rem' }}>
        <div style={{ maxWidth: '800px' }}>
          <motion.div initial="hidden" animate="show" variants={staggerContainer}>
            <motion.div variants={fadeUp} style={{ display: 'inline-flex', alignItems: 'center', gap: '8px', padding: '6px 12px', background: 'rgba(79, 70, 229, 0.1)', border: '1px solid rgba(79, 70, 229, 0.2)', borderRadius: '100px', color: 'var(--primary-light)', fontSize: '0.875rem', fontWeight: 500, marginBottom: '24px' }}>
              <span style={{ width: 8, height: 8, borderRadius: '50%', background: 'var(--primary-light)' }}></span>
              TrustForge Core v0.1.2 is now available
            </motion.div>
            
            <motion.h1 variants={fadeUp}>
              Zero-Trust Authentication,<br/>
              <span style={{ color: 'var(--primary-light)' }}>Zero Database Lookups.</span>
            </motion.h1>
            
            <motion.p variants={fadeUp} className="lead" style={{ marginBottom: '40px' }}>
              TrustForge is a high-performance cryptographic protocol that replaces stateful sessions with stateless capability proofs. Verify permissions directly at the edge in less than 1 millisecond.
            </motion.p>
            
            <motion.div variants={fadeUp} style={{ display: 'flex', gap: '16px', flexWrap: 'wrap' }}>
              <Link href="/docs" className="btn btn-primary">
                Start Building <ArrowRight size={18} />
              </Link>
              <a href="https://github.com/KodyDennon/TrustForge" target="_blank" rel="noopener noreferrer" className="btn btn-secondary">
                View on GitHub
              </a>
            </motion.div>
          </motion.div>
        </div>
      </section>

      {/* The Problem & Solution Section */}
      <section className="container section" style={{ borderTop: '1px solid var(--border-subtle)' }}>
        <div className="grid-2">
          <div>
            <div style={{ color: 'var(--accent)', fontWeight: 600, fontSize: '0.875rem', textTransform: 'uppercase', letterSpacing: '0.05em', marginBottom: '12px' }}>
              The Bottleneck
            </div>
            <h2 style={{ fontSize: '2.25rem' }}>Stateful auth is killing your edge performance.</h2>
            <p style={{ marginBottom: '24px' }}>
              Traditional applications rely on JWTs or session cookies that must be cross-referenced against a centralized database (like PostgreSQL or Redis) to verify permissions on every single request. 
            </p>
            <p>
              When you deploy to edge workers across the globe, forcing every function to round-trip back to a central database completely destroys the latency benefits of the edge.
            </p>
          </div>
          
          <div className="surface-card" style={{ background: 'var(--bg-main)' }}>
            <div className="code-window">
              <div className="code-header">
                <div className="code-dot dot-red"></div>
                <div className="code-dot dot-yellow"></div>
                <div className="code-dot dot-green"></div>
                <span style={{ marginLeft: '12px', fontSize: '0.8rem', color: 'var(--text-muted)' }}>Legacy API Route</span>
              </div>
              <div className="code-body">
                <pre><code>{`// ❌ The old way: 50ms+ latency

export async function POST(req) {
  const token = req.headers.get('Authorization');
  
  // Blocking database call from the edge
  const session = await db.query(
    'SELECT roles FROM sessions WHERE token = ?', 
    [token]
  );
  
  if (!session.roles.includes('admin')) {
    return new Response('Unauthorized', { status: 403 });
  }
}`}</code></pre>
              </div>
            </div>
          </div>
        </div>
      </section>

      {/* Features Grid */}
      <section className="container section">
        <div style={{ textAlign: 'center', maxWidth: '600px', margin: '0 auto 64px' }}>
          <h2>Engineered for the modern distributed web.</h2>
          <p>TrustForge eliminates network hops by encoding isolated capabilities directly into cryptographically signed Ed25519 proofs.</p>
        </div>

        <motion.div 
          className="grid-3"
          initial="hidden"
          whileInView="show"
          viewport={{ once: true, margin: "-100px" }}
          variants={staggerContainer}
        >
          <motion.div variants={fadeUp} className="surface-card">
            <div className="icon-wrapper">
              <Zap size={24} />
            </div>
            <h3>Microsecond Verification</h3>
            <p>Because there is no network call, validating a TrustForge capability proof takes ~100 microseconds of CPU time.</p>
          </motion.div>

          <motion.div variants={fadeUp} className="surface-card">
            <div className="icon-wrapper">
              <Database size={24} />
            </div>
            <h3>Zero Database Required</h3>
            <p>The proof contains everything needed to authorize the request. If the cryptographic signature matches the known public key, the action is approved.</p>
          </motion.div>

          <motion.div variants={fadeUp} className="surface-card">
            <div className="icon-wrapper">
              <ShieldCheck size={24} />
            </div>
            <h3>Absolute Boundaries</h3>
            <p>Instead of granting an agent wide "admin" access, capabilities scope permissions down to exact database rows or API endpoints.</p>
          </motion.div>

          <motion.div variants={fadeUp} className="surface-card">
            <div className="icon-wrapper">
              <Cpu size={24} />
            </div>
            <h3>Embedded Native</h3>
            <p>Written in Rust with `#![no_std]` support. Compile TrustForge directly into ESP32 microcontrollers or WebAssembly binaries.</p>
          </motion.div>

          <motion.div variants={fadeUp} className="surface-card">
            <div className="icon-wrapper">
              <Code2 size={24} />
            </div>
            <h3>AI Agent First</h3>
            <p>Strict schemas and programmable boundaries allow autonomous LLMs to mint capabilities and securely act on your behalf.</p>
          </motion.div>

          <motion.div variants={fadeUp} className="surface-card">
            <div className="icon-wrapper">
              <Globe size={24} />
            </div>
            <h3>Cloudflare & Vercel Ready</h3>
            <p>Designed specifically to drop into Vercel Edge Middleware or Cloudflare Workers without pulling in heavy cryptographic dependencies.</p>
          </motion.div>
        </motion.div>
      </section>

      {/* Developer Experience / Code Preview */}
      <section className="container section" style={{ borderTop: '1px solid var(--border-subtle)', paddingBottom: '12rem' }}>
        <div style={{ marginBottom: '48px' }}>
          <h2>The Developer Experience</h2>
          <p className="lead">Minting and verifying a proof takes just 4 lines of code.</p>
        </div>
        
        <div className="grid-2" style={{ alignItems: 'flex-start' }}>
          <div className="code-window">
            <div className="code-header">
              <div className="code-dot dot-red"></div>
              <div className="code-dot dot-yellow"></div>
              <div className="code-dot dot-green"></div>
              <span style={{ marginLeft: '12px', fontSize: '0.8rem', color: 'var(--text-muted)' }}>Client: Minting the Proof (Rust)</span>
            </div>
            <div className="code-body">
              <pre><code>{`use trustforge_core::{Keystore, Capability};

// Load private key
let keystore = Keystore::load(env!("TF_KEY"));

// Define isolated boundary
let cap = Capability::new("db:write")
    .with_target("user_1024");

// Mint Ed25519 cryptographic proof
let proof = keystore.mint_proof(&cap).unwrap();

// Send proof in header
client.post("/api/update")
    .header("X-TrustForge-Proof", proof.to_string())
    .send().await;`}</code></pre>
            </div>
          </div>

          <div className="code-window">
            <div className="code-header">
              <div className="code-dot dot-red"></div>
              <div className="code-dot dot-yellow"></div>
              <div className="code-dot dot-green"></div>
              <span style={{ marginLeft: '12px', fontSize: '0.8rem', color: 'var(--text-muted)' }}>Edge Node: Verifying (WASM / Next.js)</span>
            </div>
            <div className="code-body">
              <pre><code>{`import { Verifier } from 'trustforge-core-wasm';

export function middleware(req) {
  const proofStr = req.headers.get('X-TrustForge-Proof');
  
  const verifier = new Verifier(PUBLIC_KEY);
  
  // Extremely fast, synchronous, in-memory validation
  // No await required. No database lookup.
  if (!verifier.verify_string(proofStr)) {
    return new Response('Forbidden', { status: 403 });
  }

  return NextResponse.next();
}`}</code></pre>
            </div>
          </div>
        </div>
      </section>
    </main>
  );
}
