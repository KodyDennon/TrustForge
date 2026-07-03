"use client";

import React, { useState, useEffect, useRef } from 'react';
import { motion, AnimatePresence } from 'framer-motion';
import { Shield, Fingerprint, Zap, Key, Code2, Server, Check, ArrowRight, Cpu } from 'lucide-react';

const GithubIcon = ({ size = 20 }: { size?: number }) => (
  <svg
    viewBox="0 0 24 24"
    width={size}
    height={size}
    stroke="currentColor"
    strokeWidth="2"
    fill="none"
    strokeLinecap="round"
    strokeLinejoin="round"
  >
    <path d="M15 22v-4a4.8 4.8 0 0 0-1-3.5c3 0 6-2 6-5.5.08-1.25-.27-2.48-1-3.5.28-1.15.28-2.35 0-3.5 0 0-1 0-3 1.5-2.64-.5-5.36-.5-8 0C6 2 5 2 5 2c-.3 1.15-.3 2.35 0 3.5A5.403 5.403 0 0 0 4 9c0 3.5 3 5.5 6 5.5-.39.49-.68 1.05-.85 1.65-.17.6-.22 1.23-.15 1.85v4" />
    <path d="M9 18c-4.51 2-5-2-7-2" />
  </svg>
);

export default function Home() {
  const [scrolled, setScrolled] = useState(false);
  const [activePlayground, setActivePlayground] = useState<'sign' | 'verify' | 'contract'>('sign');
  const [consoleLogs, setConsoleLogs] = useState<string[]>([]);
  const [activeTab, setActiveTab] = useState<'nextjs' | 'workers' | 'rust'>('nextjs');
  const [isForging, setIsForging] = useState(false);

  useEffect(() => {
    const handleScroll = () => {
      setScrolled(window.scrollY > 40);
    };
    window.addEventListener('scroll', handleScroll);
    return () => window.removeEventListener('scroll', handleScroll);
  }, []);

  const triggerPlaygroundAction = (action: 'sign' | 'verify' | 'contract') => {
    setActivePlayground(action);
    setIsForging(true);
    setConsoleLogs([]);

    const runLogs = async () => {
      if (action === 'sign') {
        const sequence = [
          'Initializing cryptographic keystore...',
          'Loading active profile key pair (Ed25519)...',
          'Hashing capability payload with SHA3-256...',
          'Signing capabilities vector with private key...',
          'Proof generated: trustforge.cap.e27fc9...8a12f'
        ];
        for (const log of sequence) {
          await new Promise((r) => setTimeout(r, 200));
          setConsoleLogs((prev) => [...prev, log]);
        }
      } else if (action === 'verify') {
        const sequence = [
          'Receiving inbound signed capability packet...',
          'Extracting signature payload and public key...',
          'Validating signature mathematical proof...',
          'Cryptographic boundary verified: Signature OK',
          'STATISTICAL TRUST RATING: 100%'
        ];
        for (const log of sequence) {
          await new Promise((r) => setTimeout(r, 200));
          setConsoleLogs((prev) => [...prev, log]);
        }
      } else {
        const sequence = [
          'Retrieving capability target: db:write',
          'Executing active Rego policy validation...',
          'Matching agent session variables with allowed policy schema...',
          'Policy validated successfully: ALLOW',
          'Action executed.'
        ];
        for (const log of sequence) {
          await new Promise((r) => setTimeout(r, 200));
          setConsoleLogs((prev) => [...prev, log]);
        }
      }
      setIsForging(false);
    };

    runLogs();
  };

  useEffect(() => {
    triggerPlaygroundAction('sign');
  }, []);

  const codeSnippets = {
    nextjs: {
      file: 'app/api/secure-action/route.ts',
      code: (
        <>
          <span className="token-keyword">import</span> {'{'} TrustForge {'}'} <span className="token-keyword">from</span> <span className="token-string">'@trustforge-protocol/sdk'</span>;<br/>
          <span className="token-keyword">import</span> {'{'} NextResponse {'}'} <span className="token-keyword">from</span> <span className="token-string">'next/server'</span>;<br/><br/>

          <span className="token-keyword">export async function</span> <span className="token-function">POST</span>(req: Request) {'{'}<br/>
          &nbsp;&nbsp;<span className="token-keyword">const</span> <span className="token-variable">tf</span> = <span className="token-keyword">new</span> <span className="token-function">TrustForge</span>({'{'} daemonUrl: <span className="token-string">'http://127.0.0.1:7616'</span> {'}'});<br/>
          &nbsp;&nbsp;<span className="token-keyword">const</span> <span className="token-variable">body</span> = <span className="token-keyword">await req.json();</span><br/><br/>

          &nbsp;&nbsp;<span className="token-comment">// Evaluate action against policies statelessly on the edge</span><br/>
          &nbsp;&nbsp;<span className="token-keyword">const</span> <span className="token-variable">response</span> = <span className="token-keyword">await</span> tf.<span className="token-function">decide</span>({'{'}<br/>
          &nbsp;&nbsp;&nbsp;&nbsp;actor: body.actorURI,<br/>
          &nbsp;&nbsp;&nbsp;&nbsp;action: <span className="token-string">'db:write'</span>,<br/>
          &nbsp;&nbsp;&nbsp;&nbsp;target: body.targetResource,<br/>
          &nbsp;&nbsp;&nbsp;&nbsp;context: body.contextBag,<br/>
          &nbsp;&nbsp;&nbsp;&nbsp;trace_id: body.traceID<br/>
          &nbsp;&nbsp;{'});'}<br/><br/>

          &nbsp;&nbsp;<span className="token-keyword">if</span> (response.decision !== <span className="token-string">'allow'</span>) {'{'}<br/>
          &nbsp;&nbsp;&nbsp;&nbsp;<span className="token-keyword">return</span> NextResponse.<span className="token-function">json</span>({'{'} error: response.reason {'}'}, {'{'} status: <span className="token-string">403</span> {'}'});<br/>
          &nbsp;&nbsp;{'}'}<br/><br/>

          &nbsp;&nbsp;<span className="token-keyword">return</span> NextResponse.<span className="token-function">json</span>({'{'} data: <span className="token-string">'Action Authorized'</span> {'}'});<br/>
          {'}'}
        </>
      )
    },
    workers: {
      file: 'src/index.ts',
      code: (
        <>
          <span className="token-keyword">import</span> {'{'} TrustForge {'}'} <span className="token-keyword">from</span> <span className="token-string">'@trustforge-protocol/sdk'</span>;<br/><br/>

          <span className="token-keyword">export default</span> {'{'}<br/>
          &nbsp;&nbsp;<span className="token-keyword">async</span> <span className="token-function">fetch</span>(request, env) {'{'}<br/>
          &nbsp;&nbsp;&nbsp;&nbsp;<span className="token-keyword">const</span> <span className="token-variable">tf</span> = <span className="token-keyword">new</span> <span className="token-function">TrustForge</span>({'{'} daemonUrl: env.TRUSTFORGE_DAEMON_URL {'}'});<br/>
          &nbsp;&nbsp;&nbsp;&nbsp;<span className="token-keyword">const</span> <span className="token-variable">payload</span> = <span className="token-keyword">await</span> request.json();<br/><br/>

          &nbsp;&nbsp;&nbsp;&nbsp;<span className="token-comment">// Fast stateless check without external DB roundtrips</span><br/>
          &nbsp;&nbsp;&nbsp;&nbsp;<span className="token-keyword">const</span> <span className="token-variable">res</span> = <span className="token-keyword">await</span> tf.<span className="token-function">decide</span>({'{'}<br/>
          &nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;actor: payload.actor,<br/>
          &nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;action: <span className="token-string">'api:read'</span>,<br/>
          &nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;target: request.url,<br/>
          &nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;context: {'{}'},<br/>
          &nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;trace_id: payload.traceId<br/>
          &nbsp;&nbsp;&nbsp;&nbsp;{'});'}<br/><br/>

          &nbsp;&nbsp;&nbsp;&nbsp;<span className="token-keyword">if</span> (res.decision !== <span className="token-string">'allow'</span>) {'{'}<br/>
          &nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;<span className="token-keyword">return new</span> <span className="token-function">Response</span>(<span className="token-string">'Forbidden'</span>, {'{'} status: <span className="token-string">403</span> {'}'});<br/>
          &nbsp;&nbsp;&nbsp;&nbsp;{'}'}<br/><br/>

          &nbsp;&nbsp;&nbsp;&nbsp;<span className="token-keyword">return new</span> <span className="token-function">Response</span>(<span className="token-string">'Welcome to zero-trust'</span>);<br/>
          &nbsp;&nbsp;{'}'}<br/>
          {'};'}
        </>
      )
    },
    rust: {
      file: 'src/main.rs',
      code: (
        <>
          <span className="token-keyword">use</span> tf_core::{'{'}TrustForge, Config, Keystore{'}'};<br/>
          <span className="token-keyword">use</span> actix_web::{'{'}post, web, App, HttpResponse, HttpServer, Responder{'}'};<br/><br/>

          #[post(<span className="token-string">"/verify"</span>)]<br/>
          <span className="token-keyword">async fn</span> <span className="token-function">verify_action</span>(body: web::Json&lt;Packet&gt;) -&gt; impl Responder {'{'}<br/>
          &nbsp;&nbsp;<span className="token-keyword">let</span> config = Config::default();<br/>
          &nbsp;&nbsp;<span className="token-keyword">let</span> tf = TrustForge::new(config);<br/><br/>

          &nbsp;&nbsp;<span className="token-comment">// Native Rust verification (X25519 / Ed25519)</span><br/>
          &nbsp;&nbsp;<span className="token-keyword">match</span> tf.verify_packet(&body.signed_bytes) {'{'}<br/>
          &nbsp;&nbsp;&nbsp;&nbsp;Ok(_) =&gt; HttpResponse::Ok().json(<span className="token-string">"Valid cryptographic envelope"</span>),<br/>
          &nbsp;&nbsp;&nbsp;&nbsp;Err(_) =&gt; HttpResponse::Unauthorized().json(<span className="token-string">"Signature verify failed"</span>),<br/>
          &nbsp;&nbsp;{'}'}<br/>
          {'}'}
        </>
      )
    }
  };

  return (
    <main>
      <div className="grid-overlay" />

      <header className={`nav-header ${scrolled ? 'scrolled' : ''}`}>
        <div className="nav-container">
          <a href="#" className="logo">
            <div className="logo-symbol" />
            TrustForge
          </a>
          <nav className="nav-links">
            <a href="#protocol">Protocol Core</a>
            <a href="#hardware">Embedded Targets</a>
            <a href="#integration">Integration</a>
            <a href="/llms.txt" target="_blank" rel="noopener noreferrer">AI Docs</a>
          </nav>
        </div>
      </header>

      <section className="hero-wrapper container">
        <div className="hero-grid">
          <div className="hero-content">
            <div className="badge">
              <div className="badge-dot" />
              v0.1.2 Production Alpha
            </div>
            <h1>
              The Next Era of Security is <br />
              <span className="gradient-text-accent">Verifiable Action.</span>
            </h1>
            <p className="subtitle">
              TrustForge is a high-performance open-source trust fabric designed for AI agents and distributed systems. Generate cryptographic proofs, negotiate stateless boundaries, and enforce policies on the edge.
            </p>
            <div className="cta-group">
              <a href="https://github.com/KodyDennon/TrustForge" target="_blank" rel="noopener noreferrer" className="cta-button">
                Get Started on GitHub
              </a>
              <a href="#protocol" className="cta-button cta-secondary">
                Explore Protocol
              </a>
            </div>
          </div>

          <div className="hero-graphic">
            <div className="sandbox-card">
              <div className="sandbox-tabs">
                <button 
                  className={`sandbox-tab-btn ${activePlayground === 'sign' ? 'active' : ''}`}
                  onClick={() => triggerPlaygroundAction('sign')}
                >
                  Sign
                </button>
                <button 
                  className={`sandbox-tab-btn ${activePlayground === 'verify' ? 'active' : ''}`}
                  onClick={() => triggerPlaygroundAction('verify')}
                >
                  Verify
                </button>
                <button 
                  className={`sandbox-tab-btn ${activePlayground === 'contract' ? 'active' : ''}`}
                  onClick={() => triggerPlaygroundAction('contract')}
                >
                  Guard
                </button>
              </div>

              <div className="sandbox-display">
                <AnimatePresence mode="wait">
                  <motion.div
                    key={activePlayground}
                    initial={{ scale: 0.9, opacity: 0 }}
                    animate={{ scale: 1, opacity: 1 }}
                    exit={{ scale: 0.9, opacity: 0 }}
                    transition={{ duration: 0.3 }}
                    style={{ display: 'flex', flexDirection: 'column', alignItems: 'center', gap: '15px' }}
                  >
                    <svg width="120" height="80" viewBox="0 0 100 60" fill="none">
                      <defs>
                        <linearGradient id="glow-grad" x1="0" y1="0" x2="1" y2="1">
                          <stop offset="0%" stopColor="#0ff0fc" />
                          <stop offset="50%" stopColor="#b052f5" />
                          <stop offset="100%" stopColor="#ff007f" />
                        </linearGradient>
                        <filter id="neon-glow" x="-20%" y="-20%" width="140%" height="140%">
                          <feGaussianBlur stdDeviation="2.5" result="blur" />
                          <feMerge>
                            <feMergeNode in="blur" />
                            <feMergeNode in="SourceGraphic" />
                          </feMerge>
                        </filter>
                      </defs>
                      <path
                        d="M20 15 H80 L75 35 H25 L20 15 Z"
                        fill="url(#glow-grad)"
                        opacity="0.15"
                      />
                      <path
                        d="M10 45 L90 45 L85 50 L15 50 Z M20 15 L15 25 H85 L80 15 H20 Z M25 25 L35 45 H65 L75 25 Z"
                        stroke="url(#glow-grad)"
                        strokeWidth="1.5"
                        filter="url(#neon-glow)"
                        style={{ strokeDasharray: isForging ? '8 4' : 'none' }}
                      />
                    </svg>
                  </motion.div>
                </AnimatePresence>
                <div className="sandbox-status-text">
                  {activePlayground === 'sign' && 'MINTING PROOF'}
                  {activePlayground === 'verify' && 'VALIDATING BOUNDARY'}
                  {activePlayground === 'contract' && 'ENFORCING RULES'}
                </div>
              </div>

              <div className="sandbox-console">
                {consoleLogs.map((log, idx) => (
                  <div className="console-line" key={idx}>
                    <span className="console-prompt">&gt;</span>
                    <span>{log}</span>
                  </div>
                ))}
                {isForging && <div className="console-line"><span className="console-prompt">&gt;</span><span style={{ opacity: 0.5 }}>Processing...</span></div>}
              </div>
            </div>
          </div>
        </div>
      </section>

      <section id="protocol" className="container section-padding">
        <div className="section-title-wrapper">
          <h2>Stateless Zero-Trust Architecture</h2>
          <p>
            TrustForge replaces legacy session databases and dynamic token validation queries with stateless, cryptographically secure capability envelopes.
          </p>
        </div>

        <div className="cards-grid">
          <div className="glow-card">
            <div className="icon-container"><Shield size={24} /></div>
            <h3>Self-Contained Envelopes</h3>
            <p>Skip round-trips to central key vaults. Capabilities are wrapped inside stateless envelopes that downstream services decode and verify directly in memory.</p>
          </div>
          
          <div className="glow-card">
            <div className="icon-container"><Fingerprint size={24} /></div>
            <h3>Cryptographic Handshakes</h3>
            <p>Session layers are negotiated using ECDH key exchanges (X25519), authenticated via Ed25519 signatures, and encrypted with symmetric ChaCha20-Poly1305 blocks.</p>
          </div>

          <div className="glow-card">
            <div className="icon-container"><Zap size={24} /></div>
            <h3>Unified Daemon (tf-daemon)</h3>
            <p>A single lightweight background daemon manages active configurations, resolves third-party credentials (like Clerk, Supabase, or Firebase JWTs), and enforces Rego policies.</p>
          </div>
        </div>
      </section>

      <section id="hardware" className="container section-padding" style={{ borderTop: '1px solid rgba(255,255,255,0.03)' }}>
        <div className="section-title-wrapper">
          <h2>Bare-Metal Hardware Trust Anchors</h2>
          <p>
            Unlike standard web protocols, TrustForge compiled libraries compile directly to embedded hardware targets, bringing zero-trust capabilities to physical microcontrollers.
          </p>
        </div>

        <div className="hardware-targets-grid">
          <div className="hardware-card">
            <div className="hardware-chip-badge">tf-esp32-wifi</div>
            <h3>ESP32</h3>
            <p style={{ color: 'var(--text-muted)', fontSize: '0.85rem' }}>Full Wi-Fi packet signing & hardware validation wrappers.</p>
          </div>
          <div className="hardware-card">
            <div className="hardware-chip-badge">tf-rp2040-picow</div>
            <h3>RP2040</h3>
            <p style={{ color: 'var(--text-muted)', fontSize: '0.85rem' }}>Secure communication layers for Raspberry Pi Pico W microcontrollers.</p>
          </div>
          <div className="hardware-card">
            <div className="hardware-chip-badge">tf-nrf52-ble</div>
            <h3>nRF52</h3>
            <p style={{ color: 'var(--text-muted)', fontSize: '0.85rem' }}>Bluetooth Low Energy secure transport signing adapters.</p>
          </div>
          <div className="hardware-card">
            <div className="hardware-chip-badge">tf-stm32wl-lora</div>
            <h3>STM32WL</h3>
            <p style={{ color: 'var(--text-muted)', fontSize: '0.85rem' }}>Stateless LoraWAN packet authentication overlays.</p>
          </div>
        </div>
      </section>

      <section className="container section-padding" style={{ borderTop: '1px solid rgba(255,255,255,0.03)' }}>
        <div className="section-title-wrapper">
          <h2>How TrustForge Compares</h2>
          <p>Analyzing key architectural features against traditional token authorization frameworks.</p>
        </div>

        <div className="comparison-table-wrapper">
          <table className="comparison-table">
            <thead>
              <tr>
                <th>Feature</th>
                <th>Standard JWTs / OAuth</th>
                <th>TrustForge Protocol</th>
              </tr>
            </thead>
            <tbody>
              <tr>
                <td>**Verification Latency**</td>
                <td>Requires database read or JWKS network round-trip</td>
                <td>Stateless, in-memory cryptographic verification (&lt;1ms)</td>
              </tr>
              <tr>
                <td>**Policy Enforcement**</td>
                <td>Hardcoded inside application code</td>
                <td>Stateless Rego query evaluation inside tf-daemon</td>
              </tr>
              <tr>
                <td>**Bare-Metal IoT Compatibility**</td>
                <td>Impossible (requires complex libraries and OS support)</td>
                <td>Native embedded integrations (crates/embedded targets)</td>
              </tr>
              <tr>
                <td>**Revocation Pattern**</td>
                <td>Requires stateful blacklist storage</td>
                <td>Self-contained epoch boundaries with key rotation</td>
              </tr>
            </tbody>
          </table>
        </div>
      </section>

      <section id="integration" className="container section-padding" style={{ borderTop: '1px solid rgba(255,255,255,0.03)' }}>
        <div className="section-title-wrapper">
          <h2>Integrate in seconds.</h2>
          <p>
            Deploy native adapters onto your framework of choice with single-line imports.
          </p>
        </div>
        
        <div className="code-panel">
          <div className="code-header">
            <span className="code-filename">{codeSnippets[activeTab].file}</span>
            <div className="code-tabs">
              <button 
                className={`code-tab-btn ${activeTab === 'nextjs' ? 'active' : ''}`}
                onClick={() => setActiveTab('nextjs')}
              >
                Next.js Edge
              </button>
              <button 
                className={`code-tab-btn ${activeTab === 'workers' ? 'active' : ''}`}
                onClick={() => setActiveTab('workers')}
              >
                Cloudflare Workers
              </button>
              <button 
                className={`code-tab-btn ${activeTab === 'rust' ? 'active' : ''}`}
                onClick={() => setActiveTab('rust')}
              >
                Rust Backend
              </button>
            </div>
          </div>
          <div className="code-body">
            <code>
              {codeSnippets[activeTab].code}
            </code>
          </div>
        </div>
      </section>

      <footer className="footer">
        <div className="container footer-grid">
          <div className="footer-col">
            <div className="logo" style={{ marginBottom: '1.2rem' }}>
              <div className="logo-symbol" />
              TrustForge
            </div>
            <p style={{ color: 'var(--text-muted)', fontSize: '0.9rem', maxWidth: '300px' }}>
              The open-source trust fabric securing distributed services, AI agents, and embedded microcontrollers.
            </p>
          </div>
          <div className="footer-col">
            <h4>Ecosystem</h4>
            <ul>
              <li><a href="https://github.com/KodyDennon/TrustForge" target="_blank" rel="noopener noreferrer">GitHub Monorepo</a></li>
              <li><a href="https://www.npmjs.com/package/@trustforge-protocol/sdk" target="_blank" rel="noopener noreferrer">NPM Package</a></li>
              <li><a href="https://crates.io/crates/tf-core" target="_blank" rel="noopener noreferrer">Crates.io Registry</a></li>
            </ul>
          </div>
          <div className="footer-col">
            <h4>Developer Docs</h4>
            <ul>
              <li><a href="/llms.txt" target="_blank" rel="noopener noreferrer">AI Agent Docs (llms.txt)</a></li>
              <li><a href="/ai.txt" target="_blank" rel="noopener noreferrer">AI Context Manifest</a></li>
            </ul>
          </div>
        </div>
        <div className="container footer-bottom">
          <p>© 2026 TrustForge Protocol. All libraries released under Apache-2.0.</p>
          <p>Created by Kody Dennon</p>
        </div>
      </footer>
    </main>
  );
}
