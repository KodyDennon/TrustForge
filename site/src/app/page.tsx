"use client";

import React, { useState, useEffect, useRef } from 'react';
import { motion, AnimatePresence } from 'framer-motion';
import { Shield, Fingerprint, Zap, Key, Code2, Server, Check, ArrowRight } from 'lucide-react';

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

interface GlowCardProps {
  children: React.ReactNode;
}

const GlowCard: React.FC<GlowCardProps> = ({ children }) => {
  const cardRef = useRef<HTMLDivElement>(null);

  const handleMouseMove = (e: React.MouseEvent<HTMLDivElement>) => {
    if (!cardRef.current) return;
    const rect = cardRef.current.getBoundingClientRect();
    const x = e.clientX - rect.left;
    const y = e.clientY - rect.top;
    cardRef.current.style.setProperty('--mouse-x', `${x}px`);
    cardRef.current.style.setProperty('--mouse-y', `${y}px`);
  };

  return (
    <div className="glow-card" ref={cardRef} onMouseMove={handleMouseMove}>
      <div className="card-border-glow" />
      <div className="glow-card-spotlight" />
      {children}
    </div>
  );
};

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
          await new Promise((r) => setTimeout(r, 400));
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
          await new Promise((r) => setTimeout(r, 400));
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
          await new Promise((r) => setTimeout(r, 400));
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
          <span className="token-keyword">import</span> {'{'} TrustForge {'}'} <span className="token-keyword">from</span> <span className="token-string">'@trustforge-protocol/core'</span>;<br/>
          <span className="token-keyword">import</span> {'{'} NextResponse {'}'} <span className="token-keyword">from</span> <span className="token-string">'next/server'</span>;<br/><br/>

          <span className="token-keyword">export async function</span> <span className="token-function">POST</span>(req: Request) {'{'}<br/>
          &nbsp;&nbsp;<span className="token-keyword">const</span> <span className="token-variable">tf</span> = <span className="token-keyword">new</span> <span className="token-function">TrustForge</span>({'{'} profile: <span className="token-string">'edge-api'</span> {'}'});<br/>
          &nbsp;&nbsp;<span className="token-keyword">const</span> <span className="token-variable">body</span> = <span className="token-keyword">await</span> req.json();<br/><br/>

          &nbsp;&nbsp;<span className="token-comment">// Verify the cryptographic payload stateless on the edge</span><br/>
          &nbsp;&nbsp;<span className="token-keyword">const</span> <span className="token-variable">verification</span> = <span className="token-keyword">await</span> tf.<span className="token-function">verify</span>(body.signedPacket);<br/><br/>

          &nbsp;&nbsp;<span className="token-keyword">if</span> (!verification.valid) {'{'}<br/>
          &nbsp;&nbsp;&nbsp;&nbsp;<span className="token-keyword">return</span> NextResponse.<span className="token-function">json</span>({'{'} error: <span className="token-string">'Unauthorized Signature'</span> {'}'}, {'{'} status: <span className="token-string">401</span> {'}'});<br/>
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
          <span className="token-keyword">import</span> {'{'} TrustForge {'}'} <span className="token-keyword">from</span> <span className="token-string">'@trustforge-protocol/core'</span>;<br/><br/>

          <span className="token-keyword">export default</span> {'{'}<br/>
          &nbsp;&nbsp;<span className="token-keyword">async</span> <span className="token-function">fetch</span>(request, env) {'{'}<br/>
          &nbsp;&nbsp;&nbsp;&nbsp;<span className="token-keyword">const</span> <span className="token-variable">tf</span> = <span className="token-keyword">new</span> <span className="token-function">TrustForge</span>({'{'} compatibilityMode: <span className="token-string">'cloudflare'</span> {'}'});<br/>
          &nbsp;&nbsp;&nbsp;&nbsp;<span className="token-keyword">const</span> <span className="token-variable">payload</span> = <span className="token-keyword">await</span> request.json();<br/><br/>

          &nbsp;&nbsp;&nbsp;&nbsp;<span className="token-comment">// Fast stateless check without external calls</span><br/>
          &nbsp;&nbsp;&nbsp;&nbsp;<span className="token-keyword">const</span> <span className="token-variable">authorized</span> = <span className="token-keyword">await</span> tf.<span className="token-function">checkCapability</span>(payload, <span className="token-string">'api:read'</span>);<br/><br/>

          &nbsp;&nbsp;&nbsp;&nbsp;<span className="token-keyword">if</span> (!authorized) {'{'}<br/>
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
          <div className="logo">
            <div className="logo-symbol" />
            TrustForge
          </div>
          <nav className="nav-links">
            <a href="#anvil">Anvil Playground</a>
            <a href="#protocol">Protocol Core</a>
            <a href="#integration">Integration</a>
          </nav>
        </div>
      </header>

      <section className="hero container">
        <motion.div
          initial={{ opacity: 0, y: 30 }}
          animate={{ opacity: 1, y: 0 }}
          transition={{ duration: 1, ease: [0.16, 1, 0.3, 1] }}
        >
          <div className="badge">
            <div className="badge-dot" />
            v0.1.1 Production Alpha
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
            <a href="#anvil" className="cta-button cta-secondary">
              Try Interactive Sandbox
            </a>
          </div>
        </motion.div>
      </section>

      <section id="anvil" className="container playground-section">
        <div className="playground-grid">
          <div>
            <h2 style={{ marginBottom: '1.5rem' }}>The Cryptographic Sandbox</h2>
            <p style={{ color: '#8f8f9e', fontSize: '1.1rem', marginBottom: '2.5rem' }}>
              Witness how the TrustForge protocol executes cryptographic validations statelessly on the edge. Trigger an action and see the live trace output.
            </p>
            <div className="sandbox-controls">
              <button 
                className={`control-btn ${activePlayground === 'sign' ? 'active' : ''}`}
                onClick={() => triggerPlaygroundAction('sign')}
              >
                <div className="control-btn-info">
                  <span>Sign Capability</span>
                  <span>Mint self-contained cryptographic session authorization</span>
                </div>
                <ArrowRight size={18} />
              </button>
              <button 
                className={`control-btn ${activePlayground === 'verify' ? 'active' : ''}`}
                onClick={() => triggerPlaygroundAction('verify')}
              >
                <div className="control-btn-info">
                  <span>Verify Envelope</span>
                  <span>Validate public keys and verify mathematical signatures</span>
                </div>
                <ArrowRight size={18} />
              </button>
              <button 
                className={`control-btn ${activePlayground === 'contract' ? 'active' : ''}`}
                onClick={() => triggerPlaygroundAction('contract')}
              >
                <div className="control-btn-info">
                  <span>Policy Check</span>
                  <span>Validate capability targets against Rego guard models</span>
                </div>
                <ArrowRight size={18} />
              </button>
            </div>
          </div>

          <div>
            <div className="anvil-canvas">
              <div className="laser-ray" style={{ left: '30%', animationDelay: '0s' }} />
              <div className="laser-ray" style={{ left: '70%', animationDelay: '1.5s' }} />
              
              <AnimatePresence mode="wait">
                <motion.div
                  key={activePlayground}
                  initial={{ scale: 0.8, opacity: 0 }}
                  animate={{ scale: 1, opacity: 1 }}
                  exit={{ scale: 0.8, opacity: 0 }}
                  transition={{ duration: 0.5 }}
                  style={{ display: 'flex', flexDirection: 'column', alignItems: 'center', gap: '20px' }}
                >
                  {/* Glowing central SVG Anvil geometry */}
                  <svg width="180" height="120" viewBox="0 0 100 60" fill="none">
                    <defs>
                      <linearGradient id="glow-grad" x1="0" y1="0" x2="1" y2="1">
                        <stop offset="0%" stopColor="#0ff0fc" />
                        <stop offset="50%" stopColor="#b052f5" />
                        <stop offset="100%" stopColor="#ff007f" />
                      </linearGradient>
                      <filter id="neon-glow" x="-20%" y="-20%" width="140%" height="140%">
                        <feGaussianBlur stdDeviation="3" result="blur" />
                        <feMerge>
                          <feMergeNode in="blur" />
                          <feMergeNode in="SourceGraphic" />
                        </feMerge>
                      </filter>
                    </defs>
                    <path
                      d="M20 15 H80 L75 35 H25 L20 15 Z"
                      fill="url(#glow-grad)"
                      opacity="0.2"
                    />
                    <path
                      d="M10 45 L90 45 L85 52 L15 52 Z M20 15 L15 25 H85 L80 15 H20 Z M25 25 L35 45 H65 L75 25 Z"
                      stroke="url(#glow-grad)"
                      strokeWidth="1.5"
                      filter="url(#neon-glow)"
                      style={{ strokeDasharray: isForging ? '10 5' : 'none', transition: 'stroke-dasharray 0.5s ease' }}
                    />
                  </svg>
                  <span style={{ fontSize: '0.9rem', color: '#fff', letterSpacing: '0.1em', fontWeight: 700, textTransform: 'uppercase' }}>
                    {activePlayground === 'sign' && 'MINTING PROOF'}
                    {activePlayground === 'verify' && 'VALIDATING BOUNDARY'}
                    {activePlayground === 'contract' && 'ENFORCING RULES'}
                  </span>
                </motion.div>
              </AnimatePresence>
            </div>

            <div className="console-box">
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
      </section>

      <section id="protocol" className="container architecture-section">
        <h2 style={{ textAlign: 'center', marginBottom: '1rem' }}>Engineered for zero trust.</h2>
        <p style={{ color: '#8f8f9e', fontSize: '1.2rem', textAlign: 'center', maxWidth: '600px', margin: '0 auto' }}>
          Eliminate complex authorization architectures. TrustForge wraps session negotiation into stateless verification structures.
        </p>

        <div className="cards-grid">
          <GlowCard>
            <div className="icon-wrapper"><Shield size={28} /></div>
            <h3>Stateless Assertions</h3>
            <p>Skip round-trips to key vaults or central databases. Cryptographic capability boundaries are decoded and authenticated directly at edge layers within microseconds.</p>
          </GlowCard>
          
          <GlowCard>
            <div className="icon-wrapper"><Fingerprint size={28} /></div>
            <h3>Dynamic Keystores</h3>
            <p>Rotate verification certificates statelessly. Supports automatic configuration pulling with native fallback paths to cached local buffers.</p>
          </GlowCard>

          <GlowCard>
            <div className="icon-wrapper"><Zap size={28} /></div>
            <h3>Quantum Immunity</h3>
            <p>Future-proof envelope formats designed to host hybrid post-quantum cryptography payloads (PQ-MLDSA) alongside production-ready elliptic curves.</p>
          </GlowCard>
        </div>
      </section>

      <section id="integration" className="container integration-section">
        <h2 style={{ textAlign: 'center', marginBottom: '3rem' }}>Integrate in seconds.</h2>
        
        <div className="integration-tabs">
          <button 
            className={`tab-btn ${activeTab === 'nextjs' ? 'active' : ''}`}
            onClick={() => setActiveTab('nextjs')}
          >
            Next.js Edge
          </button>
          <button 
            className={`tab-btn ${activeTab === 'workers' ? 'active' : ''}`}
            onClick={() => setActiveTab('workers')}
          >
            Cloudflare Workers
          </button>
          <button 
            className={`tab-btn ${activeTab === 'rust' ? 'active' : ''}`}
            onClick={() => setActiveTab('rust')}
          >
            Rust Backend
          </button>
        </div>

        <div className="code-panel">
          <div className="code-header">
            <span className="code-filename">{codeSnippets[activeTab].file}</span>
            <span style={{ fontSize: '0.85rem', color: '#6e6e7c', fontWeight: 650 }}>TYPESCRIPT</span>
          </div>
          <div className="code-body">
            <code>
              {codeSnippets[activeTab].code}
            </code>
          </div>
        </div>
      </section>

      <footer className="footer">
        <div className="container footer-content">
          <div className="footer-logo">
            <div className="logo-symbol" />
            TrustForge
          </div>
          <p>© 2026 TrustForge Protocol. Released under Apache-2.0.</p>
        </div>
      </footer>
    </main>
  );
}
