"use client";

import React, { useEffect, useRef, useState } from 'react';
import { motion, useScroll, useTransform } from 'framer-motion';
import { Shield, Fingerprint, Zap, Key, Code2, Server, Check, ArrowRight, Github } from 'lucide-react';
import Image from 'next/image';

const GlassCard = ({ children, className = "" }: { children: React.ReactNode, className?: string }) => {
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
    <div 
      ref={cardRef} 
      className={`glass-card ${className}`} 
      onMouseMove={handleMouseMove}
    >
      {children}
    </div>
  );
};

export default function Home() {
  const [scrolled, setScrolled] = useState(false);
  const { scrollYProgress } = useScroll();
  const y = useTransform(scrollYProgress, [0, 1], [0, 200]);
  const opacity = useTransform(scrollYProgress, [0, 0.5], [1, 0]);

  useEffect(() => {
    const handleScroll = () => {
      setScrolled(window.scrollY > 50);
    };
    window.addEventListener('scroll', handleScroll);
    return () => window.removeEventListener('scroll', handleScroll);
  }, []);

  return (
    <main>
      <div className="bg-grid" />
      <div className="bg-glow" />

      <header className={`nav-header ${scrolled ? 'scrolled' : ''}`}>
        <div className="nav-container">
          <div className="logo">
            <div className="logo-icon"></div>
            TrustForge
          </div>
          <nav className="nav-links">
            <a href="#protocol">Protocol</a>
            <a href="#integration">Integration</a>
            <a href="https://github.com/KodyDennon/TrustForge" target="_blank" rel="noopener noreferrer">GitHub</a>
          </nav>
        </div>
      </header>

      <section className="hero container">
        <motion.div
          initial={{ opacity: 0, y: 20 }}
          animate={{ opacity: 1, y: 0 }}
          transition={{ duration: 0.8, ease: [0.16, 1, 0.3, 1] }}
          style={{ y, opacity }}
        >
          <div className="badge">
            <div className="badge-dot" />
            v0.1.1 Experimental Now Live
          </div>
          <h1>
            The Next Era of Security is <br />
            <span className="gradient-text-accent">Verifiable Action.</span>
          </h1>
          <p className="subtitle">
            TrustForge is the open-source trust fabric for AI-native software. Secure devices, authenticate live systems, and mint verifiable cryptographic proofs with zero-trust architectures.
          </p>
          <div className="cta-group">
            <a href="#integration" className="cta-button">
              Start Building <ArrowRight size={20} />
            </a>
            <a href="https://github.com/KodyDennon/TrustForge" target="_blank" rel="noopener noreferrer" className="cta-button cta-secondary">
              <Github size={20} /> View on GitHub
            </a>
          </div>
        </motion.div>
      </section>

      <section id="protocol" className="container" style={{ padding: '8rem 0' }}>
        <motion.div 
          initial={{ opacity: 0 }}
          whileInView={{ opacity: 1 }}
          viewport={{ once: true }}
          transition={{ duration: 1 }}
        >
          <h2 style={{ textAlign: 'center', marginBottom: '4rem' }}>
            A unified cryptographic fabric <br/> deployed across the <span className="gradient-text-accent">entire stack.</span>
          </h2>
        </motion.div>

        <div className="features-grid">
          <GlassCard>
            <div className="icon-wrapper"><Shield size={32} /></div>
            <h3>AI-Native Security</h3>
            <p>Designed from the ground up for autonomous agents. Issue capabilities and verify programmatic actions with mathematical certainty—not just bearer tokens.</p>
          </GlassCard>

          <GlassCard>
            <div className="icon-wrapper"><Fingerprint size={32} /></div>
            <h3>Cryptographic Proofs</h3>
            <p>Every action requires a signed, verifiable packet. Session logic uses X25519, ChaCha20-Poly1305, and Ed25519 to securely negotiate zero-trust boundaries.</p>
          </GlassCard>

          <GlassCard>
            <div className="icon-wrapper"><Zap size={32} /></div>
            <h3>Universal Adapters</h3>
            <p>Seamlessly integrate with Next.js, Cloudflare Workers, Axum, Express, and bare-metal embedded targets (ESP32, RP2040) via a unified SDK pipeline.</p>
          </GlassCard>

          <GlassCard>
            <div className="icon-wrapper"><Key size={32} /></div>
            <h3>Stateless Verification</h3>
            <p>Eliminate database lookups on the edge. TrustForge capabilities are fully self-contained cryptographic documents that can be instantly validated anywhere.</p>
          </GlassCard>

          <GlassCard>
            <div className="icon-wrapper"><Code2 size={32} /></div>
            <h3>Agent-Contract Guards</h3>
            <p>Define strict execution policies using Rego. Constrain exactly what an AI agent or downstream microservice is allowed to execute based on cryptographically signed rules.</p>
          </GlassCard>

          <GlassCard>
            <div className="icon-wrapper"><Server size={32} /></div>
            <h3>Distributed Edge-Native</h3>
            <p>Built for the modern web. TrustForge adapters natively compile to WebAssembly, ensuring blindingly fast execution on Vercel Edge, Deno, and Cloudflare Pages.</p>
          </GlassCard>
        </div>
      </section>

      <section id="integration" className="container section-split">
        <motion.div
          initial={{ opacity: 0, x: -50 }}
          whileInView={{ opacity: 1, x: 0 }}
          viewport={{ once: true }}
          transition={{ duration: 0.8, ease: "easeOut" }}
        >
          <h2>Stop guessing who is making the request.</h2>
          <p className="subtitle" style={{ margin: '0 0 2rem 0', textAlign: 'left' }}>
            Standard security relies on perimeter defense and leaked API keys. TrustForge requires every actor—human or machine—to cryptographically sign every capability they exercise. 
          </p>
          <ul className="check-list">
            <li><Check className="check-icon" size={24} /> Type-safe Next.js integration</li>
            <li><Check className="check-icon" size={24} /> Post-Quantum Ready architecture</li>
            <li><Check className="check-icon" size={24} /> Rust core compiled to blazing fast WASM</li>
          </ul>
        </motion.div>

        <motion.div
          initial={{ opacity: 0, x: 50 }}
          whileInView={{ opacity: 1, x: 0 }}
          viewport={{ once: true }}
          transition={{ duration: 0.8, ease: "easeOut", delay: 0.2 }}
          className="terminal-wrapper"
        >
          <div className="terminal-header">
            <div className="terminal-dot dot-r" />
            <div className="terminal-dot dot-y" />
            <div className="terminal-dot dot-g" />
          </div>
          <div className="terminal-body">
            <span className="token-keyword">import</span> {'{'} TrustForge {'}'} <span className="token-keyword">from</span> <span className="token-string">'@trustforge-protocol/core'</span>;<br/><br/>
            
            <span className="token-comment">// Initialize the protocol daemon on the edge</span><br/>
            <span className="token-keyword">const</span> <span className="token-variable">tf</span> = <span className="token-keyword">new</span> <span className="token-function">TrustForge</span>({'{'}<br/>
            &nbsp;&nbsp;profile: <span className="token-string">'tf-enterprise-compatible'</span>,<br/>
            &nbsp;&nbsp;keys: <span className="token-function">loadVaultKeys</span>(),<br/>
            {'}'});<br/><br/>

            <span className="token-comment">// Cryptographically verify an incoming agent packet</span><br/>
            <span className="token-keyword">const</span> <span className="token-variable">packet</span> = <span className="token-keyword">await</span> tf.<span className="token-function">verify</span>(req.body);<br/><br/>

            <span className="token-keyword">if</span> (!packet.<span className="token-function">hasPermission</span>(<span className="token-string">'db:write'</span>)) {'{'}<br/>
            &nbsp;&nbsp;<span className="token-keyword">throw new</span> <span className="token-function">Error</span>(<span className="token-string">'Invalid Agent Contract'</span>);<br/>
            {'}'}
          </div>
        </motion.div>
      </section>

      <footer className="footer">
        <div className="container">
          <div className="logo" style={{ justifyContent: 'center', marginBottom: '1rem', opacity: 0.5 }}>
            <div className="logo-icon" style={{ filter: 'grayscale(100%)', width: '24px', height: '24px' }}></div>
            TrustForge
          </div>
          <p>© 2026 TrustForge Protocol. Open-source under Apache-2.0.</p>
        </div>
      </footer>
    </main>
  );
}
