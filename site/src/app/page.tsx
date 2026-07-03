"use client";

import React from 'react';
import Link from 'next/link';
import { motion } from 'framer-motion';
import { Shield, Cpu, Code2, ArrowRight } from 'lucide-react';

export default function Home() {
  const container = {
    hidden: { opacity: 0 },
    show: {
      opacity: 1,
      transition: { staggerChildren: 0.2, delayChildren: 0.3 }
    }
  };

  const item = {
    hidden: { opacity: 0, y: 30 },
    show: { opacity: 1, y: 0, transition: { type: "spring", stiffness: 300, damping: 24 } }
  };

  return (
    <main>
      <section className="container hero">
        <motion.div
          initial={{ opacity: 0, y: -20 }}
          animate={{ opacity: 1, y: 0 }}
          transition={{ duration: 0.8, ease: "easeOut" }}
        >
          <div style={{ display: 'inline-flex', alignItems: 'center', gap: '0.5rem', background: 'rgba(255,255,255,0.05)', padding: '0.5rem 1rem', borderRadius: '100px', border: '1px solid var(--glass-border)', marginBottom: '2rem', fontSize: '0.9rem', color: 'var(--text-muted)' }}>
            <span style={{ display: 'inline-block', width: '8px', height: '8px', background: 'var(--primary)', borderRadius: '50%', boxShadow: '0 0 10px var(--primary)' }}></span>
            TrustForge Protocol v0.1.2 is Live
          </div>
          <h1 style={{ fontSize: '5.5rem', marginBottom: '1.5rem', lineHeight: '1.1', background: 'linear-gradient(to right, #ffffff, #a0a0b0)', WebkitBackgroundClip: 'text', WebkitTextFillColor: 'transparent' }}>
            Verifiable Action <br/> at the Edge.
          </h1>
          <p style={{ fontSize: '1.4rem', color: 'var(--text-muted)', maxWidth: '700px', margin: '0 auto 3rem', lineHeight: '1.6' }}>
            A high-performance open-source trust fabric designed for AI agents and distributed systems. Replace bloated stateful databases with stateless cryptographic proofs.
          </p>
          <div className="button-group">
            <Link href="/docs" className="btn btn-primary">
              Read Documentation <ArrowRight size={18} />
            </Link>
            <a href="https://github.com/KodyDennon/TrustForge" target="_blank" rel="noopener noreferrer" className="btn btn-secondary">
              View Source
            </a>
          </div>
        </motion.div>
      </section>

      <section className="container section-padding" style={{ borderTop: '1px solid var(--glass-border)', position: 'relative' }}>
        {/* Subtle background glow for the section */}
        <div style={{ position: 'absolute', top: 0, left: '50%', transform: 'translate(-50%, -50%)', width: '80%', height: '300px', background: 'radial-gradient(ellipse at top, rgba(176, 82, 245, 0.15), transparent 70%)', pointerEvents: 'none' }} />
        
        <div className="content-area" style={{ maxWidth: '1000px', textAlign: 'center', margin: '0 auto' }}>
          <motion.div
            initial={{ opacity: 0, y: 20 }}
            whileInView={{ opacity: 1, y: 0 }}
            viewport={{ once: true, margin: "-100px" }}
            transition={{ duration: 0.6 }}
          >
            <h2 style={{ fontSize: '3rem', marginBottom: '1rem', background: 'linear-gradient(to right, #fff, #a0a0b0)', WebkitBackgroundClip: 'text', WebkitTextFillColor: 'transparent', margin: '0 auto 1.5rem' }}>Core Capabilities</h2>
            <p style={{ fontSize: '1.25rem', color: 'var(--text-muted)', maxWidth: '600px', margin: '0 auto 4rem' }}>
              Engineered for extreme performance and absolute zero-trust verification environments.
            </p>
          </motion.div>
          
          <motion.div 
            className="grid" style={{ gridTemplateColumns: 'repeat(3, 1fr)', textAlign: 'left', marginTop: '0' }}
            variants={container}
            initial="hidden"
            whileInView="show"
            viewport={{ once: true, margin: "-100px" }}
          >
            <motion.div variants={item} className="card">
              <div className="card-icon">
                <Shield size={24} />
              </div>
              <h3>Stateless Verification</h3>
              <p>Capabilities are evaluated directly inside memory boundaries on edge nodes within microseconds. Zero database lookups or network overhead.</p>
            </motion.div>
            
            <motion.div variants={item} className="card">
              <div className="card-icon">
                <Cpu size={24} />
              </div>
              <h3>Embedded Compilation</h3>
              <p>Natively support bare-metal target microcontrollers (ESP32, RP2040) directly connecting to the cryptographic fabric using `#![no_std]` Rust.</p>
            </motion.div>

            <motion.div variants={item} className="card">
              <div className="card-icon">
                <Code2 size={24} />
              </div>
              <h3>AI Native API</h3>
              <p>Designed with programmatic schemas and LLM-first documentation, allowing autonomous agents to mint and verify zero-trust proofs seamlessly.</p>
            </motion.div>
          </motion.div>
        </div>
      </section>
    </main>
  );
}
