"use client";

import React, { useState, useEffect, useRef } from 'react';
import { motion, AnimatePresence } from 'framer-motion';
import { Terminal, Lock, ShieldCheck, Zap } from 'lucide-react';

export default function Playground() {
  const [activePlayground, setActivePlayground] = useState<'sign' | 'verify' | 'contract'>('sign');
  const [consoleLogs, setConsoleLogs] = useState<string[]>([]);
  const [isForging, setIsForging] = useState(false);
  const consoleEndRef = useRef<HTMLDivElement>(null);

  const scrollToBottom = () => {
    consoleEndRef.current?.scrollIntoView({ behavior: "smooth" });
  };

  useEffect(() => {
    scrollToBottom();
  }, [consoleLogs, isForging]);

  const triggerPlaygroundAction = (action: 'sign' | 'verify' | 'contract') => {
    setActivePlayground(action);
    setIsForging(true);
    setConsoleLogs([`> Initiating [${action.toUpperCase()}] protocol sequence...`]);

    const runLogs = async () => {
      let sequence: string[] = [];
      if (action === 'sign') {
        sequence = [
          'Initializing cryptographic keystore...',
          'Loading active profile key pair (Ed25519)...',
          'Hashing capability payload with SHA3-256...',
          'Signing capabilities vector with private key...',
          'SUCCESS: Proof generated: trustforge.cap.e27fc9...8a12f'
        ];
      } else if (action === 'verify') {
        sequence = [
          'Receiving inbound signed capability packet...',
          'Extracting signature payload and public key...',
          'Validating signature mathematical proof...',
          'Cryptographic boundary verified: Signature OK',
          'SUCCESS: STATISTICAL TRUST RATING: 100%'
        ];
      } else {
        sequence = [
          'Retrieving capability target: db:write',
          'Executing active Rego policy validation...',
          'Matching agent session variables with allowed policy schema...',
          'Policy validated successfully: ALLOW',
          'SUCCESS: Action executed.'
        ];
      }
      
      for (const log of sequence) {
        await new Promise((r) => setTimeout(r, 400));
        setConsoleLogs((prev) => [...prev, log]);
      }
      setIsForging(false);
    };

    runLogs();
  };

  useEffect(() => {
    triggerPlaygroundAction('sign');
  }, []);

  return (
    <main className="container section-padding">
      <motion.div 
        className="page-header"
        initial={{ opacity: 0, y: -20 }}
        animate={{ opacity: 1, y: 0 }}
        transition={{ duration: 0.6 }}
      >
        <h1>The Anvil Playground</h1>
        <p>Experience the latency and flow of stateless cryptographic evaluation directly in your browser.</p>
      </motion.div>

      <div style={{ maxWidth: '900px', margin: '0 auto' }}>
        <div style={{ display: 'flex', gap: '1rem', justifyContent: 'center', marginBottom: '3rem' }}>
          <button 
            className={`btn ${activePlayground === 'sign' ? 'btn-primary' : 'btn-secondary'}`}
            onClick={() => triggerPlaygroundAction('sign')}
            disabled={isForging}
          >
            <Lock size={18} /> Sign Proof
          </button>
          <button 
            className={`btn ${activePlayground === 'verify' ? 'btn-primary' : 'btn-secondary'}`}
            onClick={() => triggerPlaygroundAction('verify')}
            disabled={isForging}
          >
            <ShieldCheck size={18} /> Verify Proof
          </button>
          <button 
            className={`btn ${activePlayground === 'contract' ? 'btn-primary' : 'btn-secondary'}`}
            onClick={() => triggerPlaygroundAction('contract')}
            disabled={isForging}
          >
            <Zap size={18} /> Enforce Rego
          </button>
        </div>

        <motion.div 
          className="card"
          initial={{ opacity: 0, scale: 0.95 }}
          animate={{ opacity: 1, scale: 1 }}
          transition={{ duration: 0.5 }}
          style={{ padding: 0, overflow: 'hidden', border: '1px solid var(--glass-border-hover)' }}
        >
          <div style={{ background: 'rgba(0,0,0,0.8)', padding: '1rem 1.5rem', borderBottom: '1px solid var(--glass-border)', display: 'flex', alignItems: 'center', gap: '0.75rem' }}>
            <Terminal size={18} color="var(--text-muted)" />
            <span style={{ fontSize: '0.9rem', color: 'var(--text-muted)', fontFamily: 'monospace' }}>tf-daemon --interactive</span>
          </div>
          
          <div style={{
            background: 'rgba(10, 10, 15, 0.9)',
            padding: '2rem',
            fontFamily: 'monospace',
            fontSize: '1rem',
            minHeight: '400px',
            maxHeight: '400px',
            overflowY: 'auto',
            color: 'var(--primary)'
          }}>
            <AnimatePresence>
              {consoleLogs.map((log, idx) => (
                <motion.div 
                  key={idx}
                  initial={{ opacity: 0, x: -10 }}
                  animate={{ opacity: 1, x: 0 }}
                  style={{ marginBottom: '0.75rem', color: log.startsWith('SUCCESS') ? 'var(--primary)' : 'var(--text-muted)' }}
                >
                  <span style={{ marginRight: '1rem', opacity: 0.5 }}>{new Date().toISOString().split('T')[1].split('.')[0]}</span>
                  <span>{log}</span>
                </motion.div>
              ))}
              {isForging && (
                <motion.div 
                  initial={{ opacity: 0 }}
                  animate={{ opacity: 1 }}
                  style={{ color: 'var(--text-muted)' }}
                >
                  <span style={{ marginRight: '1rem', opacity: 0.5 }}>{new Date().toISOString().split('T')[1].split('.')[0]}</span>
                  <span className="typing-indicator">Processing...</span>
                </motion.div>
              )}
            </AnimatePresence>
            <div ref={consoleEndRef} />
          </div>
        </motion.div>
      </div>
    </main>
  );
}
