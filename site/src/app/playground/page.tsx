"use client";

import React, { useState, useEffect } from 'react';

export default function Playground() {
  const [activePlayground, setActivePlayground] = useState<'sign' | 'verify' | 'contract'>('sign');
  const [consoleLogs, setConsoleLogs] = useState<string[]>([]);
  const [isForging, setIsForging] = useState(false);

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

  return (
    <main className="container section-padding">
      <div className="page-header">
        <h1>Anvil Playground</h1>
        <p>Experience the latency and flow of stateless cryptographic evaluation.</p>
      </div>

      <div style={{ display: 'grid', gridTemplateColumns: '1fr', gap: '2rem', maxWidth: '800px', margin: '0 auto' }}>
        <div style={{ display: 'flex', gap: '1rem', borderBottom: '1px solid var(--border)', paddingBottom: '1rem' }}>
          <button 
            className="btn"
            style={{ 
              background: activePlayground === 'sign' ? 'var(--text)' : 'transparent',
              color: activePlayground === 'sign' ? 'var(--bg)' : 'var(--text)',
              border: '1px solid var(--text)'
            }}
            onClick={() => triggerPlaygroundAction('sign')}
          >
            Sign
          </button>
          <button 
            className="btn"
            style={{ 
              background: activePlayground === 'verify' ? 'var(--text)' : 'transparent',
              color: activePlayground === 'verify' ? 'var(--bg)' : 'var(--text)',
              border: '1px solid var(--text)'
            }}
            onClick={() => triggerPlaygroundAction('verify')}
          >
            Verify
          </button>
          <button 
            className="btn"
            style={{ 
              background: activePlayground === 'contract' ? 'var(--text)' : 'transparent',
              color: activePlayground === 'contract' ? 'var(--bg)' : 'var(--text)',
              border: '1px solid var(--text)'
            }}
            onClick={() => triggerPlaygroundAction('contract')}
          >
            Guard
          </button>
        </div>

        <div style={{
          background: 'var(--accents-1)',
          border: '1px solid var(--border-subtle)',
          borderRadius: '8px',
          padding: '2rem',
          fontFamily: 'monospace',
          fontSize: '0.9rem',
          minHeight: '300px'
        }}>
          {consoleLogs.map((log, idx) => (
            <div key={idx} style={{ marginBottom: '0.5rem' }}>
              <span style={{ color: 'var(--text-muted)', marginRight: '1rem' }}>&gt;</span>
              <span>{log}</span>
            </div>
          ))}
          {isForging && (
            <div>
              <span style={{ color: 'var(--text-muted)', marginRight: '1rem' }}>&gt;</span>
              <span style={{ opacity: 0.5 }}>Processing...</span>
            </div>
          )}
        </div>
      </div>
    </main>
  );
}
