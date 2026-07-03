"use client";

import React, { useState } from 'react';
import { Header } from '../../components/Header';
import { Footer } from '../../components/Footer';

export default function Integration() {
  const [activeTab, setActiveTab] = useState<'nextjs' | 'workers' | 'rust'>('nextjs');

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
          <span className="token-keyword">import</span> {'{'} TrustForge {'}'} <span className="token-string">'@trustforge-protocol/sdk'</span>;<br/><br/>

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
      <Header />

      <section className="container section-padding" style={{ paddingTop: '10rem' }}>
        <div className="section-title-wrapper" style={{ textAlign: 'left', margin: '0 0 4rem 0', maxWidth: '800px' }}>
          <div className="badge">Integration</div>
          <h1 style={{ fontSize: '3.5rem', marginBottom: '1.5rem' }}>SDK Reference Guide</h1>
          <p style={{ fontSize: '1.2rem', color: 'var(--text-muted)' }}>
            Integrate TrustForge into your Next.js application, Cloudflare Workers backend, or native Rust servers with minimal lines of code.
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

      <Footer />
    </main>
  );
}
