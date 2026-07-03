"use client";

import React from 'react';
import { Header } from '../../components/Header';
import { Footer } from '../../components/Footer';
import { Cpu } from 'lucide-react';

export default function Hardware() {
  return (
    <main>
      <div className="grid-overlay" />
      <Header />

      <section className="container section-padding" style={{ paddingTop: '10rem' }}>
        <div className="section-title-wrapper" style={{ textAlign: 'left', margin: '0 0 4rem 0', maxWidth: '800px' }}>
          <div className="badge">Embedded Core</div>
          <h1 style={{ fontSize: '3.5rem', marginBottom: '1.5rem' }}>Microcontroller Trust Anchors</h1>
          <p style={{ fontSize: '1.2rem', color: 'var(--text-muted)' }}>
            TrustForge is built to compile natively onto bare-metal hardware. Bring secure cryptographic packet signing and zero-trust identity architectures to embedded IoT devices.
          </p>
        </div>

        <div className="hardware-targets-grid" style={{ marginBottom: '5rem' }}>
          <div className="hardware-card">
            <div className="hardware-chip-badge">tf-esp32-wifi</div>
            <h3>ESP32</h3>
            <p style={{ color: 'var(--text-muted)', fontSize: '0.85rem' }}>Direct integration with ESP32-IDF / ESP-WIFI drivers. Signs Wi-Fi packets statelessly.</p>
          </div>
          <div className="hardware-card">
            <div className="hardware-chip-badge">tf-rp2040-picow</div>
            <h3>RP2040</h3>
            <p style={{ color: 'var(--text-muted)', fontSize: '0.85rem' }}>Optimized assembly footprint for dual ARM Cortex-M0+ cores on Raspberry Pi Pico W.</p>
          </div>
          <div className="hardware-card">
            <div className="hardware-chip-badge">tf-nrf52-ble</div>
            <h3>nRF52</h3>
            <p style={{ color: 'var(--text-muted)', fontSize: '0.85rem' }}>Secure BLE packet signing envelopes utilizing hardware crypto accelerators.</p>
          </div>
          <div className="hardware-card">
            <div className="hardware-chip-badge">tf-stm32wl-lora</div>
            <h3>STM32WL</h3>
            <p style={{ color: 'var(--text-muted)', fontSize: '0.85rem' }}>Long-range secure LoRaWAN capability packet injection layers.</p>
          </div>
        </div>
      </section>

      <section className="container section-padding" style={{ borderTop: '1px solid rgba(255,255,255,0.03)' }}>
        <h2>Bare-Metal Verification Flow</h2>
        <p style={{ color: 'var(--text-muted)', marginBottom: '3rem', maxWidth: '600px' }}>
          By implementing `tf-embedded-hal`, microcontrollers can verify signed decisions from the local system or upstream gateway.
        </p>
        <div className="code-panel">
          <div className="code-header">
            <span className="code-filename">embedded/src/main.rs</span>
            <span style={{ fontSize: '0.85rem', color: '#6e6e7c', fontWeight: 650 }}>RUST</span>
          </div>
          <div className="code-body">
            <code>
              <span className="token-keyword">use</span> tf_embedded_hal::{'{'}HardwareVerifier, Sha3Digest{'}'};<br/>
              <span className="token-keyword">use</span> embedded_hal::digital::v2::OutputPin;<br/><br/>

              <span className="token-keyword">fn</span> <span className="token-function">main</span>() {'{'}<br/>
              &nbsp;&nbsp;<span className="token-comment">// Initialize embedded hardware trust verifier</span><br/>
              &nbsp;&nbsp;<span className="token-keyword">let</span> verifier = HardwareVerifier::new_with_accelerator();<br/><br/>

              &nbsp;&nbsp;<span className="token-comment">// Verify stateless capability envelopes locally</span><br/>
              &nbsp;&nbsp;<span className="token-keyword">let</span> result = verifier.verify_action(INPUT_PACKET_BYTES);<br/><br/>

              &nbsp;&nbsp;<span className="token-keyword">if</span> result.is_ok() {'{'}<br/>
              &nbsp;&nbsp;&nbsp;&nbsp;trigger_gpio_output();<br/>
              &nbsp;&nbsp;{'}'}<br/>
              {'}'}
            </code>
          </div>
        </div>
      </section>

      <Footer />
    </main>
  );
}
