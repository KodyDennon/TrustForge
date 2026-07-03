"use client";

import React from 'react';
import Link from 'next/link';
import { usePathname } from 'next/navigation';

export const Header = () => {
  const pathname = usePathname();

  return (
    <header className="nav-header">
      <div className="nav-container">
        <Link href="/" className="logo">
          <div className="logo-symbol" />
          TrustForge
        </Link>
        <nav className="nav-links">
          <Link href="/docs" className={pathname === '/docs' ? 'active' : ''}>Documentation</Link>
          <Link href="/architecture" className={pathname === '/architecture' ? 'active' : ''}>Architecture</Link>
          <Link href="/playground" className={pathname === '/playground' ? 'active' : ''}>Playground</Link>
          <Link href="/agents" className={pathname === '/agents' ? 'active' : ''}>AI Agents</Link>
          <a href="https://github.com/KodyDennon/TrustForge" target="_blank" rel="noopener noreferrer">GitHub</a>
        </nav>
      </div>
    </header>
  );
};

export default Header;
