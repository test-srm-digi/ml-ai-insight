import React from 'react';

export default function Header() {
  return (
    <header className="header">
      <div className="header-content">
        <div className="header-left">
          <div className="logo">
            <svg width="28" height="28" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
              <path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/>
            </svg>
          </div>
          <div>
            <h1 className="header-title">VulnInsight</h1>
            <p className="header-subtitle">ML-Powered Vulnerability Risk Intelligence</p>
          </div>
        </div>
      </div>
    </header>
  );
}
