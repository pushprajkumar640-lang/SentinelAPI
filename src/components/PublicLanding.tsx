import React, { useState } from 'react';
import { ArrowRight, Menu, Shield, X } from 'lucide-react';
import { LandingHero } from './LandingHero';

interface PublicLandingProps {
  onOpenAuth: (mode: 'signin' | 'signup') => void;
  onOpenDashboard: () => void;
}

export const PublicLanding: React.FC<PublicLandingProps> = ({ onOpenAuth, onOpenDashboard }) => {
  const [menuOpen, setMenuOpen] = useState(false);

  const openAuth = (mode: 'signin' | 'signup') => {
    setMenuOpen(false);
    onOpenAuth(mode);
  };

  return (
    <main className="landing-shell cyber-grid">
      <header className="landing-nav">
        <div className="brand-lockup">
          <div className="brand-mark"><Shield className="h-5 w-5" /></div>
          <span>SENTINEL<span className="text-emerald-400">API</span></span>
        </div>
        <button
          type="button"
          className="landing-menu-button"
          onClick={() => setMenuOpen((open) => !open)}
          aria-label={menuOpen ? 'Close menu' : 'Open menu'}
        >
          {menuOpen ? <X className="h-5 w-5" /> : <Menu className="h-5 w-5" />}
        </button>
        {menuOpen && (
          <>
            <button
              type="button"
              aria-label="Close menu"
              className="landing-menu-backdrop"
              onClick={() => setMenuOpen(false)}
            />
            <nav className="landing-menu glass-panel">
              <button type="button" onClick={() => openAuth('signin')}>Sign In <ArrowRight className="h-4 w-4" /></button>
              <button type="button" onClick={() => openAuth('signup')}>Create Account <ArrowRight className="h-4 w-4" /></button>
              <button type="button" onClick={() => { setMenuOpen(false); onOpenDashboard(); }}>Dashboard <ArrowRight className="h-4 w-4" /></button>
              <a href="#about" onClick={() => setMenuOpen(false)}>About <ArrowRight className="h-4 w-4" /></a>
              <a href="mailto:security@sentinelapi.dev" onClick={() => setMenuOpen(false)}>Contact <ArrowRight className="h-4 w-4" /></a>
            </nav>
          </>
        )}
      </header>

      <div id="about">
        <LandingHero
          onStartScan={() => openAuth('signup')}
          onOpenPresentation={() => openAuth('signin')}
        />
      </div>
    </main>
  );
};