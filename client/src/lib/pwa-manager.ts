/**
 * Enhanced PWA Manager with Installation State Management
 * Handles PWA prompt display logic and installation tracking
 */

interface BeforeInstallPromptEvent extends Event {
  readonly platforms: string[];
  readonly userChoice: Promise<{
    outcome: 'accepted' | 'dismissed';
    platform: string;
  }>;
  prompt(): Promise<void>;
}

interface PWAState {
  canInstall: boolean;
  isInstalled: boolean;
  isStandalone: boolean;
  platform: string | null;
  promptShown: boolean;
  installationDate: Date | null;
}

class PWAManager {
  private promptEvent: BeforeInstallPromptEvent | null = null;
  private state: PWAState;
  private listeners: Set<(state: PWAState) => void> = new Set();

  constructor() {
    this.state = this.calculateInitialState();
    this.setupEventListeners();
  }

  private calculateInitialState(): PWAState {
    const isStandalone = window.matchMedia('(display-mode: standalone)').matches ||
                        (window.navigator as any).standalone === true ||
                        document.referrer.includes('android-app://');

    const installationDate = localStorage.getItem('pwa-installation-date');
    const promptShown = localStorage.getItem('pwa-prompt-shown') === 'true';

    return {
      canInstall: false,
      isInstalled: isStandalone || installationDate !== null,
      isStandalone,
      platform: this.detectPlatform(),
      promptShown,
      installationDate: installationDate ? new Date(installationDate) : null
    };
  }

  private detectPlatform(): string | null {
    const userAgent = navigator.userAgent.toLowerCase();
    
    if (userAgent.includes('android')) return 'android';
    if (userAgent.includes('iphone') || userAgent.includes('ipad')) return 'ios';
    if (userAgent.includes('mac')) return 'macos';
    if (userAgent.includes('windows')) return 'windows';
    if (userAgent.includes('linux')) return 'linux';
    
    return null;
  }

  private setupEventListeners() {
    // Listen for beforeinstallprompt event
    window.addEventListener('beforeinstallprompt', (e) => {
      console.log('🔔 PWA install prompt available');
      e.preventDefault();
      this.promptEvent = e as BeforeInstallPromptEvent;
      
      this.updateState({
        canInstall: true
      });
    });

    // Listen for app installation
    window.addEventListener('appinstalled', () => {
      console.log('✅ PWA installed successfully');
      const installationDate = new Date();
      localStorage.setItem('pwa-installation-date', installationDate.toISOString());
      
      this.updateState({
        isInstalled: true,
        canInstall: false,
        installationDate
      });
      
      this.promptEvent = null;
    });

    // Monitor display mode changes
    const displayModeQuery = window.matchMedia('(display-mode: standalone)');
    displayModeQuery.addEventListener('change', (e) => {
      console.log('📱 Display mode changed:', e.matches ? 'standalone' : 'browser');
      this.updateState({
        isStandalone: e.matches
      });
    });

    // Check for iOS PWA installation periodically
    if (this.state.platform === 'ios') {
      this.setupiOSInstallCheck();
    }
  }

  private setupiOSInstallCheck() {
    // iOS doesn't fire standard PWA events, so we need to check manually
    const checkInterval = setInterval(() => {
      const wasStandalone = this.state.isStandalone;
      const isNowStandalone = (window.navigator as any).standalone === true;
      
      if (!wasStandalone && isNowStandalone) {
        console.log('✅ iOS PWA detected as installed');
        const installationDate = new Date();
        localStorage.setItem('pwa-installation-date', installationDate.toISOString());
        
        this.updateState({
          isInstalled: true,
          isStandalone: true,
          canInstall: false,
          installationDate
        });
        
        clearInterval(checkInterval);
      }
    }, 1000);

    // Clean up interval after 30 seconds
    setTimeout(() => clearInterval(checkInterval), 30000);
  }

  private updateState(updates: Partial<PWAState>) {
    const oldState = { ...this.state };
    this.state = { ...this.state, ...updates };
    
    console.log('PWA state updated:', { from: oldState, to: this.state });
    
    this.notifyListeners(this.state);
  }

  private notifyListeners(state: PWAState) {
    this.listeners.forEach(listener => {
      try {
        listener(state);
      } catch (error) {
        const errorObj = error instanceof Error ? error : new Error(String(error));
        console.error('PWA state listener error:', errorObj);
        if (window.Sentry) {
          window.Sentry.captureException(errorObj, {
            tags: { component: 'PWAManager' }
          });
        }
      }
    });
  }

  public subscribe(listener: (state: PWAState) => void): () => void {
    this.listeners.add(listener);
    
    // Immediately call with current state
    listener(this.state);
    
    return () => {
      this.listeners.delete(listener);
    };
  }

  public async showInstallPrompt(): Promise<boolean> {
    if (!this.promptEvent) {
      console.warn('🚫 PWA install prompt not available');
      return false;
    }

    try {
      console.log('🔔 Showing PWA install prompt');
      localStorage.setItem('pwa-prompt-shown', 'true');
      
      this.updateState({
        promptShown: true
      });

      await this.promptEvent.prompt();
      const choiceResult = await this.promptEvent.userChoice;
      
      console.log('👤 User PWA install choice:', choiceResult.outcome);
      
      if (choiceResult.outcome === 'accepted') {
        this.promptEvent = null;
        return true;
      }
      
      return false;
    } catch (error) {
      const errorObj = error instanceof Error ? error : new Error(String(error));
      console.error('❌ PWA install prompt error:', errorObj);
      if (window.Sentry) {
        window.Sentry.captureException(errorObj);
      }
      return false;
    }
  }

  public shouldShowInstallButton(): boolean {
    // Don't show if already installed
    if (this.state.isInstalled) return false;
    
    // Don't show if can't install
    if (!this.state.canInstall) return false;
    
    // Don't show on iOS (uses different installation method)
    if (this.state.platform === 'ios') return false;
    
    // Don't show if user already dismissed it recently
    const lastDismissed = localStorage.getItem('pwa-prompt-dismissed');
    if (lastDismissed) {
      const dismissedDate = new Date(lastDismissed);
      const daysSinceDismissed = (Date.now() - dismissedDate.getTime()) / (1000 * 60 * 60 * 24);
      if (daysSinceDismissed < 7) return false; // Wait 7 days before showing again
    }
    
    return true;
  }

  public dismissInstallPrompt() {
    console.log('🚫 PWA install prompt dismissed');
    localStorage.setItem('pwa-prompt-dismissed', new Date().toISOString());
    
    this.updateState({
      canInstall: false
    });
  }

  public getState(): PWAState {
    return { ...this.state };
  }

  public isInstalled(): boolean {
    return this.state.isInstalled;
  }

  public canInstall(): boolean {
    return this.state.canInstall && this.shouldShowInstallButton();
  }

  public getInstallationDate(): Date | null {
    return this.state.installationDate;
  }

  public getPlatform(): string | null {
    return this.state.platform;
  }

  public isStandalone(): boolean {
    return this.state.isStandalone;
  }

  public cleanup() {
    this.listeners.clear();
    this.promptEvent = null;
  }
}

// Export singleton instance
export const pwaManager = new PWAManager();

// React hook for PWA state
export function usePWAState() {
  const [state, setState] = useState<PWAState>(pwaManager.getState());

  useEffect(() => {
    const unsubscribe = pwaManager.subscribe(setState);
    return unsubscribe;
  }, []);

  return {
    ...state,
    showInstallPrompt: () => pwaManager.showInstallPrompt(),
    dismissPrompt: () => pwaManager.dismissInstallPrompt(),
    shouldShowButton: pwaManager.shouldShowInstallButton()
  };
}

// Utility functions
export const isPWAInstalled = () => pwaManager.isInstalled();
export const canInstallPWA = () => pwaManager.canInstall();
export const showPWAPrompt = () => pwaManager.showInstallPrompt();

import { useState, useEffect } from 'react';

declare global {
  interface Window {
    Sentry?: {
      captureException: (error: Error, context?: any) => void;
    };
  }
}