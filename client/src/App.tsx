import { useState, useEffect } from "react";
import { Switch, Route } from "wouter";
import { queryClient } from "./lib/queryClient";
import { QueryClientProvider } from "@tanstack/react-query";
import { Toaster } from "@/components/ui/toaster";
import OptimizedTooltipProvider from "@/components/OptimizedTooltipProvider";
import RouterErrorBoundary from "@/components/RouterErrorBoundary";
import { performSecureLogout } from "@/utils/logout-handler";
import ErrorBoundary from "@/components/ErrorBoundary";

// Import components directly for stable routing
import Subscription from "@/pages/subscription";
import BrandPurpose from "@/pages/brand-purpose";
import IntelligentSchedule from "@/pages/intelligent-schedule";
import Login from "@/pages/login";
import Analytics from "@/pages/analytics";
import AIDashboard from "@/pages/ai-dashboard";
import VideoGen from "@/pages/video-gen";

import GrokWidget from "@/components/grok-widget";
import OnboardingWizard from "@/components/onboarding/OnboardingWizard";
import NotFound from "@/pages/not-found";
import { initGA } from "./lib/analytics";
import { useAnalytics } from "./hooks/use-analytics";
import { sentryLogger, setupGlobalErrorHandlers } from "./lib/sentry-config";
import { mobileDetection } from "./lib/mobile";
import { pwaManager } from "./lib/pwa-manager";
import { clearBrowserCache } from "./utils/cache-utils";
import { sessionManager } from "./utils/session-manager";
import { apiClient } from "./utils/api-client";
import pwaSessionManager from "./utils/PWASessionManager";
import { useSessionManager } from "@/hooks/useSessionManager";
import SessionLoadingSpinner from "@/components/SessionLoadingSpinner";
import { useMobileDetection } from "@/hooks/useMobileDetection";
import Splash from "@/pages/splash";
import PlatformConnections from "@/pages/real-platform-connections";
import ConnectPlatforms from "@/pages/connect-platforms";
import GrokTest from "@/pages/grok-test";
import YearlyAnalytics from "@/pages/yearly-analytics";
import Profile from "@/pages/profile";
import ResetPassword from "@/pages/reset-password";
import RedeemCertificate from "@/pages/redeem-certificate";
import AdminDashboard from "@/components/AdminDashboard";
import AdminVideoPrompts from "@/pages/admin-video-prompts";
import ConnectionRepair from "@/pages/connection-repair";
import OAuthReconnect from "@/pages/oauth-reconnect";
import TokenStatus from "@/pages/token-status";
import OAuthDiagnostic from "@/pages/oauth-diagnostic";
import InstagramFix from "@/pages/instagram-fix";
import DataDeletionStatus from "@/pages/data-deletion-status";
import MetaPixelTest from "@/pages/meta-pixel-test";
import BulletproofDashboard from "@/pages/bulletproof-dashboard";




// Enhanced logout component with comprehensive session clearing
function LogoutComponent() {
  useEffect(() => {
    const performLogout = async () => {
      try {
        // Call server logout endpoint
        await fetch('/api/auth/logout', {
          method: 'POST',
          credentials: 'include'
        });
        
        // Clear all client-side storage
        localStorage.clear();
        sessionStorage.clear();
        
        // Clear cookies manually
        document.cookie.split(";").forEach((c) => {
          const eqPos = c.indexOf("=");
          const name = eqPos > -1 ? c.substr(0, eqPos) : c;
          document.cookie = name + "=;expires=Thu, 01 Jan 1970 00:00:00 GMT;path=/";
          document.cookie = name + "=;expires=Thu, 01 Jan 1970 00:00:00 GMT;path=/;domain=" + window.location.hostname;
        });
        
        // Clear any cached data
        if ('caches' in window) {
          const names = await caches.keys();
          await Promise.all(names.map(name => caches.delete(name)));
        }
        
        console.log('🚪 Complete logout performed');
        
        // Force redirect to login
        window.location.replace('/api/login');
      } catch (error) {
        console.error('Logout error:', error);
        // Force logout even on error
        localStorage.clear();
        sessionStorage.clear();
        window.location.replace('/api/login');
      }
    };
    
    performLogout();
  }, []);
  
  return <div>Logging out...</div>;
}

function Router() {
  // Track page views when routes change
  useAnalytics();
  
  // Add error boundary for routing
  try {
    return (
      <Switch>
        <Route path="/" component={Splash} />
        <Route path="/subscription" component={Subscription} />
        <Route path="/brand-purpose" component={BrandPurpose} />
        <Route path="/platform-connections" component={ConnectPlatforms} />
        <Route path="/connect-platforms" component={ConnectPlatforms} />
        <Route path="/schedule" component={IntelligentSchedule} />
        <Route path="/intelligent-schedule" component={IntelligentSchedule} />
        <Route path="/analytics" component={Analytics} />
        <Route path="/ai-dashboard" component={AIDashboard} />
        <Route path="/yearly-analytics" component={YearlyAnalytics} />
        <Route path="/profile" component={Profile} />
        <Route path="/grok-test" component={GrokTest} />
        <Route path="/login" component={Login} />
        <Route path="/reset-password" component={ResetPassword} />
        <Route path="/redeem-certificate" component={RedeemCertificate} />
        <Route path="/admin" component={AdminDashboard} />
        <Route path="/admin/video-prompts" component={AdminVideoPrompts} />
        <Route path="/video-gen" component={VideoGen} />
        <Route path="/logout">
          {() => {
            // Immediately perform logout when route is accessed
            useEffect(() => {
              const performLogout = async () => {
                try {
                  // Call server logout endpoint
                  await fetch('/api/auth/logout', {
                    method: 'POST',
                    credentials: 'include'
                  });
                  
                  // Clear all client-side storage
                  localStorage.clear();
                  sessionStorage.clear();
                  
                  // Clear cookies manually
                  document.cookie.split(";").forEach((c) => {
                    const eqPos = c.indexOf("=");
                    const name = eqPos > -1 ? c.substr(0, eqPos) : c;
                    document.cookie = name + "=;expires=Thu, 01 Jan 1970 00:00:00 GMT;path=/";
                    document.cookie = name + "=;expires=Thu, 01 Jan 1970 00:00:00 GMT;path=/;domain=" + window.location.hostname;
                  });
                  
                  // Clear any cached data
                  if ('caches' in window) {
                    const names = await caches.keys();
                    await Promise.all(names.map(name => caches.delete(name)));
                  }
                  
                  console.log('🚪 Complete logout performed');
                  
                  // Force redirect to login
                  window.location.replace('/api/login');
                } catch (error) {
                  console.error('Logout error:', error);
                  // Force logout even on error
                  localStorage.clear();
                  sessionStorage.clear();
                  window.location.replace('/api/login');
                }
              };
              
              performLogout();
            }, []);
            
            return <div>Logging out...</div>;
          }}
        </Route>
      <Route path="/dashboard" component={ConnectPlatforms} />
      <Route path="/connection-repair" component={ConnectionRepair} />
      <Route path="/oauth-reconnect" component={OAuthReconnect} />
      <Route path="/token-status" component={TokenStatus} />
      <Route path="/oauth-diagnostic" component={OAuthDiagnostic} />
      <Route path="/instagram-fix" component={InstagramFix} />
      <Route path="/data-deletion-status" component={DataDeletionStatus} />
      <Route path="/meta-pixel-test" component={MetaPixelTest} />
      <Route component={NotFound} />
    </Switch>
  );
  } catch (error) {
    console.error("❌ Router error:", error);
    
    // Log to Sentry if available
    if (window.Sentry) {
      window.Sentry.captureException(error as Error, {
        tags: { component: 'Router' },
        extra: { location: window.location.href }
      });
    }
    
    return (
      <div style={{ padding: '20px', textAlign: 'center' }}>
        <h1>Navigation Error</h1>
        <p>Router failed to load. Please refresh the page.</p>
        <button onClick={() => window.location.reload()}>Refresh Page</button>
      </div>
    );
  }
}

function AppContent() {
  const sessionHook = useSessionManager();
  const mobileState = useMobileDetection();
  const [showOnboarding, setShowOnboarding] = useState(false);

  // Initialize Google Analytics with comprehensive fallback error handling
  useEffect(() => {
    const initializeGA = async () => {
      try {
        // Verify required environment variable is present
        if (!import.meta.env.VITE_GA_MEASUREMENT_ID) {
          console.warn('Missing required Google Analytics key: VITE_GA_MEASUREMENT_ID - Analytics disabled');
          // Set fallback analytics mode to prevent quota issues
          window.gtag = window.gtag || function() {
            console.debug('GA offline mode: event logged locally', arguments);
          };
          return;
        }
        
        // Validate measurement ID format
        const measurementId = import.meta.env.VITE_GA_MEASUREMENT_ID;
        if (!measurementId.match(/^G-[A-Z0-9]{10}$/)) {
          console.warn('Invalid GA measurement ID format - Analytics disabled');
          window.gtag = window.gtag || function() {
            console.debug('GA offline mode: invalid ID', arguments);
          };
          return;
        }
        
        await initGA();
        console.log('Google Analytics initialized successfully');
      } catch (error) {
        console.warn('GA initialization failed, using fallback mode:', error);
        // Provide fallback gtag function to prevent crashes
        window.gtag = window.gtag || function() {
          console.debug('GA fallback mode: event logged locally', arguments);
        };
        
        // Report GA initialization failure to Sentry if available
        if (window.Sentry?.captureException) {
          window.Sentry.captureException(error as Error, {
            tags: { component: 'GA_initialization' },
            extra: { measurementId: import.meta.env.VITE_GA_MEASUREMENT_ID }
          });
        }
      }
    };

    initializeGA();
  }, []);

  // Apply mobile layout dynamically
  useEffect(() => {
    if (mobileState.isMobile) {
      console.log('Mobile layout applied');
      document.body.classList.add('mobile-layout');
    } else {
      document.body.classList.remove('mobile-layout');
    }
    
    // Clean up orientation classes
    document.body.classList.remove('portrait', 'landscape');
    document.body.classList.add(mobileState.orientation);
  }, [mobileState.isMobile, mobileState.orientation]);

  // Enhanced session establishment with UI feedback
  useEffect(() => {
    const initializeApp = async () => {
      try {
        await sessionHook.establishSession();
        console.log('✅ Session established with UI feedback');
      } catch (error) {
        console.log('❌ Session establishment failed, user can retry via UI');
      }
    };

    initializeApp();
  }, []);

  // Conditional onboarding based on session state and localStorage
  useEffect(() => {
    if (sessionHook.isReady && sessionHook.sessionInfo) {
      const onboardingComplete = localStorage.getItem('onboarding-complete');
      const hasCompletedSetup = sessionHook.sessionInfo.user?.hasCompletedSetup;
      
      // Show onboarding if not completed or if localStorage flag is false
      if (!onboardingComplete || onboardingComplete === 'false' || !hasCompletedSetup) {
        setShowOnboarding(true);
      } else {
        setShowOnboarding(false);
      }
    } else if (!sessionHook.isEstablishing && !sessionHook.isReady) {
      // No session - don't show onboarding
      setShowOnboarding(false);
    }
  }, [sessionHook.isReady, sessionHook.sessionInfo, sessionHook.isEstablishing]);

  // Enhanced PWA Install Prompt Handler with session sync
  useEffect(() => {
    let deferredPrompt: any;
    const DISMISSAL_STORAGE_KEY = 'pwa-install-dismissed';
    const DISMISSAL_DURATION = 7 * 24 * 60 * 60 * 1000; // 7 days

    const handleBeforeInstallPrompt = (e: Event) => {
      e.preventDefault();
      deferredPrompt = e as any;
      
      // Check if already installed or recently dismissed
      if (isAlreadyInstalled() || isRecentlyDismissed()) {
        return;
      }
      
      showInstallPromotion();
    };

    const isAlreadyInstalled = () => {
      // Check if app is already installed (standalone mode)
      return window.matchMedia('(display-mode: standalone)').matches || 
             (window.navigator as any).standalone === true;
    };

    const isRecentlyDismissed = () => {
      // Check if PWA was dismissed recently (within 7 days dismissal cooldown)
      const dismissedTime = localStorage.getItem(DISMISSAL_STORAGE_KEY);
      if (!dismissedTime) return false;
      
      const now = Date.now();
      const dismissed = parseInt(dismissedTime, 10);
      return (now - dismissed) < DISMISSAL_DURATION; // 7 days cooldown active
    };

    const showInstallPromotion = () => {
      // Check if install button already exists
      if (document.getElementById('pwa-install-button')) return;
      
      const installButton = document.createElement('button');
      installButton.id = 'pwa-install-button';
      installButton.textContent = 'Install TheAgencyIQ';
      installButton.style.cssText = `
        position: fixed;
        top: 20px;
        right: 20px;
        z-index: 9999;
        background: #3250fa;
        color: white;
        border: none;
        padding: 12px 24px;
        border-radius: 8px;
        font-weight: 600;
        cursor: pointer;
        box-shadow: 0 4px 12px rgba(0,0,0,0.15);
      `;
      
      installButton.addEventListener('click', () => {
        if (deferredPrompt) {
          // Sync session before installation
          if (sessionHook.sessionInfo) {
            localStorage.setItem('pre-install-session', JSON.stringify(sessionHook.sessionInfo));
          }
          
          deferredPrompt.prompt();
          deferredPrompt.userChoice.then((choiceResult: any) => {
            if (choiceResult.outcome === 'accepted') {
              console.log('User accepted the install prompt');
            } else {
              console.log('User dismissed the install prompt');
              localStorage.setItem(DISMISSAL_STORAGE_KEY, Date.now().toString());
            }
            deferredPrompt = null;
            installButton.remove();
          });
        }
      });
      
      // Add dismiss button
      const dismissButton = document.createElement('button');
      dismissButton.textContent = '×';
      dismissButton.style.cssText = `
        position: absolute;
        top: 4px;
        right: 4px;
        background: transparent;
        color: white;
        border: none;
        font-size: 16px;
        cursor: pointer;
        width: 20px;
        height: 20px;
        display: flex;
        align-items: center;
        justify-content: center;
      `;
      
      dismissButton.addEventListener('click', () => {
        localStorage.setItem(DISMISSAL_STORAGE_KEY, Date.now().toString());
        installButton.remove();
      });
      
      installButton.appendChild(dismissButton);
      document.body.appendChild(installButton);
    };

    window.addEventListener('beforeinstallprompt', handleBeforeInstallPrompt);

    return () => {
      window.removeEventListener('beforeinstallprompt', handleBeforeInstallPrompt);
      const button = document.getElementById('pwa-install-button');
      if (button) button.remove();
    };
  }, [sessionHook.sessionInfo]);



  return (
    <div className="min-h-screen bg-background">
      <Router />
      <OnboardingWizard />
      <GrokWidget />
      <Toaster />
      <SessionLoadingSpinner
        isEstablishing={sessionHook.isEstablishing}
        isError={sessionHook.isError}
        error={sessionHook.error}
        onRetry={sessionHook.retrySession}
      />
    </div>
  );
}

function App() {
  // Initialize Google Analytics with comprehensive fallback error handling  
  useEffect(() => {
    const initializeGA = async () => {
      try {
        // Verify required environment variable is present
        if (!import.meta.env.VITE_GA_MEASUREMENT_ID) {
          console.warn('Missing required Google Analytics key: VITE_GA_MEASUREMENT_ID - Analytics disabled');
          // Set fallback analytics mode to prevent quota issues
          window.gtag = window.gtag || function() {
            console.debug('GA offline mode: event logged locally', arguments);
          };
          return;
        }
        
        // Validate measurement ID format
        const measurementId = import.meta.env.VITE_GA_MEASUREMENT_ID;
        if (!measurementId.match(/^G-[A-Z0-9]{10}$/)) {
          console.warn('Invalid GA measurement ID format - Analytics disabled');
          window.gtag = window.gtag || function() {
            console.debug('GA offline mode: invalid ID', arguments);
          };
          return;
        }
        
        await initGA();
        console.log('Google Analytics initialized successfully');
      } catch (error) {
        console.warn('GA initialization failed, using fallback mode:', error);
        // Provide fallback gtag function to prevent crashes
        window.gtag = window.gtag || function() {
          console.debug('GA fallback mode: event logged locally', arguments);
        };
        
        // Report GA initialization failure to Sentry if available
        if (window.Sentry?.captureException) {
          window.Sentry.captureException(error as Error, {
            tags: { component: 'GA_initialization' },
            extra: { measurementId: import.meta.env.VITE_GA_MEASUREMENT_ID }
          });
        }
      }
    };

    initializeGA();
  }, []);

  return (
    <QueryClientProvider client={queryClient}>
      <OptimizedTooltipProvider>
        <RouterErrorBoundary>
          <AppContent />
        </RouterErrorBoundary>
      </OptimizedTooltipProvider>
    </QueryClientProvider>
  );
}

export default App;
