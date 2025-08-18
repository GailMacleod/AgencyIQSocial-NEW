/**
 * Responsive Mobile Detection with Orientation Change Handling
 * Provides comprehensive mobile detection and responsive behavior
 */

export interface MobileDetectionState {
  isMobile: boolean;
  isTablet: boolean;
  isDesktop: boolean;
  orientation: 'portrait' | 'landscape';
  screenWidth: number;
  screenHeight: number;
}

class MobileDetectionManager {
  private listeners: Set<(state: MobileDetectionState) => void> = new Set();
  private currentState: MobileDetectionState;
  private resizeHandler?: () => void;
  private orientationHandler?: () => void;

  constructor() {
    this.currentState = this.calculateState();
    this.setupEventListeners();
  }

  private calculateState(): MobileDetectionState {
    const width = window.innerWidth;
    const height = window.innerHeight;
    
    return {
      isMobile: width < 768,
      isTablet: width >= 768 && width < 1024,
      isDesktop: width >= 1024,
      orientation: width > height ? 'landscape' : 'portrait',
      screenWidth: width,
      screenHeight: height
    };
  }

  private setupEventListeners() {
    // Debounced resize handler to prevent excessive calls
    let resizeTimeout: NodeJS.Timeout;
    this.resizeHandler = () => {
      clearTimeout(resizeTimeout);
      resizeTimeout = setTimeout(() => {
        const newState = this.calculateState();
        const hasChanged = this.hasStateChanged(this.currentState, newState);
        
        if (hasChanged) {
          console.log('Mobile state changed:', {
            from: this.currentState,
            to: newState
          });
          
          this.currentState = newState;
          this.notifyListeners(newState);
        }
      }, 100); // 100ms debounce
    };

    // Orientation change handler
    this.orientationHandler = () => {
      // Small delay to ensure screen dimensions have updated
      setTimeout(() => {
        const newState = this.calculateState();
        if (this.hasStateChanged(this.currentState, newState)) {
          console.log('Orientation changed:', newState.orientation);
          this.currentState = newState;
          this.notifyListeners(newState);
        }
      }, 200);
    };

    // Add event listeners
    window.addEventListener('resize', this.resizeHandler);
    window.addEventListener('orientationchange', this.orientationHandler);
    
    // Fallback for devices that don't support orientationchange  
    // Note: screen.addEventListener is not standard, using alternative approach
    if ('orientation' in screen && 'addEventListener' in screen) {
      (screen as any).addEventListener('orientationchange', this.orientationHandler);
    }
  }

  private hasStateChanged(oldState: MobileDetectionState, newState: MobileDetectionState): boolean {
    return (
      oldState.isMobile !== newState.isMobile ||
      oldState.isTablet !== newState.isTablet ||
      oldState.isDesktop !== newState.isDesktop ||
      oldState.orientation !== newState.orientation ||
      Math.abs(oldState.screenWidth - newState.screenWidth) > 50 // Significant width change
    );
  }

  private notifyListeners(state: MobileDetectionState) {
    this.listeners.forEach(listener => {
      try {
        listener(state);
      } catch (error) {
        const errorObj = error instanceof Error ? error : new Error(String(error));
        console.error('Mobile detection listener error:', errorObj);
        if (window.Sentry) {
          window.Sentry.captureException(errorObj, {
            tags: { component: 'MobileDetectionManager' }
          });
        }
      }
    });
  }

  public subscribe(listener: (state: MobileDetectionState) => void): () => void {
    this.listeners.add(listener);
    
    // Immediately call with current state
    listener(this.currentState);
    
    // Return unsubscribe function
    return () => {
      this.listeners.delete(listener);
    };
  }

  public getCurrentState(): MobileDetectionState {
    return { ...this.currentState };
  }

  public isMobile(): boolean {
    return this.currentState.isMobile;
  }

  public isTablet(): boolean {
    return this.currentState.isTablet;
  }

  public isDesktop(): boolean {
    return this.currentState.isDesktop;
  }

  public getOrientation(): 'portrait' | 'landscape' {
    return this.currentState.orientation;
  }

  public cleanup() {
    if (this.resizeHandler) {
      window.removeEventListener('resize', this.resizeHandler);
    }
    if (this.orientationHandler) {
      window.removeEventListener('orientationchange', this.orientationHandler);
      if ('orientation' in screen && 'removeEventListener' in screen) {
        (screen as any).removeEventListener('orientationchange', this.orientationHandler);
      }
    }
    this.listeners.clear();
  }
}

// Export singleton instance
export const mobileDetection = new MobileDetectionManager();

// Legacy exports for backward compatibility
export const isMobile = () => mobileDetection.isMobile();
export const isTablet = () => mobileDetection.isTablet();
export const isDesktop = () => mobileDetection.isDesktop();

// React hook for mobile detection
export function useMobileDetection() {
  const [state, setState] = useState<MobileDetectionState>(
    mobileDetection.getCurrentState()
  );

  useEffect(() => {
    const unsubscribe = mobileDetection.subscribe(setState);
    return unsubscribe;
  }, []);

  return state;
}

// Utility functions
export const getBreakpoint = (width: number): 'mobile' | 'tablet' | 'desktop' => {
  if (width < 768) return 'mobile';
  if (width < 1024) return 'tablet';
  return 'desktop';
};

export const isLandscape = () => mobileDetection.getOrientation() === 'landscape';
export const isPortrait = () => mobileDetection.getOrientation() === 'portrait';

// CSS class helper
export const getResponsiveClasses = (state: MobileDetectionState): string => {
  const classes = [];
  
  if (state.isMobile) classes.push('mobile');
  if (state.isTablet) classes.push('tablet');
  if (state.isDesktop) classes.push('desktop');
  classes.push(state.orientation);
  
  return classes.join(' ');
};

import { useState, useEffect } from 'react';

declare global {
  interface Window {
    Sentry?: {
      captureException: (error: Error, context?: any) => void;
    };
  }
}