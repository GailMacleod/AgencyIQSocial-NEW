/**
 * Dynamic Mobile Detection Hook
 * Addresses user's concern about static mobile detection
 */

import { useState, useEffect } from 'react';

interface MobileDetectionState {
  isMobile: boolean;
  isTablet: boolean;
  isDesktop: boolean;
  orientation: 'portrait' | 'landscape';
  screenWidth: number;
  screenHeight: number;
}

export function useMobileDetection(): MobileDetectionState {
  const [state, setState] = useState<MobileDetectionState>(() => {
    // Initial state with safe defaults
    if (typeof window === 'undefined') {
      return {
        isMobile: false,
        isTablet: false,
        isDesktop: true,
        orientation: 'landscape',
        screenWidth: 1024,
        screenHeight: 768
      };
    }

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
  });

  useEffect(() => {
    if (typeof window === 'undefined') return;

    let timeoutId: ReturnType<typeof setTimeout>;

    const updateState = () => {
      const width = window.innerWidth;
      const height = window.innerHeight;
      
      setState({
        isMobile: width < 768,
        isTablet: width >= 768 && width < 1024,
        isDesktop: width >= 1024,
        orientation: width > height ? 'landscape' : 'portrait',
        screenWidth: width,
        screenHeight: height
      });
    };

    // Debounced resize handler to prevent excessive updates
    const handleResize = () => {
      clearTimeout(timeoutId);
      timeoutId = setTimeout(updateState, 100);
    };

    // Handle orientation change with immediate update
    const handleOrientationChange = () => {
      // Small delay to allow for screen dimension updates
      setTimeout(updateState, 100);
    };

    // Add event listeners
    window.addEventListener('resize', handleResize);
    
    // Handle orientation change for mobile devices
    if ('orientation' in window) {
      window.addEventListener('orientationchange', handleOrientationChange);
    }
    
    // Fallback for older browsers or screen API
    if (window.screen && typeof (window.screen as any).addEventListener === 'function') {
      try {
        (window.screen as any).addEventListener('orientationchange', handleOrientationChange);
      } catch (error) {
        console.warn('Screen orientation API not available:', error);
      }
    }

    // Cleanup function
    return () => {
      clearTimeout(timeoutId);
      window.removeEventListener('resize', handleResize);
      
      if ('orientation' in window) {
        window.removeEventListener('orientationchange', handleOrientationChange);
      }
      
      if (window.screen && typeof (window.screen as any).removeEventListener === 'function') {
        try {
          (window.screen as any).removeEventListener('orientationchange', handleOrientationChange);
        } catch (error) {
          console.warn('Error removing screen orientation listener:', error);
        }
      }
    };
  }, []);

  return state;
}