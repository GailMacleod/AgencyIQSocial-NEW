// Mock Replit runtime error modal plugin for development
export default function runtimeErrorOverlay() {
  return {
    name: 'mock-runtime-error-overlay',
    configResolved() {
      // Mock implementation - do nothing
    }
  };
}