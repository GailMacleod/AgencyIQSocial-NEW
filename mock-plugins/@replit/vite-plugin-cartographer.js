// Mock Replit cartographer plugin for development
export function cartographer() {
  return {
    name: 'mock-cartographer',
    configResolved() {
      // Mock implementation - do nothing
    }
  };
}

export default { cartographer };