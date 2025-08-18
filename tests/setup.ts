// Jest setup file
import { config } from 'dotenv';

// Load environment variables for testing
config({ path: '.env.test' });

// Global test setup
beforeAll(() => {
  // Mock console methods for cleaner test output
  jest.spyOn(console, 'log').mockImplementation(() => {});
  jest.spyOn(console, 'warn').mockImplementation(() => {});
  jest.spyOn(console, 'error').mockImplementation(() => {});
});

afterAll(() => {
  // Restore console methods
  jest.restoreAllMocks();
});