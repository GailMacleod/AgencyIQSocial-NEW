import { describe, it, expect, beforeAll, afterAll } from '@jest/globals';
import request from 'supertest';
import { app } from '../../server/index';

describe('OAuth Integration Tests', () => {
  let server: any;

  beforeAll(async () => {
    server = app.listen(0); // Use random port for testing
  });

  afterAll(async () => {
    if (server) {
      server.close();
    }
  });

  describe('OAuth Status Endpoints', () => {
    it('should return OAuth status', async () => {
      const response = await request(app)
        .get('/api/oauth/status')
        .expect(200);

      expect(response.body).toHaveProperty('platforms');
      expect(Array.isArray(response.body.platforms)).toBe(true);
    });

    it('should handle platform connections', async () => {
      const response = await request(app)
        .get('/api/platform-connections')
        .expect(200);

      expect(response.body).toHaveProperty('connections');
      expect(Array.isArray(response.body.connections)).toBe(true);
    });
  });

  describe('OAuth Refresh Endpoints', () => {
    it('should validate X platform refresh', async () => {
      const response = await request(app)
        .post('/api/oauth/refresh/x')
        .expect(200);

      expect(response.body).toHaveProperty('success');
      expect(response.body).toHaveProperty('platform');
      expect(response.body.platform).toBe('x');
    });

    it('should handle invalid platform refresh', async () => {
      const response = await request(app)
        .post('/api/oauth/refresh/invalid')
        .expect(400);

      expect(response.body).toHaveProperty('error');
    });
  });

  describe('Health Check', () => {
    it('should return health status', async () => {
      const response = await request(app)
        .get('/api/health')
        .expect(200);

      expect(response.body).toHaveProperty('status');
      expect(response.body.status).toBe('ok');
    });
  });
});