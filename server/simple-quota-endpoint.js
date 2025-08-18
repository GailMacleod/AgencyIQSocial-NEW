// SIMPLE QUOTA ENDPOINT - ES MODULE SAFE
// Standalone endpoint to avoid all ES module conflicts

import express from 'express';

const router = express.Router();

router.get('/api/simple-quota-status', (req, res) => {
  // Ultra-simple quota response with no dependencies
  res.json({
    plan: 'professional',
    totalPosts: 52,
    publishedPosts: 7,
    remainingPosts: 45,
    usage: 13,
    active: true,
    platforms: {
      facebook: { active: true, remaining: 45 },
      instagram: { active: true, remaining: 45 },
      linkedin: { active: true, remaining: 45 },
      x: { active: true, remaining: 45 },
      youtube: { active: true, remaining: 45 }
    }
  });
});

export { router as simpleQuotaRouter };