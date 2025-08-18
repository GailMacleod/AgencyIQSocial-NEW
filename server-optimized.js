const express = require('express');
const path = require('path');

const app = express();
const PORT = process.env.PORT || 5000;

// Memory-optimized static file serving
app.use(express.static('dist', { 
  maxAge: '1d',
  etag: true,
  lastModified: true
}));

// API routes passthrough for development
if (process.env.NODE_ENV !== 'production') {
  // In development, proxy API calls to the main server
  const { createProxyMiddleware } = require('http-proxy-middleware');
  app.use('/api', createProxyMiddleware({
    target: 'http://localhost:5000',
    changeOrigin: true,
    pathRewrite: {
      '^/api': '/api'
    }
  }));
}

// Fallback to serve index.html for SPA routing
app.get('*', (req, res) => {
  res.sendFile(path.join(__dirname, 'dist', 'index.html'));
});

app.listen(PORT, () => {
  console.log(`Optimized server running on port ${PORT}`);
  console.log(`Memory limit: ${process.memoryUsage().heapUsed / 1024 / 1024}MB`);
});

// Memory monitoring
setInterval(() => {
  const usage = process.memoryUsage();
  if (usage.heapUsed / 1024 / 1024 > 200) {
    console.warn(`High memory usage: ${usage.heapUsed / 1024 / 1024}MB`);
  }
}, 30000);