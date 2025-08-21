// client/src/main.tsx
import { createRoot } from 'react-dom/client';
import App from './App';
import './index.css';

// Initialize Sentry **shim** (no SDK or cost). This is safe even if the file doesn’t exist yet.
import '@/lib/sentry-config';

const rootEl = document.getElementById('root');
if (!rootEl) {
  throw new Error('Root element not found');
}

createRoot(rootEl).render(<App />);

