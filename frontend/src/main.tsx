import { StrictMode } from 'react';
import { createRoot } from 'react-dom/client';
import App from './App';
import ManualReviewPage from './pages/manual-review';
import { resumeManualReviewUrl } from './lib/manualReviewRoute';
import './styles.css';

// OAuth returns to the existing allowed root URL. Resume the review in this tab
// using only its stored scan ID; restoreSession removes the token fragment.
if (window.location.pathname === '/' && window.location.hash) {
  try {
    const pending = sessionStorage.getItem('aegis_pending_manual_scan');
    const resume = resumeManualReviewUrl(window.location.pathname, window.location.hash, pending);
    if (resume) {
      sessionStorage.removeItem('aegis_pending_manual_scan');
      window.history.replaceState(window.history.state, '', resume);
    }
  } catch { /* The regular dashboard sign-in can still complete. */ }
}

createRoot(document.getElementById('root')!).render(
  <StrictMode>{window.location.pathname === '/manual-review' ? <ManualReviewPage /> : <App />}</StrictMode>,
);
