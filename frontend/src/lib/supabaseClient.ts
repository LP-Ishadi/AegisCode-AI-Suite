import { createClient } from '@supabase/supabase-js';

const url = import.meta.env.VITE_SUPABASE_URL;
const key = import.meta.env.VITE_SUPABASE_ANON_KEY;

// No localStorage, sessionStorage, IndexedDB, cookie persistence, or offline cache.
// Auth tokens live in SDK memory only; refreshing the page requires signing in again.
export const supabase = url && key
  ? createClient(url, key, {
      // Implicit flow needs no stored PKCE verifier across the GitHub redirect.
      auth: { persistSession: false, autoRefreshToken: true, detectSessionInUrl: true, flowType: 'implicit' },
    })
  : null;

export const demoMode = import.meta.env.VITE_DEMO_MODE === 'true'
  || (import.meta.env.VITE_DEMO_MODE !== 'false' && !supabase);
