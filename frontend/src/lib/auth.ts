import type { SupabaseClient } from '@supabase/supabase-js';

// Await URL processing before reading the memory-only session. Never display
// provider error descriptions or log callback URLs, which can contain tokens.
export async function restoreSession(client: SupabaseClient) {
  const fragment = new URLSearchParams(window.location.hash.slice(1));
  const callback = ['access_token', 'refresh_token', 'error', 'error_description']
    .some(key => fragment.has(key));
  try {
    const initialized = await client.auth.initialize();
    if (initialized.error || fragment.has('error') || fragment.has('error_description')) {
      throw new Error('GitHub sign-in was cancelled or could not be completed. Please try again.');
    }
    const { data, error } = await client.auth.getSession();
    if (error) throw new Error('Unable to check your session. Please sign in again.');
    return data.session;
  } finally {
    if (callback) {
      window.history.replaceState(window.history.state, '', window.location.pathname + window.location.search);
    }
  }
}
