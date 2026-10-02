import { afterEach, describe, expect, it, vi } from 'vitest';
import type { SupabaseClient } from '@supabase/supabase-js';
import { restoreSession } from './auth';

function setup(hash = '') {
  const replaceState = vi.fn();
  vi.stubGlobal('window', {
    location: { hash, pathname: '/', search: '' },
    history: { state: null, replaceState },
  });
  const initialize = vi.fn().mockResolvedValue({ error: null });
  const getSession = vi.fn().mockResolvedValue({ data: { session: null }, error: null });
  const client = { auth: { initialize, getSession } } as unknown as SupabaseClient;
  return { client, initialize, getSession, replaceState };
}

afterEach(() => vi.unstubAllGlobals());

describe('OAuth session restoration', () => {
  it('awaits callback initialization before loading the session and clears the fragment', async () => {
    const { client, initialize, getSession, replaceState } = setup('#access_token=test&refresh_token=test');
    const session = { user: { id: 'user-id' } };
    getSession.mockResolvedValue({ data: { session }, error: null });
    expect(await restoreSession(client)).toEqual(session);
    expect(initialize.mock.invocationCallOrder[0]).toBeLessThan(getSession.mock.invocationCallOrder[0]);
    expect(replaceState).toHaveBeenCalledWith(null, '', '/');
  });
  it('handles a cancelled callback without exposing the provider description', async () => {
    const { client, getSession, replaceState } = setup('#error=access_denied&error_description=private-details');
    await expect(restoreSession(client)).rejects.toThrow('cancelled');
    expect(getSession).not.toHaveBeenCalled();
    expect(replaceState).toHaveBeenCalled();
  });
  it('clears callback tokens even when initialization fails', async () => {
    const { client, initialize, replaceState } = setup('#access_token=invalid');
    initialize.mockResolvedValue({ error: new Error('invalid') });
    await expect(restoreSession(client)).rejects.toThrow();
    expect(replaceState).toHaveBeenCalled();
  });
  it('preserves normal navigation fragments when no session exists', async () => {
    const { client, replaceState } = setup('#overview');
    expect(await restoreSession(client)).toBeNull();
    expect(replaceState).not.toHaveBeenCalled();
  });
});
