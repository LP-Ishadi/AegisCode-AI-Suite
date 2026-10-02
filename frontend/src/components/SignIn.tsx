import { useRef, useState } from 'react';
import { Github, LoaderCircle, ShieldCheck } from 'lucide-react';
import { supabase } from '../lib/supabaseClient';

export function SignIn({ callbackError = '' }: { callbackError?: string }) {
  const [error, setError] = useState('');
  const [busy, setBusy] = useState(false);
  const pending = useRef(false);

  async function signIn() {
    if (!supabase || pending.current) return;
    pending.current = true;
    setBusy(true);
    setError('');
    try {
      const { error } = await supabase.auth.signInWithOAuth({
        provider: 'github',
        options: { redirectTo: `${window.location.origin}/` },
      });
      if (error) throw error;
      // Keep the button disabled while the browser navigates to GitHub.
    } catch {
      setError('Unable to start GitHub sign-in. Please try again.');
      pending.current = false;
      setBusy(false);
    }
  }

  return <section className="panel mx-auto mt-16 max-w-md p-8" aria-labelledby="sign-in-heading">
    <span className="inline-flex rounded-xl border border-indigo-300/20 bg-indigo-300/10 p-3 text-indigo-200"><ShieldCheck size={26} aria-hidden="true" /></span>
    <h1 id="sign-in-heading" className="mt-5 text-2xl font-semibold tracking-tight">Welcome to AegisCode</h1>
    <p className="mt-3 text-sm leading-6 text-zinc-400">Sign in with GitHub to access your team’s code reviews and security insights.</p>
    {!supabase && <p role="alert" className="mt-5 text-sm text-amber-200">Public Supabase configuration is missing.</p>}
    {(error || (!busy && callbackError)) && <p role="alert" className="mt-5 text-sm text-rose-300">{error || callbackError}</p>}
    <button type="button" onClick={() => void signIn()} disabled={busy || !supabase} aria-busy={busy}
      className="mt-7 inline-flex w-full items-center justify-center gap-3 rounded-lg border border-white/15 bg-zinc-100 px-4 py-3 text-sm font-semibold text-zinc-950 transition-colors hover:bg-white disabled:opacity-50">
      {busy ? <LoaderCircle size={20} className="animate-spin motion-reduce:animate-none" aria-hidden="true" /> : <Github size={20} aria-hidden="true" />}
      {busy ? 'Redirecting to GitHub…' : 'Sign in with GitHub'}
    </button>
    <p className="mt-5 text-xs leading-5 text-zinc-500">Your session stays in memory and ends on page refresh. Ask your administrator for workspace access.</p>
  </section>;
}
