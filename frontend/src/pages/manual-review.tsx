import { useEffect, useState } from 'react';
import type { Session } from '@supabase/supabase-js';
import { ArrowLeft, ExternalLink, ShieldCheck } from 'lucide-react';
import { ManualReview } from '../components/ManualReview';
import { SignIn } from '../components/SignIn';
import { restoreSession } from '../lib/auth';
import { isScanId } from '../lib/manualReviewRoute';
import { supabase } from '../lib/supabaseClient';

export default function ManualReviewPage() {
  const scanId = new URLSearchParams(window.location.search).get('scan');
  const validScanId = isScanId(scanId);
  const [session, setSession] = useState<Session | null>(null);
  const [authLoading, setAuthLoading] = useState(validScanId && !!supabase);
  const [authError, setAuthError] = useState('');

  useEffect(() => {
    if (!validScanId || !supabase) return;
    let active = true;
    let revision = 0;
    const { data: listener } = supabase.auth.onAuthStateChange((_event, next) => {
      if (!active) return;
      revision++;
      setSession(next);
      if (next) setAuthError('');
    });
    const initialRevision = revision;
    void restoreSession(supabase).then(next => {
      if (active && revision === initialRevision) setSession(next);
    }).catch(() => {
      if (active) setAuthError('GitHub sign-in could not be completed. Please try again.');
    }).finally(() => {
      if (active) setAuthLoading(false);
    });
    return () => { active = false; listener.subscription.unsubscribe(); };
  }, []);

  return <div className="min-h-screen bg-[#080d20] text-zinc-100">
    <header className="border-b border-white/10">
      <div className="mx-auto flex max-w-5xl flex-wrap items-center justify-between gap-4 px-5 py-5 md:px-8">
        <div className="flex items-center gap-3"><ShieldCheck className="text-indigo-300" size={25} /><span className="text-lg font-semibold">AegisCode · Manual AI review</span></div>
        <a href="/" target="_blank" rel="noopener noreferrer" className="secondary-button"><ArrowLeft size={15} />Open dashboard<ExternalLink size={13} /></a>
      </div>
    </header>
    <main className="mx-auto max-w-5xl space-y-5 px-5 py-8 md:px-8">
      {!validScanId ? <p role="alert" className="panel p-6 text-sm text-rose-300">This review link has an invalid scan ID. Open it from a completed pull request on the dashboard.</p>
        : !supabase ? <p role="alert" className="panel p-6 text-sm text-rose-300">Supabase is not configured for manual reviews.</p>
          : authLoading ? <p role="status" className="text-sm text-zinc-400">Checking your session…</p>
            : !session ? <><p className="text-sm text-zinc-400">Sign in to this review window to continue. Sign-in tokens stay in this window’s memory.</p><SignIn callbackError={authError} pendingManualScanId={scanId!} /></>
              : <ManualReview scanId={scanId!} session={session} onClose={() => window.close()} onComplete={() => {}} />}
    </main>
  </div>;
}
