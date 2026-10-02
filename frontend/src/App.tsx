import { useCallback, useEffect, useRef, useState } from 'react';
import type { Session } from '@supabase/supabase-js';
import { Activity, ArrowUpRight, LayoutDashboard, RefreshCw } from 'lucide-react';
import { Navbar } from './components/Navbar';
import { SignIn } from './components/SignIn';
import Dashboard from './pages';
import Analytics from './pages/analytics';
import { demoMode, supabase } from './lib/supabaseClient';
import { loadDashboard, type DashboardData } from './lib/dashboard';
import { demoData } from './lib/demoData';
import { restoreSession } from './lib/auth';

const emptyData: DashboardData = { totalPRs: 0, activeVulnerabilities: 0, repositoryCount: 0, passedPRs: 0, reviewedPRs: 0, pullRequests: [] };

export default function App() {
  const [page, setPage] = useState<'overview' | 'analytics'>('overview');
  const [session, setSession] = useState<Session | null>(null);
  const [authLoading, setAuthLoading] = useState(!demoMode && !!supabase);
  const [authError, setAuthError] = useState('');
  const [data, setData] = useState(demoMode ? demoData : emptyData);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState('');
  const generation = useRef(0);

  const refresh = useCallback(async () => {
    if (demoMode) return;
    const current = ++generation.current;
    setLoading(true); setError('');
    try {
      const result = await loadDashboard();
      if (current === generation.current) setData(result);
    } catch (err) {
      if (current === generation.current) setError(err instanceof Error ? err.message : 'Unable to load data.');
    } finally { if (current === generation.current) setLoading(false); }
  }, []);

  useEffect(() => {
    if (demoMode || !supabase) return;
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

  useEffect(() => {
    if (demoMode) return;
    if (session) { void refresh(); }
    else { ++generation.current; setData(emptyData); setError(''); setLoading(false); }
    return () => { ++generation.current; };
  }, [session, refresh]);

  async function signOut() {
    try {
      const result = await supabase?.auth.signOut({ scope: 'local' });
      if (result?.error) throw result.error;
      setSession(null);
    } catch { setError('Sign-out failed. Refresh this page to clear the in-memory session.'); }
  }

  return <div className="min-h-screen bg-[#080d20] text-zinc-100">
    <a href="#main" className="sr-only focus:not-sr-only focus:absolute focus:z-50 focus:bg-indigo-200 focus:p-3 focus:text-black">Skip to content</a>
    <Navbar repositories={data.repositoryCount} demo={demoMode} email={session?.user.email} onSignOut={() => void signOut()} />
    <div className="border-b border-white/7"><nav aria-label="Main navigation" className="mx-auto flex max-w-[1440px] gap-7 px-5 md:px-10">{([{ id: 'overview', label: 'Overview', icon: LayoutDashboard }, { id: 'analytics', label: 'Analytics', icon: Activity }] as const).map(({ id, label, icon: Icon }) => <button key={id} onClick={() => setPage(id)} aria-current={page === id ? 'page' : undefined} className={`flex items-center gap-2 border-b-2 py-4 text-xs transition-colors ${page === id ? 'border-indigo-300 text-indigo-200' : 'border-transparent text-zinc-500 hover:text-zinc-200'}`}><Icon size={15} />{label}</button>)}<span className="ml-auto hidden items-center text-[10px] text-zinc-500 sm:flex">{demoMode ? 'Demo workspace' : 'Cloud workspace'}</span></nav></div>
    <main id="main" className="mx-auto max-w-[1440px] px-5 pb-10 pt-8 md:px-10">
      {authLoading ? <p role="status" className="py-16 text-center text-sm text-zinc-400">Checking your session…</p> : !demoMode && !session ? <SignIn callbackError={authError} /> : <>
        <div className="mb-7 flex flex-wrap items-start justify-between gap-4"><div><p className="mb-2 text-[10px] font-medium uppercase tracking-[0.2em] text-zinc-500">Workspace / {page}</p><h1 className="text-[28px] font-semibold tracking-tight">{page === 'overview' ? 'Security overview' : 'Review analytics'}</h1><p className="mt-2 text-sm text-zinc-500">A clear view of your code. Confidence in every merge.</p></div><div className="flex items-center gap-3 pt-3"><span className="rounded-md border border-white/10 px-3 py-2 text-xs text-zinc-400">All time</span>{!demoMode && <button onClick={() => void refresh()} disabled={loading} className="secondary-button"><RefreshCw size={14} className={loading ? 'animate-spin' : ''} />Refresh</button>}<button className="primary-button" onClick={() => setPage(page === 'overview' ? 'analytics' : 'overview')}>{page === 'overview' ? 'View analytics' : 'View overview'}<ArrowUpRight size={14} /></button></div></div>
        {demoMode && <div className="mb-6 flex items-center gap-2 rounded-lg border border-indigo-300/10 bg-indigo-300/4 px-4 py-3 text-xs text-indigo-200/70"><span className="size-1.5 shrink-0 rounded-full bg-indigo-300" />Demo workspace — sample reviews and metrics. No repositories are connected.</div>}
        {error && <div role="alert" className="mb-5 rounded-lg border border-rose-300/20 bg-rose-300/5 p-4 text-sm text-rose-200">{error}</div>}
        {loading && <p role="status" className="mb-4 text-xs text-zinc-400">Loading your cloud workspace…</p>}
        {page === 'overview' ? <Dashboard data={data} demo={demoMode} /> : <Analytics data={data} />}
        <footer className="mt-7 flex flex-wrap justify-between gap-3 text-[10px] text-zinc-600"><span>AegisCode AI Suite · Secure code starts here</span><span>{demoMode ? 'Sample data · Foundation preview' : 'Supabase cloud · Session in memory'}</span></footer>
      </>}
    </main>
  </div>;
}
