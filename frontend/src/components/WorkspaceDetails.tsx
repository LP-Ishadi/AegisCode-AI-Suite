import { useEffect, useId, useRef, useState } from 'react';
import { ExternalLink, GitBranch, X } from 'lucide-react';
import type { MetricView } from './DashboardStats';
import { PRTable } from './PRTable';
import { securityScore, type DashboardData } from '../lib/dashboard';
import { loadRepositories, loadVulnerabilities, sampleFindings, type Repository, type Vulnerability } from '../lib/details';

type View = MetricView | 'repositories';
const titles: Record<View, string> = {
  repositories: 'Connected GitHub repositories', pullRequests: 'Pull request activity',
  findings: 'Vulnerability logs', score: 'Security score details',
};

export function WorkspaceDetails({ view, data, demo, onClose }: {
  view: View; data: DashboardData; demo: boolean; onClose: () => void;
}) {
  const dialog = useRef<HTMLDialogElement>(null);
  const titleId = useId();
  const [repositories, setRepositories] = useState<Repository[]>([]);
  const [findings, setFindings] = useState<Vulnerability[]>([]);
  const [loading, setLoading] = useState(view === 'repositories' || view === 'findings');
  const [error, setError] = useState('');
  const [attempt, setAttempt] = useState(0);
  const [query, setQuery] = useState('');
  const [severity, setSeverity] = useState('all');

  useEffect(() => {
    const element = dialog.current;
    const trigger = document.activeElement as HTMLElement | null;
    element?.showModal();
    const previousOverflow = document.body.style.overflow;
    document.body.style.overflow = 'hidden';
    return () => { element?.close(); document.body.style.overflow = previousOverflow; trigger?.focus(); };
  }, []);

  useEffect(() => {
    let active = true;
    setError('');
    if (view !== 'repositories' && view !== 'findings') { setLoading(false); return; }
    setLoading(true);
    async function load() {
      try {
        if (view === 'repositories') {
          const rows = demo ? [...new Set(data.pullRequests.map(pr => pr.repository))].map(name => ({ id: name, full_name: name, default_branch: 'main' })) : await loadRepositories();
          if (active) setRepositories(rows);
        } else {
          const rows = demo ? sampleFindings : await loadVulnerabilities();
          if (active) setFindings(rows);
        }
      } catch (err) { if (active) setError(err instanceof Error ? err.message : 'Unable to load details.'); }
      finally { if (active) setLoading(false); }
    }
    void load();
    return () => { active = false; };
  }, [view, demo, data.pullRequests, attempt]);

  const visibleFindings = findings.filter(f => (severity === 'all' || f.severity === severity)
    && `${f.rule_id} ${f.file_path} ${f.message}`.toLowerCase().includes(query.toLowerCase()));
  const score = securityScore(data);

  return <dialog ref={dialog} aria-labelledby={titleId} onCancel={onClose}
    className="m-auto max-h-[90dvh] w-[calc(100%-2rem)] max-w-5xl overflow-y-auto rounded-2xl border border-indigo-400/25 bg-slate-950 p-0 text-slate-100 shadow-2xl backdrop:bg-slate-950/80 backdrop:backdrop-blur-sm">
    <header className="sticky top-0 z-10 flex items-center justify-between gap-4 border-b border-indigo-400/15 bg-slate-950 p-5">
      <h2 id={titleId} className="text-lg font-semibold">{titles[view]}</h2>
      <button type="button" aria-label="Close details" onClick={onClose} className="rounded-lg p-2 text-slate-400 hover:bg-indigo-500/15 hover:text-white"><X size={20} /></button>
    </header>
    <div className="space-y-5 p-5 md:p-7">
      {demo && <p className="text-xs text-violet-300">Demo preview · illustrative records, not connected GitHub data.</p>}
      {loading && <p role="status" className="text-sm text-slate-400">Loading details…</p>}
      {error && <div role="alert" className="text-sm text-rose-300">{error}<button className="secondary-button ml-3" onClick={() => setAttempt(a => a + 1)}>Retry</button></div>}
      {view === 'repositories' && <>
        <div className="rounded-xl border border-indigo-400/20 bg-indigo-950/40 p-4">
          <p className="text-sm leading-6 text-slate-300">Manage repository access through your installed GitHub Apps. Signing in with GitHub does not connect repositories for scanning.</p>
          <a href="https://github.com/settings/installations" target="_blank" rel="noopener noreferrer" className="primary-button mt-3">Manage access on GitHub<ExternalLink size={14} /></a>
          <p className="mt-3 text-xs text-slate-400">In-app connection and disconnection will be available when the AegisCode GitHub App integration is enabled.</p>
        </div>
        <label className="block text-xs text-slate-400">Search repositories<input className="form-input" value={query} onChange={e => setQuery(e.target.value)} placeholder="Filter by repository name" /></label>
        {!loading && !error && <>
          <p className="text-xs text-slate-400">{demo ? 'Sample repositories from recent demo reviews' : 'Up to 100 repositories accessible to your account'}</p>
          {repositories.filter(r => r.full_name.toLowerCase().includes(query.toLowerCase())).map(repo => <article key={repo.id} className="panel flex flex-wrap items-center justify-between gap-3 p-4">
            <div className="min-w-0"><p className="flex items-center gap-2 break-all text-sm"><GitBranch size={16} className="shrink-0 text-violet-400" />{repo.full_name}</p><p className="mt-2 text-xs text-slate-400">Default branch: {repo.default_branch}</p></div>
            {!demo && /^[A-Za-z0-9_.-]+\/[A-Za-z0-9_.-]+$/.test(repo.full_name) && <a href={`https://github.com/${repo.full_name}`} target="_blank" rel="noopener noreferrer" className="secondary-button">Open repository<ExternalLink size={13} /></a>}
          </article>)}
          {!repositories.some(r => r.full_name.toLowerCase().includes(query.toLowerCase())) && <p className="py-6 text-sm text-slate-400">{repositories.length ? 'No repositories match your search.' : 'No connected repository records yet.'}</p>}
        </>}
      </>}
      {view === 'findings' && !loading && !error && <>
        <p className="text-xs text-slate-400">{demo ? 'Two sample log entries; overview metrics are illustrative.' : 'Latest 100 unresolved findings. Open an entry for its rule, location, and scan details.'}</p>
        <div className="flex flex-wrap gap-3"><label className="grow text-xs text-slate-400">Search logs<input className="form-input" value={query} onChange={e => setQuery(e.target.value)} placeholder="Rule, file path, or message" /></label><label className="text-xs text-slate-400">Severity<select className="form-input" value={severity} onChange={e => setSeverity(e.target.value)}>{['all', 'critical', 'high', 'medium', 'low', 'info'].map(s => <option key={s} value={s}>{s}</option>)}</select></label></div>
        {visibleFindings.map(finding => <details key={finding.id} className="panel p-4">
          <summary className="cursor-pointer text-sm"><span className="mr-3 rounded bg-violet-500/15 px-2 py-1 text-xs uppercase text-violet-200">{finding.severity}</span><span className="break-all">{finding.rule_id}</span><span className="mt-3 block break-all text-xs text-slate-400">{finding.file_path}:{finding.line}</span></summary>
          <p className="mt-4 whitespace-pre-wrap break-words text-sm leading-6 text-slate-300">{finding.message}</p>
          <dl className="mt-4 space-y-2 break-all text-xs text-slate-400"><div><dt className="inline font-medium text-slate-300">Scan: </dt><dd className="inline">{finding.scan_id}</dd></div><div><dt className="inline font-medium text-slate-300">Detected: </dt><dd className="inline">{new Date(finding.created_at).toLocaleString()}</dd></div><div><dt className="inline font-medium text-slate-300">Status: </dt><dd className="inline">Unresolved</dd></div></dl>
        </details>)}
        {!visibleFindings.length && <p className="py-6 text-sm text-slate-400">{findings.length ? 'No findings match these filters.' : 'No unresolved findings recorded. This does not confirm that every repository has been scanned.'}</p>}
      </>}
      {view === 'pullRequests' && <PRTable pullRequests={data.pullRequests} />}
      {view === 'score' && <>
        <p className="text-5xl font-semibold text-violet-300">{score === null ? '—' : `${score}%`}</p>
        <p className="text-sm leading-6 text-slate-300">{data.passedPRs} passed pull requests out of {data.reviewedPRs} completed reviews. Queued, scanning, and failed reviews are excluded from this calculation.</p>
        <p className="text-xs leading-6 text-slate-400">This score is a review pass rate, not a guarantee of security. No completed reviews means no score is available.</p>
        <PRTable pullRequests={data.pullRequests.filter(pr => pr.status === 'action_required')} />
      </>}
    </div>
  </dialog>;
}
