import { Check, CircleAlert, GitPullRequest, LoaderCircle, Search, X } from 'lucide-react';
import { useState } from 'react';
import type { PullRequest, ReviewStatus } from '../lib/dashboard';

const statuses: Record<ReviewStatus, { label: string; className: string }> = {
  passed: { label: 'Passed', className: 'bg-indigo-400/8 text-indigo-300 border-indigo-400/15' },
  action_required: { label: 'Action required', className: 'bg-amber-400/8 text-amber-200 border-amber-400/15' },
  scanning: { label: 'Scanning', className: 'bg-sky-400/8 text-sky-300 border-sky-400/15' },
  queued: { label: 'Queued', className: 'bg-zinc-400/8 text-zinc-300 border-zinc-400/15' },
  failed: { label: 'Scan failed', className: 'bg-rose-400/8 text-rose-300 border-rose-400/15' },
};

export function PRTable({ pullRequests }: { pullRequests: PullRequest[] }) {
  const [query, setQuery] = useState('');
  const [filter, setFilter] = useState('all');
  const filtered = pullRequests.filter(pr => (filter === 'all' || pr.status === filter)
    && `${pr.repository} ${pr.title} ${pr.author} ${pr.number}`.toLowerCase().includes(query.toLowerCase()));
  return <section className="panel overflow-hidden" aria-labelledby="pr-heading">
    <div className="flex flex-wrap items-center justify-between gap-4 border-b border-white/7 p-5 md:px-6">
      <div><h2 id="pr-heading" className="text-sm font-semibold">Recent pull requests <span className="ml-2 rounded bg-white/5 px-2 py-0.5 text-xs text-zinc-400">{pullRequests.length}</span></h2><p className="mt-1.5 text-xs text-zinc-500">Latest 50 pull requests across your accessible repositories.</p></div>
      <div className="flex w-full flex-wrap items-center gap-2 sm:w-auto">
        <label className="flex items-center gap-2 rounded-lg border border-white/10 bg-black/15 px-3 py-2 text-zinc-500"><Search size={14} /><input className="w-36 bg-transparent text-xs text-zinc-200 outline-none" aria-label="Search pull requests" placeholder="Search pull requests…" value={query} onChange={e => setQuery(e.target.value)} />{query && <button aria-label="Clear search" onClick={() => setQuery('')}><X size={13} /></button>}</label>
        <select aria-label="Filter by review status" className="rounded-lg border border-white/10 bg-[#111a35] px-3 py-2 text-xs text-zinc-300" value={filter} onChange={e => setFilter(e.target.value)}><option value="all">All statuses</option>{Object.entries(statuses).map(([key, status]) => <option key={key} value={key}>{status.label}</option>)}</select>
      </div>
    </div>
    <div className="overflow-x-auto"><table className="w-full min-w-[850px] text-left text-xs">
      <thead className="border-b border-white/7 bg-white/2 text-[10px] uppercase tracking-wider text-zinc-500"><tr>{['Pull request', 'Review status', 'Security findings', 'Updated'].map(h => <th key={h} className="px-6 py-3.5 font-medium">{h}</th>)}</tr></thead>
      <tbody>{filtered.map(pr => <tr key={pr.id} className="border-b border-white/5 transition-colors last:border-0 hover:bg-white/2">
        <td className="px-6 py-5"><div className="flex gap-3"><GitPullRequest size={17} className="mt-0.5 shrink-0 text-zinc-500" /><div><p className="max-w-[380px] font-medium text-zinc-200">{pr.title}</p><p className="mt-2 text-[11px] text-zinc-500"><span className="text-zinc-400">{pr.repository}</span> <span className="px-1">·</span> #{pr.number} <span className="px-1">·</span> {pr.author}</p></div></div></td>
        <td className="px-6 py-5"><span className={`inline-flex items-center gap-1.5 whitespace-nowrap rounded-md border px-2 py-1 text-[10px] ${statuses[pr.status].className}`}>{pr.status === 'passed' ? <Check size={12} /> : pr.status === 'scanning' ? <LoaderCircle size={12} className="animate-spin motion-reduce:animate-none" /> : <CircleAlert size={12} />}{statuses[pr.status].label}</span></td>
        <td className="px-6 py-5"><div className="flex flex-wrap gap-1.5">{pr.riskTags.length ? pr.riskTags.map(tag => <span key={tag} className="whitespace-nowrap rounded border border-rose-300/10 bg-rose-300/5 px-2 py-1 text-[10px] text-rose-200/80">{tag}</span>) : <span className="text-zinc-500">{pr.status === 'passed' ? 'No findings' : '—'}</span>}</div></td>
        <td className="whitespace-nowrap px-6 py-5 text-[11px] text-zinc-500"><time dateTime={pr.updatedAt}>{new Date(pr.updatedAt).toLocaleDateString(undefined, { month: 'short', day: 'numeric' })}</time></td>
      </tr>)}</tbody>
    </table></div>
    {filtered.length === 0 && <p className="px-6 py-12 text-center text-sm text-zinc-500">{pullRequests.length ? 'No pull requests match these filters.' : 'No pull requests yet. Connected reviews will appear here.'}</p>}
    <div className="border-t border-white/7 px-6 py-3 text-[11px] text-zinc-500">Showing {filtered.length} of {pullRequests.length} recent pull requests</div>
  </section>;
}
