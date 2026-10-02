import { useState } from 'react';
import { WorkspaceDetails } from '../components/WorkspaceDetails';
import type { MetricView } from '../components/DashboardStats';
import { GitBranch, ArrowUpRight, ShieldCheck, Terminal } from 'lucide-react';
import { DashboardStats } from '../components/DashboardStats';
import { PRTable } from '../components/PRTable';
import type { DashboardData } from '../lib/dashboard';

export default function Dashboard({ data, demo }: { data: DashboardData; demo: boolean }) {
  const [view, setView] = useState<MetricView | 'repositories' | null>(null);
  return <div className="space-y-6">
    <div className="flex justify-end"><button className="secondary-button" aria-haspopup="dialog" onClick={() => setView('repositories')}><GitBranch size={16} />Manage GitHub repositories</button></div>
    <DashboardStats data={data} onSelect={setView} />
    {view && <WorkspaceDetails key={view} view={view} data={data} demo={demo} onClose={() => setView(null)} />}
    <div className="grid gap-4 lg:grid-cols-[1.65fr_1fr]">
      <section className="panel flex items-center gap-5 p-6"><span className="hidden rounded-2xl border border-indigo-300/10 bg-indigo-300/5 p-4 text-indigo-200 sm:block"><ShieldCheck size={29} strokeWidth={1.4} /></span><div><div className="mb-2 text-[10px] font-medium uppercase tracking-[0.18em] text-indigo-300">Security at every commit</div><h2 className="text-base font-medium">A second set of eyes for your code.</h2><p className="mt-2 max-w-lg text-xs leading-5 text-zinc-500">Static analysis finds risky patterns. AI adds context and explains the fix. Your team stays in control.</p></div></section>
      <section className="panel p-6"><div className="flex items-center justify-between"><h2 className="text-xs font-medium text-zinc-300">Review pipeline</h2><Terminal size={15} className="text-zinc-500" /></div><div className="mt-5 flex items-center gap-2 text-[10px] text-zinc-400"><span className="rounded border border-white/10 px-2 py-1.5">GitHub PR</span><ArrowUpRight size={12} /><span className="rounded border border-white/10 px-2 py-1.5">SAST</span><ArrowUpRight size={12} /><span className="rounded border border-indigo-300/15 bg-indigo-300/5 px-2 py-1.5 text-indigo-200">AI review</span></div><p className="mt-4 text-[10px] text-zinc-500">{demo ? 'Preview workflow · illustrative data' : 'Scanner and AI integrations await configuration'}</p></section>
    </div>
    <PRTable pullRequests={data.pullRequests} />
  </div>;
}
