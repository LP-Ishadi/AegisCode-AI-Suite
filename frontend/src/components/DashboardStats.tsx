import { ArrowUpRight, Bug, GitPullRequest, ShieldCheck } from 'lucide-react';
import { securityScore, type DashboardData } from '../lib/dashboard';

export type MetricView = 'pullRequests' | 'findings' | 'score';

export function DashboardStats({ data, onSelect }: { data: DashboardData; onSelect: (view: MetricView) => void }) {
  const score = securityScore(data);
  const cards = [
    { id: 'pullRequests' as const, label: 'Total pull requests', value: data.totalPRs.toLocaleString(), detail: 'Across connected repositories', icon: GitPullRequest, color: 'text-indigo-300' },
    { id: 'findings' as const, label: 'Active vulnerabilities', value: data.activeVulnerabilities.toLocaleString(), detail: 'Unresolved findings · all severities', icon: Bug, color: 'text-amber-300' },
    { id: 'score' as const, label: 'Security score', value: score === null ? '—' : `${score}%`, detail: 'Passed PRs / completed reviews', icon: ShieldCheck, color: 'text-indigo-300' },
  ];
  return <section aria-label="Workspace metrics" className="grid gap-4 md:grid-cols-3">
    {cards.map(({ id, label, value, detail, icon: Icon, color }) => <button type="button" key={label} onClick={() => onSelect(id)} aria-haspopup="dialog" className="panel relative overflow-hidden p-6 text-left transition-colors hover:border-violet-500/50 hover:bg-indigo-950">
      <div className="flex items-center justify-between text-sm text-zinc-400"><span>{label}</span><Icon size={18} className={color} /></div>
      <div className="mt-5 flex items-end justify-between"><strong className="text-4xl font-medium tracking-tight">{value}</strong><span className={`rounded-full bg-white/3 p-2 ${color}`}><ArrowUpRight size={18} /></span></div>
      <p className="mt-4 text-xs text-zinc-500">{detail}</p>
    </button>)}
  </section>;
}
