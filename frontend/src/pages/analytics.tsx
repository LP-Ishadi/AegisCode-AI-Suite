import type { DashboardData, ReviewStatus } from '../lib/dashboard';

export default function Analytics({ data }: { data: DashboardData }) {
  const labels: Record<ReviewStatus, string> = { passed: 'Passed', action_required: 'Action required', scanning: 'Scanning', queued: 'Queued', failed: 'Failed' };
  return <section className="panel p-7"><h2 className="text-lg font-medium">Review outcomes</h2><p className="mt-2 text-sm text-zinc-500">Distribution in the latest {data.pullRequests.length} pull requests. This is a recent sample, not an all-time trend.</p><div className="mt-8 max-w-3xl space-y-6">{Object.entries(labels).map(([status, label]) => {
    const count = data.pullRequests.filter(pr => pr.status === status).length;
    const percentage = data.pullRequests.length ? count / data.pullRequests.length * 100 : 0;
    return <div key={status}><div className="mb-2 flex justify-between text-xs"><span className="text-zinc-400">{label}</span><span>{count}</span></div><div role="meter" aria-label={label} aria-valuenow={count} aria-valuemin={0} aria-valuemax={data.pullRequests.length || 1} className="h-2 overflow-hidden rounded-full bg-white/5"><div className={`h-full rounded-full ${status === 'action_required' || status === 'failed' ? 'bg-amber-300/70' : 'bg-indigo-300/70'}`} style={{ width: `${percentage}%` }} /></div></div>;
  })}</div></section>;
}
