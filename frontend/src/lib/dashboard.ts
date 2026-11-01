import { supabase } from './supabaseClient';
import { IMAGE_RULE_PATTERN } from './details';

export type ReviewStatus = 'passed' | 'action_required' | 'scanning' | 'queued' | 'failed';
export interface PullRequest {
  id: string; repository: string; number: number; title: string;
  author: string; status: ReviewStatus; riskTags: string[]; updatedAt: string; latestScanId?: string | null;
}
export interface DashboardData {
  totalPRs: number; activeVulnerabilities: number; repositoryCount: number;
  activeProjectFindings: number; activeImageFindings: number;
  passedPRs: number; reviewedPRs: number; pullRequests: PullRequest[];
}

export function securityScore(data: Pick<DashboardData, 'passedPRs' | 'reviewedPRs'>): number | null {
  return data.reviewedPRs > 0 ? Math.round(data.passedPRs / data.reviewedPRs * 100) : null;
}

export async function loadDashboard(): Promise<DashboardData> {
  if (!supabase) throw new Error('Add your public Supabase configuration to connect this workspace.');
  const [prs, repositories, projectFindings, imageFindings, passed, reviewed] = await Promise.all([
    supabase.from('pull_requests').select('id,number,title,author,status,risk_tags,updated_at,latest_scan_id,repositories(full_name)', { count: 'exact' }).order('updated_at', { ascending: false }).limit(50),
    supabase.from('repositories').select('id', { count: 'exact', head: true }),
    supabase.from('findings').select('id', { count: 'exact', head: true }).eq('resolved', false).not('rule_id', 'like', IMAGE_RULE_PATTERN),
    supabase.from('findings').select('id', { count: 'exact', head: true }).eq('resolved', false).like('rule_id', IMAGE_RULE_PATTERN),
    supabase.from('pull_requests').select('id', { count: 'exact', head: true }).eq('status', 'passed'),
    supabase.from('pull_requests').select('id', { count: 'exact', head: true }).in('status', ['passed', 'action_required']),
  ]);
  if ([prs, repositories, projectFindings, imageFindings, passed, reviewed].some(result => result.error)) {
    throw new Error('Unable to load cloud data. Check your connection, membership, and database migration.');
  }
  return {
    totalPRs: prs.count ?? 0, repositoryCount: repositories.count ?? 0,
    activeVulnerabilities: (projectFindings.count ?? 0) + (imageFindings.count ?? 0),
    activeProjectFindings: projectFindings.count ?? 0,
    activeImageFindings: imageFindings.count ?? 0,
    passedPRs: passed.count ?? 0, reviewedPRs: reviewed.count ?? 0,
    pullRequests: (prs.data ?? []).map(row => {
      // PostgREST infers relationship cardinality at runtime without generated DB types.
      const relation = row.repositories as unknown as { full_name: string } | { full_name: string }[] | null;
      const repository = Array.isArray(relation) ? relation[0]?.full_name : relation?.full_name;
      return {
        id: row.id, repository: repository ?? 'Unknown repository', number: row.number,
        title: row.title, author: row.author, status: row.status, riskTags: row.risk_tags,
        updatedAt: row.updated_at, latestScanId: row.latest_scan_id,
      };
    }),
  };
}
