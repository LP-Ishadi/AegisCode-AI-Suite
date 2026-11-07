import { supabase } from './supabaseClient';

export interface Repository { id: string; full_name: string; default_branch: string }
export interface Vulnerability {
  id: string; rule_id: string; file_path: string; line: number; severity: string;
  message: string; resolved: boolean; created_at: string; scan_id: string;
}
export type FindingGroup = 'project' | 'image';
export const IMAGE_RULE_PATTERN = 'trivy.image.%';

export async function loadRepositories(): Promise<Repository[]> {
  if (!supabase) throw new Error('Supabase is not configured.');
  const { data, error } = await supabase.from('repositories')
    .select('id,full_name,default_branch').order('full_name').limit(100);
  if (error) throw new Error('Unable to load repositories. Please try again.');
  return data ?? [];
}

export async function loadVulnerabilities(group: FindingGroup): Promise<Vulnerability[]> {
  const client = supabase;
  if (!client) throw new Error('Supabase is not configured.');
  const levels = ['critical', 'high', 'medium', 'low', 'info'];
  const results = await Promise.all(levels.map(level => {
    const scoped = group === 'image'
      ? client.from('current_image_findings')
        .select('id,rule_id,file_path,line,severity,message,resolved,created_at,scan_id')
        .eq('severity', level)
      : client.from('findings')
        .select('id,rule_id,file_path,line,severity,message,resolved,created_at,scan_id')
        .eq('resolved', false).eq('severity', level)
        .not('rule_id', 'like', IMAGE_RULE_PATTERN);
    return scoped.order('created_at', { ascending: false }).limit(200);
  }));
  if (results.some(result => result.error)) throw new Error('Unable to load finding logs. Please try again.');
  return results.flatMap(result => result.data ?? []);
}

export function findingGroup(ruleId: string): FindingGroup {
  return ruleId.startsWith('trivy.image.') ? 'image' : 'project';
}

export function findingSource(ruleId: string): string {
  if (findingGroup(ruleId) === 'image') return 'Base image package';
  if (ruleId.startsWith('trivy.')) return 'Dependency package';
  if (ruleId.startsWith('semgrep.')) return 'Code pattern';
  if (ruleId.startsWith('trufflehog.')) return 'Possible secret';
  return 'Other finding';
}

export const sampleFindings: Vulnerability[] = [
  { id: 'demo-sql', rule_id: 'python.sql-injection', file_path: 'api/routes/organizations.py', line: 42, severity: 'high', message: 'User input is interpolated into a SQL query. Use parameterized queries and validate organization access before reading records.', resolved: false, created_at: '2026-09-30T08:30:00Z', scan_id: 'demo-scan-284' },
  { id: 'demo-secret', rule_id: 'generic.hardcoded-secret', file_path: 'billing/webhooks.ts', line: 18, severity: 'high', message: 'A credential-like literal was detected. Revoke any exposed credential and retrieve its replacement from a server-side secret manager. Secret value omitted.', resolved: false, created_at: '2026-09-30T07:55:00Z', scan_id: 'demo-scan-87' },
];
