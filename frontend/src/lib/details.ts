import { supabase } from './supabaseClient';

export interface Repository { id: string; full_name: string; default_branch: string }
export interface Vulnerability {
  id: string; rule_id: string; file_path: string; line: number; severity: string;
  message: string; resolved: boolean; created_at: string; scan_id: string;
}

export async function loadRepositories(): Promise<Repository[]> {
  if (!supabase) throw new Error('Supabase is not configured.');
  const { data, error } = await supabase.from('repositories')
    .select('id,full_name,default_branch').order('full_name').limit(100);
  if (error) throw new Error('Unable to load repositories. Please try again.');
  return data ?? [];
}

export async function loadVulnerabilities(): Promise<Vulnerability[]> {
  if (!supabase) throw new Error('Supabase is not configured.');
  const { data, error } = await supabase.from('findings')
    .select('id,rule_id,file_path,line,severity,message,resolved,created_at,scan_id')
    .eq('resolved', false).order('created_at', { ascending: false }).limit(100);
  if (error) throw new Error('Unable to load vulnerability logs. Please try again.');
  return data ?? [];
}

export const sampleFindings: Vulnerability[] = [
  { id: 'demo-sql', rule_id: 'python.sql-injection', file_path: 'api/routes/organizations.py', line: 42, severity: 'high', message: 'User input is interpolated into a SQL query. Use parameterized queries and validate organization access before reading records.', resolved: false, created_at: '2026-09-30T08:30:00Z', scan_id: 'demo-scan-284' },
  { id: 'demo-secret', rule_id: 'generic.hardcoded-secret', file_path: 'billing/webhooks.ts', line: 18, severity: 'high', message: 'A credential-like literal was detected. Revoke any exposed credential and retrieve its replacement from a server-side secret manager. Secret value omitted.', resolved: false, created_at: '2026-09-30T07:55:00Z', scan_id: 'demo-scan-87' },
];
