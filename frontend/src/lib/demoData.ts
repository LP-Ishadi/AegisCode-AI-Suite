import type { DashboardData } from './dashboard';

export const demoData: DashboardData = {
  totalPRs: 142, activeVulnerabilities: 7, repositoryCount: 6, passedPRs: 128, reviewedPRs: 136,
  pullRequests: [
    { id: '1', repository: 'acme/api-gateway', number: 284, title: 'Add organization-scoped API authentication', author: 'sarah-chen', status: 'action_required', riskTags: ['SQL injection', 'Auth bypass'], updatedAt: '2026-09-30T08:30:00Z' },
    { id: '2', repository: 'acme/web-platform', number: 192, title: 'Refactor workspace settings and permissions', author: 'alex-rivera', status: 'passed', riskTags: [], updatedAt: '2026-09-30T08:12:00Z' },
    { id: '3', repository: 'acme/payment-service', number: 87, title: 'Integrate subscription billing webhooks', author: 'james-wilson', status: 'action_required', riskTags: ['Hardcoded secret'], updatedAt: '2026-09-30T07:55:00Z' },
    { id: '4', repository: 'acme/api-gateway', number: 281, title: 'Optimize rate limiter for distributed requests', author: 'maya-patel', status: 'scanning', riskTags: [], updatedAt: '2026-09-30T07:40:00Z' },
    { id: '5', repository: 'acme/design-system', number: 56, title: 'Improve keyboard navigation in dialog components', author: 'alex-rivera', status: 'passed', riskTags: [], updatedAt: '2026-09-30T06:20:00Z' },
    { id: '6', repository: 'acme/web-platform', number: 189, title: 'Sanitize user-generated markdown previews', author: 'sarah-chen', status: 'passed', riskTags: [], updatedAt: '2026-09-29T16:40:00Z' },
  ],
};
