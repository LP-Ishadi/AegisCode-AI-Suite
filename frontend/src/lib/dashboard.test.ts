import { describe, expect, it } from 'vitest';
import { securityScore } from './dashboard';

describe('security score', () => {
  it('does not report perfect security when no reviews have completed', () => {
    expect(securityScore({ passedPRs: 0, reviewedPRs: 0 })).toBeNull();
  });
  it('uses completed reviews as the denominator', () => {
    expect(securityScore({ passedPRs: 128, reviewedPRs: 136 })).toBe(94);
  });
  it('reports zero when every completed review requires action', () => {
    expect(securityScore({ passedPRs: 0, reviewedPRs: 5 })).toBe(0);
  });
});
