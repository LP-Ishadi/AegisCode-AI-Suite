import { describe, expect, it } from 'vitest';
import { resumeManualReviewUrl } from './manualReviewRoute';

const scan = 'b79d6e69-32ea-4585-a1b9-d23de3b793e0';

describe('manual review OAuth return', () => {
  it('restores the selected scan after a successful sign-in', () => {
    expect(resumeManualReviewUrl('/', '#access_token=opaque', scan))
      .toBe(`/manual-review?scan=${scan}#access_token=opaque`);
  });

  it('keeps failed sign-ins on the review page so the error can be shown', () => {
    expect(resumeManualReviewUrl('/', '#error=access_denied', scan))
      .toBe(`/manual-review?scan=${scan}#error=access_denied`);
  });

  it('does not redirect regular dashboard visits or invalid scan IDs', () => {
    expect(resumeManualReviewUrl('/', '', scan)).toBeNull();
    expect(resumeManualReviewUrl('/', '#access_token=opaque', '../other')).toBeNull();
    expect(resumeManualReviewUrl('/manual-review', '#access_token=opaque', scan)).toBeNull();
  });
});
