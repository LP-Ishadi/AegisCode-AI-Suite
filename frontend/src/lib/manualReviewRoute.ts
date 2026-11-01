const SCAN_ID = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;

export function isScanId(value: string | null): value is string {
  return value !== null && SCAN_ID.test(value);
}

export function resumeManualReviewUrl(pathname: string, hash: string, pending: string | null): string | null {
  if (pathname !== '/' || !/(?:^|&)(?:access_token|error|error_description)=/.test(hash.slice(1)) || !isScanId(pending)) return null;
  return `/manual-review?scan=${encodeURIComponent(pending)}${hash}`;
}
