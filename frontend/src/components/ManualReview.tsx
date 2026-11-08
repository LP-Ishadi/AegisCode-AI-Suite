import { useEffect, useState } from 'react';
import type { Session } from '@supabase/supabase-js';

const apiBase = import.meta.env.VITE_API_URL || 'http://localhost:8000';

type ReviewPrompt = { next_required_action?: string; example_next_reply?: unknown; file_read_completed?: boolean };
type Review = { id: string; step: number; status: string; prompt: ReviewPrompt };
type Step = { step: number; action: string; response: unknown; tool_summary: unknown };

export function ManualReview({ scanId, session, onClose, onComplete }: {
  scanId: string; session: Session; onClose: () => void; onComplete: () => void;
}) {
  const [review, setReview] = useState<Review | null>(null);
  const [steps, setSteps] = useState<Step[]>([]);
  const [answer, setAnswer] = useState('');
  const [error, setError] = useState('');
  const [busy, setBusy] = useState(false);

  async function request(path: string, method = 'GET', body?: unknown) {
    const response = await fetch(`${apiBase}/api/v1/manual-reviews${path}`, {
      method,
      headers: { Authorization: `Bearer ${session.access_token}`, 'Content-Type': 'application/json' },
      body: body === undefined ? undefined : JSON.stringify(body),
    });
    const result = await response.json();
    if (!response.ok) throw new Error(typeof result.detail === 'string' ? result.detail : 'Review request failed');
    return result;
  }

  async function load(id: string) {
    const result = await request(`/${id}`);
    setReview(result.review);
    setSteps(result.steps);
  }

  useEffect(() => {
    let active = true;
    setBusy(true);
    void request(`/scans/${scanId}`, 'POST').then(result => {
      if (active) return load(result.id);
    }).catch(err => { if (active) setError(err.message); })
      .finally(() => { if (active) setBusy(false); });
    return () => { active = false; };
  }, [scanId]);

  async function submit() {
    if (!review) return;
    setBusy(true); setError('');
    try {
      const parsed = JSON.parse(answer);
      await request(`/${review.id}/responses`, 'POST', { step: review.step, response: parsed });
      setAnswer('');
      await load(review.id);
      onComplete();
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Invalid response');
    } finally { setBusy(false); }
  }

  return <section className="panel space-y-5 p-5" aria-label="Manual AI review">
    <div className="flex items-center justify-between gap-3"><div><h2 className="text-lg font-semibold">Manual AI review</h2><p className="text-xs text-zinc-400">Copy the full request into your AI chat, then paste its JSON answer below.</p></div><button className="secondary-button" onClick={onClose}>Close</button></div>
    <p className="text-xs text-amber-200">Prompts may contain private source code. Review them before pasting into an external chat. Only organization owners and admins can operate this review.</p>
    {error && <p role="alert" className="text-sm text-rose-300">{error}</p>}
    {busy && <p role="status" className="text-xs text-zinc-400">Working…</p>}
    {review && <><p className="text-xs text-zinc-400">Step {review.step + 1} · {review.status}</p>
      {review.status === 'active' && review.prompt.next_required_action &&
        <p className="text-sm text-indigo-200">Next: {review.prompt.next_required_action}</p>}
      <label className="block text-xs font-medium" htmlFor="review-prompt">Request to copy</label>
      <textarea id="review-prompt" className="form-input h-72 font-mono text-xs" readOnly value={JSON.stringify(review.prompt, null, 2)} />
      <button className="secondary-button" onClick={() => void navigator.clipboard.writeText(JSON.stringify(review.prompt, null, 2))}>Copy request</button>
      {review.status === 'active' && <><label className="block text-xs font-medium" htmlFor="review-answer">AI JSON response</label>
        <textarea id="review-answer" className="form-input h-40 font-mono text-xs" value={answer} onChange={event => setAnswer(event.target.value)} placeholder={JSON.stringify(review.prompt.example_next_reply || { kind: 'tool', tool: { name: 'list_files' } })} />
        <button className="primary-button" disabled={busy || !answer.trim()} onClick={() => void submit()}>Validate and continue</button></>}
      {steps.length > 0 && <details><summary className="cursor-pointer text-sm">Review history ({steps.length} steps)</summary><ol className="mt-3 space-y-2 text-xs text-zinc-400">{steps.map(step => <li key={step.step}>Step {step.step + 1}: {step.action} · {JSON.stringify(step.tool_summary)}</li>)}</ol></details>}
    </>}
  </section>;
}
