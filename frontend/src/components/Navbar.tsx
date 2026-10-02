import { GitBranch, ShieldCheck } from 'lucide-react';

export function Navbar({ repositories, demo, email, onSignOut }: {
  repositories: number; demo: boolean; email?: string; onSignOut: () => void;
}) {
  return <header className="border-b border-white/8 bg-[#0d142b]">
    <div className="mx-auto flex max-w-[1440px] items-center justify-between gap-4 px-5 py-5 md:px-10">
      <a href="#overview" className="flex items-center gap-3" aria-label="AegisCode home">
        <span className="rounded-xl border border-indigo-300/20 bg-indigo-300/10 p-2 text-indigo-200"><ShieldCheck size={24} /></span>
        <span className="text-lg font-semibold tracking-tight">AegisCode <span className="text-indigo-300">AI</span></span>
        <span className="hidden rounded border border-white/10 px-1.5 py-0.5 text-[9px] font-medium tracking-widest text-zinc-400 sm:block">SUITE</span>
      </a>
      <div className="flex items-center gap-5 text-xs text-zinc-400">
        <span className="hidden items-center gap-2 sm:flex"><GitBranch size={15} />{repositories} repositories</span>
        <span className="h-5 w-px bg-white/10" />
        <span className="flex items-center gap-2"><span className="grid size-8 place-items-center rounded-full bg-[#312e81] text-xs font-semibold text-indigo-100">{email ? email.slice(0, 2).toUpperCase() : 'AC'}</span><span className="hidden md:block">{demo ? 'Acme workspace' : email ?? 'Your workspace'}</span></span>
        {email && <button className="hover:text-white" onClick={onSignOut}>Sign out</button>}
      </div>
    </div>
  </header>;
}
