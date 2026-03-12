import { Link } from "react-router-dom";

import { FeatureGrid } from "../components/FeatureGrid";

export function HomePage() {
  return (
    <div className="space-y-8">
      <section className="glass-panel overflow-hidden px-6 py-10 sm:px-10 lg:px-12">
        <div className="grid gap-10 lg:grid-cols-[1.2fr_0.8fr] lg:items-center">
          <div>
            <p className="section-label">AI-powered secure review</p>
            <h1 className="mt-5 max-w-3xl text-4xl font-black leading-tight text-white sm:text-5xl">
              Find OWASP Top 10 vulnerabilities before they ship.
            </h1>
            <p className="mt-5 max-w-2xl text-base leading-7 text-slate-300">
              CodeSentinel combines stage-1 statistical pattern analysis, stage-2 Gemini validation, and stage-3
              OWASP correlation to detect insecure code patterns, report exact line numbers, explain the risk in plain
              English, and recommend safer replacements.
            </p>
            <div className="mt-8 flex flex-wrap gap-3">
              <Link to="/scanner" className="action-button bg-mint text-slate-950 hover:bg-cyan-300">
                Launch scanner
              </Link>
              <Link to="/results" className="action-button bg-white/10 text-white hover:bg-white/15">
                View dashboard
              </Link>
            </div>
            <div className="mt-8 grid gap-4 sm:grid-cols-3">
              <div className="rounded-3xl border border-white/10 bg-slate-950/35 p-4">
                <p className="text-xs uppercase tracking-[0.18em] text-slate-500">Findings</p>
                <p className="mt-2 text-2xl font-black text-white">8+</p>
                <p className="mt-1 text-sm text-slate-300">Core vulnerability classes with OWASP mapping.</p>
              </div>
              <div className="rounded-3xl border border-white/10 bg-slate-950/35 p-4">
                <p className="text-xs uppercase tracking-[0.18em] text-slate-500">Inputs</p>
                <p className="mt-2 text-2xl font-black text-white">3</p>
                <p className="mt-1 text-sm text-slate-300">Paste snippets, upload files, or scan GitHub repositories.</p>
              </div>
              <div className="rounded-3xl border border-white/10 bg-slate-950/35 p-4">
                <p className="text-xs uppercase tracking-[0.18em] text-slate-500">Outputs</p>
                <p className="mt-2 text-2xl font-black text-white">100</p>
                <p className="mt-1 text-sm text-slate-300">Weighted security score with severity breakdown.</p>
              </div>
            </div>
          </div>
          <div className="relative">
            <div className="absolute inset-0 rounded-[2rem] bg-gradient-to-br from-mint/20 via-transparent to-amber-300/20 blur-2xl" />
            <div className="relative rounded-[2rem] border border-white/10 bg-slate-950/60 p-6 shadow-glow">
              <p className="text-xs uppercase tracking-[0.18em] text-slate-500">Sample flagged issue</p>
              <pre className="mt-4 overflow-x-auto rounded-3xl bg-slate-900/90 p-5 text-sm text-slate-100">
                <code>{`query = "SELECT * FROM users WHERE id=" + user_input`}</code>
              </pre>
              <div className="mt-5 rounded-3xl border border-orange-300/25 bg-orange-500/10 p-4">
                <p className="text-sm font-semibold text-orange-100">SQL Injection · HIGH · A03 Injection</p>
                <p className="mt-2 text-sm leading-6 text-slate-200">
                  Dynamic query construction lets attacker input change the SQL structure. Use a prepared statement and
                  bind the value separately.
                </p>
              </div>
            </div>
          </div>
        </div>
      </section>

      <FeatureGrid />
    </div>
  );
}
