function stageTone(status) {
  if (status === "completed") {
    return "border-emerald-400/25 bg-emerald-500/10";
  }
  if (status === "completed_with_fallback") {
    return "border-amber-400/25 bg-amber-500/10";
  }
  if (status === "fallback") {
    return "border-orange-400/25 bg-orange-500/10";
  }
  return "border-white/10 bg-slate-950/35";
}

function renderDetailValue(value) {
  if (value === null || value === undefined) {
    return "n/a";
  }
  if (typeof value === "object") {
    return JSON.stringify(value);
  }
  return String(value);
}

export function ReviewStages({ stages }) {
  return (
    <section className="glass-panel p-6">
      <p className="section-label">Three-stage review</p>
      <h2 className="mt-4 text-2xl font-semibold text-white">Statistical analysis, Gemini validation, OWASP scoring</h2>
      <div className="mt-6 grid gap-4 xl:grid-cols-3">
        {stages.map((stage) => (
          <article key={stage.id} className={`rounded-3xl border p-5 ${stageTone(stage.status)}`}>
            <div className="flex items-center justify-between gap-3">
              <p className="text-sm font-semibold text-white">{stage.name}</p>
              <span className="rounded-full border border-white/10 px-3 py-1 text-[11px] uppercase tracking-[0.18em] text-slate-200">
                {stage.status.replaceAll("_", " ")}
              </span>
            </div>
            <p className="mt-3 text-sm leading-6 text-slate-300">{stage.summary}</p>
            <div className="mt-4 space-y-2 text-xs text-slate-400">
              {Object.entries(stage.details || {}).slice(0, 4).map(([key, value]) => (
                <div key={key} className="flex items-start justify-between gap-3 border-t border-white/5 pt-2">
                  <span className="uppercase tracking-[0.16em]">{key.replaceAll("_", " ")}</span>
                  <span className="max-w-[55%] text-right text-slate-300">{renderDetailValue(value)}</span>
                </div>
              ))}
            </div>
          </article>
        ))}
      </div>
    </section>
  );
}
