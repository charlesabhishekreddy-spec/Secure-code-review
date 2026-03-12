function sumBreakdown(breakdown = {}) {
  return Object.values(breakdown).reduce((total, count) => total + Number(count || 0), 0);
}

function compareDelta(currentValue, previousValue) {
  const delta = Number(currentValue || 0) - Number(previousValue || 0);
  if (delta === 0) {
    return "No change";
  }
  return `${delta > 0 ? "+" : ""}${delta}`;
}

export function ScanHistoryPanel({
  currentResults,
  history,
  selectedHistoryId,
  onSelectHistory,
  onOpenHistory,
  onClearHistory
}) {
  const comparableHistory = history.filter((entry) => entry.results);
  const selectedEntry = comparableHistory.find((entry) => entry.id === selectedHistoryId) || comparableHistory[1] || null;

  return (
    <section className="glass-panel p-6">
      <div className="flex flex-col gap-4 lg:flex-row lg:items-center lg:justify-between">
        <div>
          <p className="section-label">Scan history</p>
          <h2 className="mt-4 text-2xl font-semibold text-white">Compare the current scan with earlier runs</h2>
          <p className="mt-2 text-sm leading-6 text-slate-300">
            Local history is kept in the browser so you can measure whether a patch improved score, findings, and severity mix.
          </p>
        </div>
        <button
          type="button"
          onClick={onClearHistory}
          className="rounded-2xl border border-white/10 px-4 py-3 text-sm font-semibold text-slate-200 transition hover:bg-white/5"
        >
          Clear history
        </button>
      </div>

      <div className="mt-6 grid gap-6 xl:grid-cols-[0.9fr_1.1fr]">
        <div className="space-y-3">
          {comparableHistory.length ? (
            comparableHistory.map((entry) => (
              <button
                key={entry.id}
                type="button"
                onClick={() => onSelectHistory(entry.id)}
                className={`w-full rounded-3xl border px-4 py-4 text-left transition ${
                  entry.id === (selectedEntry?.id || selectedHistoryId)
                    ? "border-mint bg-mint/10"
                    : "border-white/10 bg-slate-950/30 hover:bg-white/5"
                }`}
              >
                <div className="flex items-center justify-between gap-3">
                  <div>
                    <p className="text-sm font-semibold text-white">{entry.summary.filename}</p>
                    <p className="mt-1 text-xs uppercase tracking-[0.18em] text-slate-500">
                      {new Date(entry.createdAt).toLocaleString()}
                    </p>
                  </div>
                  <span className="rounded-full border border-white/10 px-3 py-1 text-[11px] uppercase tracking-[0.18em] text-slate-300">
                    {entry.summary.securityScore}
                  </span>
                </div>
                <p className="mt-3 text-sm text-slate-300">
                  {entry.summary.repository || entry.summary.filename} | {entry.summary.totalVulnerabilities} finding(s)
                </p>
                <div className="mt-4 flex items-center gap-3">
                  <button
                    type="button"
                    onClick={(event) => {
                      event.stopPropagation();
                      onOpenHistory(entry.id);
                    }}
                    className="rounded-xl border border-white/10 px-3 py-2 text-xs font-semibold uppercase tracking-[0.18em] text-slate-200 transition hover:bg-white/5"
                  >
                    Open report
                  </button>
                </div>
              </button>
            ))
          ) : (
            <div className="rounded-3xl border border-white/10 bg-slate-950/30 px-4 py-5 text-sm text-slate-300">
              No prior scans are stored yet. Run at least two scans to unlock comparison.
            </div>
          )}
        </div>

        <div className="grid gap-4 md:grid-cols-3">
          <article className="rounded-3xl border border-white/10 bg-slate-950/30 p-5">
            <p className="text-xs uppercase tracking-[0.18em] text-slate-500">Score delta</p>
            <p className="mt-3 text-3xl font-black text-white">
              {selectedEntry ? compareDelta(currentResults?.security_score, selectedEntry.results?.security_score) : "n/a"}
            </p>
            <p className="mt-2 text-sm text-slate-300">Current score versus the selected historical scan.</p>
          </article>
          <article className="rounded-3xl border border-white/10 bg-slate-950/30 p-5">
            <p className="text-xs uppercase tracking-[0.18em] text-slate-500">Findings delta</p>
            <p className="mt-3 text-3xl font-black text-white">
              {selectedEntry
                ? compareDelta(currentResults?.total_vulnerabilities, selectedEntry.results?.total_vulnerabilities)
                : "n/a"}
            </p>
            <p className="mt-2 text-sm text-slate-300">Current total vulnerabilities versus the selected scan.</p>
          </article>
          <article className="rounded-3xl border border-white/10 bg-slate-950/30 p-5">
            <p className="text-xs uppercase tracking-[0.18em] text-slate-500">Severity load</p>
            <p className="mt-3 text-3xl font-black text-white">
              {selectedEntry
                ? compareDelta(
                    sumBreakdown(currentResults?.severity_breakdown),
                    sumBreakdown(selectedEntry.results?.severity_breakdown)
                  )
                : "n/a"}
            </p>
            <p className="mt-2 text-sm text-slate-300">Difference in total severity buckets across both scans.</p>
          </article>
        </div>
      </div>
    </section>
  );
}
