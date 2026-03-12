export function SessionSettingsPanel({ settings, onChange, disabled }) {
  function updateField(field, value) {
    onChange((current) => ({
      ...current,
      [field]: value
    }));
  }

  return (
    <section className="glass-panel p-5">
      <div className="flex flex-col gap-4">
        <div>
          <p className="text-sm font-semibold text-white">Session settings</p>
          <p className="mt-1 text-sm text-slate-300">
            Configure optional API auth, editor markers, repo polling, and local scan history retention.
          </p>
        </div>

        <label className="grid gap-2 text-sm text-slate-300">
          <span>API token</span>
          <input
            type="password"
            value={settings.apiToken}
            onChange={(event) => updateField("apiToken", event.target.value)}
            placeholder="Optional bearer token for protected API deployments"
            disabled={disabled}
            className="min-h-12 rounded-2xl border border-white/10 bg-slate-950/40 px-4 text-sm text-white outline-none ring-0 placeholder:text-slate-500 focus:border-mint"
          />
        </label>

        <div className="grid gap-3 sm:grid-cols-2">
          <label className="rounded-2xl border border-white/10 bg-slate-950/30 px-4 py-3 text-sm text-slate-300">
            <span className="block text-xs uppercase tracking-[0.18em] text-slate-500">Repo polling ms</span>
            <input
              type="number"
              min="1000"
              step="500"
              value={settings.repoPollIntervalMs}
              onChange={(event) => updateField("repoPollIntervalMs", Number(event.target.value) || 2000)}
              disabled={disabled}
              className="mt-2 w-full bg-transparent text-white outline-none"
            />
          </label>
          <label className="rounded-2xl border border-white/10 bg-slate-950/30 px-4 py-3 text-sm text-slate-300">
            <span className="block text-xs uppercase tracking-[0.18em] text-slate-500">History limit</span>
            <input
              type="number"
              min="3"
              max="20"
              step="1"
              value={settings.historyLimit}
              onChange={(event) => updateField("historyLimit", Number(event.target.value) || 8)}
              disabled={disabled}
              className="mt-2 w-full bg-transparent text-white outline-none"
            />
          </label>
        </div>

        <label className="flex items-center justify-between gap-3 rounded-2xl border border-white/10 bg-slate-950/30 px-4 py-3 text-sm text-slate-300">
          <span>Auto-open results after a scan completes</span>
          <input
            type="checkbox"
            checked={settings.autoOpenResults}
            onChange={(event) => updateField("autoOpenResults", event.target.checked)}
            disabled={disabled}
            className="h-4 w-4 rounded border-white/20 bg-slate-950 text-mint"
          />
        </label>

        <label className="flex items-center justify-between gap-3 rounded-2xl border border-white/10 bg-slate-950/30 px-4 py-3 text-sm text-slate-300">
          <span>Show Monaco markers for the latest file scan</span>
          <input
            type="checkbox"
            checked={settings.showMonacoMarkers}
            onChange={(event) => updateField("showMonacoMarkers", event.target.checked)}
            disabled={disabled}
            className="h-4 w-4 rounded border-white/20 bg-slate-950 text-mint"
          />
        </label>
      </div>
    </section>
  );
}
