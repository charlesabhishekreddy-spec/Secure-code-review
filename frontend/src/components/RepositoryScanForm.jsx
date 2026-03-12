export function RepositoryScanForm({ value, onChange, branchValue, onBranchChange, onSubmit, disabled }) {
  return (
    <section className="glass-panel p-5">
      <div className="flex flex-col gap-4">
        <div>
          <p className="text-sm font-semibold text-white">Optional GitHub repository scan</p>
          <p className="mt-1 text-sm text-slate-300">
            Paste a public GitHub repository URL or a <code>/tree/&lt;branch&gt;</code> URL to scan Python,
            JavaScript, TypeScript, and Java source files.
          </p>
        </div>
        <div className="grid gap-3">
          <input
            value={value}
            onChange={(event) => onChange(event.target.value)}
            placeholder="https://github.com/owner/repository"
            className="min-h-12 flex-1 rounded-2xl border border-white/10 bg-slate-950/40 px-4 text-sm text-white outline-none ring-0 placeholder:text-slate-500 focus:border-mint"
          />
          <div className="flex flex-col gap-3 sm:flex-row">
            <input
              value={branchValue}
              onChange={(event) => onBranchChange(event.target.value)}
              placeholder="Optional branch, e.g. main"
              className="min-h-12 flex-1 rounded-2xl border border-white/10 bg-slate-950/40 px-4 text-sm text-white outline-none ring-0 placeholder:text-slate-500 focus:border-mint"
            />
            <button
              type="button"
              className="action-button bg-mint text-slate-950 hover:bg-cyan-300 disabled:cursor-not-allowed disabled:opacity-60"
              onClick={onSubmit}
              disabled={disabled}
            >
              Scan repository
            </button>
          </div>
        </div>
      </div>
    </section>
  );
}
