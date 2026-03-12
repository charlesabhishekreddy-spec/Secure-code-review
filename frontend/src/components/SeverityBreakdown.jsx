const palette = {
  CRITICAL: "from-rose-500 to-rose-300",
  HIGH: "from-orange-500 to-orange-300",
  MEDIUM: "from-amber-500 to-amber-300",
  LOW: "from-sky-500 to-sky-300"
};

export function SeverityBreakdown({ breakdown }) {
  const total = Object.values(breakdown).reduce((sum, count) => sum + count, 0) || 1;

  return (
    <div className="glass-panel p-6">
      <h3 className="text-lg font-semibold text-white">Severity breakdown</h3>
      <div className="mt-5 space-y-4">
        {Object.entries(breakdown).map(([severity, count]) => (
          <div key={severity}>
            <div className="mb-2 flex items-center justify-between text-sm">
              <span className="font-medium text-white">{severity}</span>
              <span className="text-slate-300">{count}</span>
            </div>
            <div className="h-3 overflow-hidden rounded-full bg-white/5">
              <div
                className={`h-full rounded-full bg-gradient-to-r ${palette[severity]}`}
                style={{ width: `${Math.max((count / total) * 100, count > 0 ? 8 : 0)}%` }}
              />
            </div>
          </div>
        ))}
      </div>
    </div>
  );
}
