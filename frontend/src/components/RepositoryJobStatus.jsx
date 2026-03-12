export function RepositoryJobStatus({ job }) {
  if (!job) {
    return null;
  }

  const progress = job.progress || {};

  return (
    <section className="glass-panel p-5">
      <div className="flex items-center justify-between gap-3">
        <div>
          <p className="text-sm font-semibold text-white">Repository scan job</p>
          <p className="mt-1 text-xs uppercase tracking-[0.18em] text-slate-500">{job.jobId || job.job_id}</p>
        </div>
        <span className="rounded-full border border-white/10 px-3 py-1 text-[11px] uppercase tracking-[0.18em] text-slate-300">
          {String(job.status || "queued").replaceAll("_", " ")}
        </span>
      </div>
      <div className="mt-4 rounded-2xl border border-white/10 bg-slate-950/30 px-4 py-3">
        <p className="text-xs uppercase tracking-[0.18em] text-slate-500">{progress.stage || "waiting"}</p>
        <p className="mt-2 text-sm text-slate-200">{progress.message || "Waiting for job progress updates."}</p>
        {typeof progress.scanned_files === "number" ? (
          <p className="mt-2 text-xs text-slate-400">Files queued for review: {progress.scanned_files}</p>
        ) : null}
        {job.error ? <p className="mt-3 text-sm text-rose-200">{job.error}</p> : null}
      </div>
    </section>
  );
}
