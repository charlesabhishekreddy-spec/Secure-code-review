import { Link } from "react-router-dom";

export function EmptyResultsState() {
  return (
    <section className="glass-panel mx-auto max-w-3xl p-8 text-center">
      <p className="section-label">No results yet</p>
      <h1 className="mt-5 text-3xl font-semibold text-white">Run a scan to generate a report</h1>
      <p className="mx-auto mt-3 max-w-xl text-sm leading-6 text-slate-300">
        Paste code into the Monaco editor, upload a file, or scan a GitHub repository to populate the dashboard.
      </p>
      <Link to="/scanner" className="action-button mt-6 bg-mint text-slate-950 hover:bg-cyan-300">
        Open scanner
      </Link>
    </section>
  );
}
