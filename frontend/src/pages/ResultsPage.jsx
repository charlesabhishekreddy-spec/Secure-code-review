import { Link } from "react-router-dom";

import { EmptyResultsState } from "../components/EmptyResultsState";
import { ResultsSummary } from "../components/ResultsSummary";
import { ResultsTable } from "../components/ResultsTable";
import { useScanContext } from "../context/ScanContext";

export function ResultsPage() {
  const { results } = useScanContext();

  if (!results) {
    return <EmptyResultsState />;
  }

  return (
    <div className="space-y-6">
      <div className="flex flex-col gap-4 lg:flex-row lg:items-center lg:justify-between">
        <div>
          <p className="section-label">Results dashboard</p>
          <h1 className="mt-4 text-3xl font-semibold text-white">Security review summary</h1>
          <p className="mt-3 max-w-3xl text-sm leading-6 text-slate-300">
            Review the findings, understand the exploit path, and copy the secure replacement into your codebase.
          </p>
        </div>
        <Link to="/scanner" className="action-button bg-white/10 text-white hover:bg-white/15">
          New scan
        </Link>
      </div>

      <ResultsSummary results={results} />
      <ResultsTable vulnerabilities={results.vulnerabilities} />
    </div>
  );
}
