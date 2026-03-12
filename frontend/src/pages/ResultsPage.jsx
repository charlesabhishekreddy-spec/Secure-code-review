import { useState } from "react";
import { Link } from "react-router-dom";

import { EmptyResultsState } from "../components/EmptyResultsState";
import { ResultsSummary } from "../components/ResultsSummary";
import { ResultsTable } from "../components/ResultsTable";
import { ReviewStages } from "../components/ReviewStages";
import { ScanHistoryPanel } from "../components/ScanHistoryPanel";
import { useScanContext } from "../context/ScanContext";

export function ResultsPage() {
  const { results, scanHistory, clearHistory, restoreHistoryEntry } = useScanContext();
  const [selectedHistoryId, setSelectedHistoryId] = useState(scanHistory[1]?.id || "");

  if (!results) {
    return <EmptyResultsState />;
  }

  return (
    <div className="space-y-6">
      <div className="flex flex-col gap-4 lg:flex-row lg:items-center lg:justify-between">
        <div>
          <p className="section-label">Results dashboard</p>
          <h1 className="mt-4 text-3xl font-semibold text-white">Three-stage security review summary</h1>
          <p className="mt-3 max-w-3xl text-sm leading-6 text-slate-300">
            Review the stage-1 statistical signals, the stage-2 Gemini validation output, and the stage-3 OWASP-based
            score before applying the recommended fix.
          </p>
        </div>
        <Link to="/scanner" className="action-button bg-white/10 text-white hover:bg-white/15">
          New scan
        </Link>
      </div>

      <ResultsSummary results={results} />
      <ReviewStages stages={results.review_stages || []} />
      <ScanHistoryPanel
        currentResults={results}
        history={scanHistory}
        selectedHistoryId={selectedHistoryId}
        onSelectHistory={setSelectedHistoryId}
        onOpenHistory={restoreHistoryEntry}
        onClearHistory={clearHistory}
      />
      <ResultsTable vulnerabilities={results.vulnerabilities || []} />
    </div>
  );
}
