import { useState } from "react";
import { Link, useNavigate } from "react-router-dom";

import { ScanHistoryPanel } from "../components/ScanHistoryPanel";
import { useScanContext } from "../context/ScanContext";

export function HistoryPage() {
  const navigate = useNavigate();
  const { results, scanHistory, clearHistory, restoreHistoryEntry } = useScanContext();
  const currentResults = results || scanHistory[0]?.results || null;
  const [selectedHistoryId, setSelectedHistoryId] = useState(scanHistory[1]?.id || "");

  return (
    <div className="space-y-6">
      <div className="flex flex-col gap-4 lg:flex-row lg:items-center lg:justify-between">
        <div>
          <p className="section-label">History dashboard</p>
          <h1 className="mt-4 text-3xl font-semibold text-white">Scan history and comparison</h1>
          <p className="mt-3 max-w-3xl text-sm leading-6 text-slate-300">
            Review saved scans in one place, compare deltas against the latest run, and reopen any historical report.
          </p>
        </div>
        <div className="flex flex-wrap items-center gap-3">
          <Link to="/results" className="action-button bg-white/10 text-white hover:bg-white/15">
            Current results
          </Link>
          <Link to="/scanner" className="action-button bg-white/10 text-white hover:bg-white/15">
            New scan
          </Link>
        </div>
      </div>

      <ScanHistoryPanel
        currentResults={currentResults}
        history={scanHistory}
        selectedHistoryId={selectedHistoryId}
        onSelectHistory={setSelectedHistoryId}
        onOpenHistory={(entryId) => {
          restoreHistoryEntry(entryId);
          navigate("/results");
        }}
        onClearHistory={clearHistory}
      />
    </div>
  );
}
