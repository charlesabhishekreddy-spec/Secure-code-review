import { useState } from "react";

import { PatchDiffViewer } from "./PatchDiffViewer";
import { severityTone } from "../utils/language";

function humanize(value) {
  return String(value || "").replaceAll("_", " ");
}

export function ResultsTable({ vulnerabilities }) {
  const [copiedIndex, setCopiedIndex] = useState(null);
  const [expandedDiffKey, setExpandedDiffKey] = useState(null);
  const [filters, setFilters] = useState({
    severity: "ALL",
    category: "ALL",
    provider: "ALL",
    filename: "ALL",
    search: ""
  });

  const severityOptions = ["ALL", ...new Set(vulnerabilities.map((item) => item.severity))];
  const categoryOptions = ["ALL", ...new Set(vulnerabilities.map((item) => item.owasp_category))];
  const providerOptions = ["ALL", ...new Set(vulnerabilities.map((item) => item.ai_provider))];
  const filenameOptions = ["ALL", ...new Set(vulnerabilities.map((item) => item.filename))];

  const filteredVulnerabilities = vulnerabilities.filter((item) => {
    const searchTarget = [
      item.type,
      item.fix,
      item.explanation,
      item.filename,
      ...(item.rule_ids || []),
      ...(item.signals || [])
    ]
      .join(" ")
      .toLowerCase();

    return (
      (filters.severity === "ALL" || item.severity === filters.severity) &&
      (filters.category === "ALL" || item.owasp_category === filters.category) &&
      (filters.provider === "ALL" || item.ai_provider === filters.provider) &&
      (filters.filename === "ALL" || item.filename === filters.filename) &&
      (!filters.search.trim() || searchTarget.includes(filters.search.trim().toLowerCase()))
    );
  });

  async function handleCopy(index, text) {
    try {
      await navigator.clipboard.writeText(text);
      setCopiedIndex(index);
      window.setTimeout(() => setCopiedIndex(null), 1800);
    } catch {
      setCopiedIndex(null);
    }
  }

  return (
    <section className="glass-panel overflow-hidden">
      <div className="border-b border-white/10 px-6 py-5">
        <h2 className="text-xl font-semibold text-white">Vulnerability report</h2>
        <p className="mt-2 text-sm text-slate-300">
          Filter findings by severity, OWASP category, file, provider, or rule evidence before reviewing the secure patch.
        </p>
      </div>

      <div className="grid gap-3 border-b border-white/10 bg-slate-950/25 px-6 py-5 md:grid-cols-5">
        <label className="grid gap-2 text-xs uppercase tracking-[0.16em] text-slate-500">
          Severity
          <select
            value={filters.severity}
            onChange={(event) => setFilters((current) => ({ ...current, severity: event.target.value }))}
            className="rounded-2xl border border-white/10 bg-slate-950 px-3 py-2 text-sm normal-case tracking-normal text-white outline-none"
          >
            {severityOptions.map((option) => (
              <option key={option} value={option}>
                {option}
              </option>
            ))}
          </select>
        </label>

        <label className="grid gap-2 text-xs uppercase tracking-[0.16em] text-slate-500">
          OWASP
          <select
            value={filters.category}
            onChange={(event) => setFilters((current) => ({ ...current, category: event.target.value }))}
            className="rounded-2xl border border-white/10 bg-slate-950 px-3 py-2 text-sm normal-case tracking-normal text-white outline-none"
          >
            {categoryOptions.map((option) => (
              <option key={option} value={option}>
                {option}
              </option>
            ))}
          </select>
        </label>

        <label className="grid gap-2 text-xs uppercase tracking-[0.16em] text-slate-500">
          Provider
          <select
            value={filters.provider}
            onChange={(event) => setFilters((current) => ({ ...current, provider: event.target.value }))}
            className="rounded-2xl border border-white/10 bg-slate-950 px-3 py-2 text-sm normal-case tracking-normal text-white outline-none"
          >
            {providerOptions.map((option) => (
              <option key={option} value={option}>
                {option}
              </option>
            ))}
          </select>
        </label>

        <label className="grid gap-2 text-xs uppercase tracking-[0.16em] text-slate-500">
          File
          <select
            value={filters.filename}
            onChange={(event) => setFilters((current) => ({ ...current, filename: event.target.value }))}
            className="rounded-2xl border border-white/10 bg-slate-950 px-3 py-2 text-sm normal-case tracking-normal text-white outline-none"
          >
            {filenameOptions.map((option) => (
              <option key={option} value={option}>
                {option}
              </option>
            ))}
          </select>
        </label>

        <label className="grid gap-2 text-xs uppercase tracking-[0.16em] text-slate-500">
          Search
          <input
            value={filters.search}
            onChange={(event) => setFilters((current) => ({ ...current, search: event.target.value }))}
            placeholder="Type, rule, fix..."
            className="rounded-2xl border border-white/10 bg-slate-950 px-3 py-2 text-sm normal-case tracking-normal text-white outline-none placeholder:text-slate-500"
          />
        </label>
      </div>

      <div className="border-b border-white/10 px-6 py-4 text-sm text-slate-300">
        Showing <span className="font-semibold text-white">{filteredVulnerabilities.length}</span> of{" "}
        <span className="font-semibold text-white">{vulnerabilities.length}</span> finding(s)
      </div>

      <div className="overflow-x-auto">
        <table className="min-w-full border-collapse">
          <thead className="bg-slate-950/35 text-left text-xs uppercase tracking-[0.18em] text-slate-400">
            <tr>
              <th className="px-6 py-4">Line</th>
              <th className="px-6 py-4">Vulnerability</th>
              <th className="px-6 py-4">Severity</th>
              <th className="px-6 py-4">OWASP</th>
              <th className="px-6 py-4">Fix suggestion</th>
            </tr>
          </thead>
          <tbody>
            {filteredVulnerabilities.map((item, index) => {
              const diffKey = `${item.filename}-${item.line}-${item.type}`;
              const isDiffExpanded = expandedDiffKey === diffKey;

              return (
                <tr key={diffKey} className="align-top border-t border-white/10">
                  <td className="px-6 py-5 text-sm font-semibold text-white">{item.line}</td>
                  <td className="px-6 py-5">
                    <div className="space-y-3">
                      <div>
                        <p className="font-semibold text-white">{item.type}</p>
                        <p className="mt-1 text-xs uppercase tracking-[0.18em] text-slate-400">{item.filename}</p>
                      </div>
                      <code className="block rounded-2xl bg-slate-950/50 px-3 py-2 text-xs text-slate-200">{item.snippet}</code>
                      <div className="flex flex-wrap gap-2">
                        <span className="rounded-full border border-white/10 px-3 py-1 text-[11px] uppercase tracking-[0.18em] text-slate-300">
                          {humanize(item.review_decision)}
                        </span>
                        <span className="rounded-full border border-cyan-300/20 bg-cyan-400/10 px-3 py-1 text-[11px] uppercase tracking-[0.18em] text-cyan-100">
                          Confidence {item.confidence}
                        </span>
                        <span className="rounded-full border border-white/10 px-3 py-1 text-[11px] uppercase tracking-[0.18em] text-slate-300">
                          {item.ai_provider}
                        </span>
                      </div>
                      <div className="flex flex-wrap gap-2 text-[11px] uppercase tracking-[0.16em] text-slate-400">
                        {(item.rule_ids || []).map((ruleId) => (
                          <span key={ruleId} className="rounded-full border border-white/10 px-3 py-1">
                            {ruleId}
                          </span>
                        ))}
                        {(item.detection_methods || []).map((method) => (
                          <span key={method} className="rounded-full border border-mint/20 bg-mint/10 px-3 py-1 text-mint">
                            {method}
                          </span>
                        ))}
                      </div>
                    </div>
                  </td>
                  <td className="px-6 py-5">
                    <span className={`inline-flex rounded-full px-3 py-1 text-xs font-semibold ${severityTone(item.severity)}`}>
                      {item.severity}
                    </span>
                  </td>
                  <td className="px-6 py-5 text-sm font-medium text-mint">{item.owasp_category}</td>
                  <td className="px-6 py-5">
                    <div className="space-y-3">
                      <p className="text-sm text-slate-200">{item.fix}</p>
                      <details className="rounded-2xl border border-white/10 bg-slate-950/35 p-4">
                        <summary className="cursor-pointer list-none text-sm font-semibold text-white">View explanation and patch</summary>
                        <div className="mt-4 space-y-4 text-sm leading-6 text-slate-300">
                          <div>
                            <p className="text-xs uppercase tracking-[0.18em] text-slate-500">Why this matters</p>
                            <p className="mt-1">{item.explanation}</p>
                          </div>
                          <div>
                            <p className="text-xs uppercase tracking-[0.18em] text-slate-500">Attack scenario</p>
                            <p className="mt-1">{item.attack_scenario}</p>
                          </div>
                          {item.signals?.length ? (
                            <div>
                              <p className="text-xs uppercase tracking-[0.18em] text-slate-500">Signals</p>
                              <div className="mt-2 flex flex-wrap gap-2">
                                {item.signals.map((signal) => (
                                  <span key={signal} className="rounded-full border border-white/10 px-3 py-1 text-xs text-slate-300">
                                    {signal}
                                  </span>
                                ))}
                              </div>
                            </div>
                          ) : null}
                          <div>
                            <p className="text-xs uppercase tracking-[0.18em] text-slate-500">Review pipeline</p>
                            <div className="mt-2 space-y-2">
                              {Object.entries(item.review_pipeline || {}).map(([stageKey, stageValue]) => (
                                <div key={stageKey} className="rounded-2xl border border-white/10 bg-slate-950/40 p-3">
                                  <div className="flex items-center justify-between gap-3">
                                    <p className="text-sm font-semibold text-white">{stageValue.name || stageKey}</p>
                                    <span className="text-[11px] uppercase tracking-[0.18em] text-slate-400">
                                      {humanize(stageValue.status || "")}
                                    </span>
                                  </div>
                                  <p className="mt-2 text-sm text-slate-300">{stageValue.summary}</p>
                                </div>
                              ))}
                            </div>
                          </div>
                          <div className="space-y-3">
                            <div className="flex flex-wrap items-center justify-between gap-3">
                              <p className="text-xs uppercase tracking-[0.18em] text-slate-500">Patched replacement</p>
                              <div className="flex flex-wrap gap-2">
                                <button
                                  type="button"
                                  className="rounded-xl border border-white/10 px-3 py-2 text-xs font-semibold uppercase tracking-[0.18em] text-slate-200 transition hover:bg-white/5"
                                  onClick={() => setExpandedDiffKey((current) => (current === diffKey ? null : diffKey))}
                                >
                                  {isDiffExpanded ? "Hide diff" : "Show diff"}
                                </button>
                                <button
                                  type="button"
                                  className="rounded-xl border border-white/10 px-3 py-2 text-xs font-semibold uppercase tracking-[0.18em] text-slate-200 transition hover:bg-white/5"
                                  onClick={() => handleCopy(index, item.patched_code)}
                                >
                                  {copiedIndex === index ? "Copied" : "Copy fixed code"}
                                </button>
                              </div>
                            </div>
                            {isDiffExpanded ? (
                              <PatchDiffViewer
                                originalCode={item.snippet}
                                patchedCode={item.patched_code}
                                language={item.language}
                              />
                            ) : (
                              <pre className="overflow-x-auto rounded-2xl bg-slate-950/60 p-4 text-xs text-slate-100">
                                <code>{item.patched_code}</code>
                              </pre>
                            )}
                          </div>
                        </div>
                      </details>
                    </div>
                  </td>
                </tr>
              );
            })}
          </tbody>
        </table>
      </div>
    </section>
  );
}
