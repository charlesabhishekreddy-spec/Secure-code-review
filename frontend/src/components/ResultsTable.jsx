import { useState } from "react";

import { severityTone } from "../utils/language";

export function ResultsTable({ vulnerabilities }) {
  const [copiedIndex, setCopiedIndex] = useState(null);

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
          Each finding now includes its stage-1 signal, stage-2 AI review outcome, and stage-3 OWASP mapping.
        </p>
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
            {vulnerabilities.map((item, index) => (
              <tr key={`${item.filename}-${item.line}-${item.type}`} className="align-top border-t border-white/10">
                <td className="px-6 py-5 text-sm font-semibold text-white">{item.line}</td>
                <td className="px-6 py-5">
                  <div className="space-y-2">
                    <p className="font-semibold text-white">{item.type}</p>
                    <p className="text-xs uppercase tracking-[0.18em] text-slate-400">{item.filename}</p>
                    <code className="block rounded-2xl bg-slate-950/50 px-3 py-2 text-xs text-slate-200">{item.snippet}</code>
                    <div className="flex flex-wrap gap-2 pt-1">
                      <span className="rounded-full border border-white/10 px-3 py-1 text-[11px] uppercase tracking-[0.18em] text-slate-300">
                        {item.review_decision.replaceAll("_", " ")}
                      </span>
                      <span className="rounded-full border border-cyan-300/20 bg-cyan-400/10 px-3 py-1 text-[11px] uppercase tracking-[0.18em] text-cyan-100">
                        Confidence {item.confidence}
                      </span>
                      <span className="rounded-full border border-white/10 px-3 py-1 text-[11px] uppercase tracking-[0.18em] text-slate-300">
                        {item.ai_provider}
                      </span>
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
                        <div>
                          <p className="text-xs uppercase tracking-[0.18em] text-slate-500">Review pipeline</p>
                          <div className="mt-2 space-y-2">
                            {Object.entries(item.review_pipeline || {}).map(([stageKey, stageValue]) => (
                              <div key={stageKey} className="rounded-2xl border border-white/10 bg-slate-950/40 p-3">
                                <div className="flex items-center justify-between gap-3">
                                  <p className="text-sm font-semibold text-white">{stageValue.name || stageKey}</p>
                                  <span className="text-[11px] uppercase tracking-[0.18em] text-slate-400">
                                    {String(stageValue.status || "").replaceAll("_", " ")}
                                  </span>
                                </div>
                                <p className="mt-2 text-sm text-slate-300">{stageValue.summary}</p>
                              </div>
                            ))}
                          </div>
                        </div>
                        <div>
                          <div className="mb-2 flex items-center justify-between gap-3">
                            <p className="text-xs uppercase tracking-[0.18em] text-slate-500">Patched replacement</p>
                            <button
                              type="button"
                              className="rounded-xl border border-white/10 px-3 py-2 text-xs font-semibold uppercase tracking-[0.18em] text-slate-200 transition hover:bg-white/5"
                              onClick={() => handleCopy(index, item.patched_code)}
                            >
                              {copiedIndex === index ? "Copied" : "Copy fixed code"}
                            </button>
                          </div>
                          <pre className="overflow-x-auto rounded-2xl bg-slate-950/60 p-4 text-xs text-slate-100">
                            <code>{item.patched_code}</code>
                          </pre>
                        </div>
                      </div>
                    </details>
                  </div>
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </section>
  );
}
