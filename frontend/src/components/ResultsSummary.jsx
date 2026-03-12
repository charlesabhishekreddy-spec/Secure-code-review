import { SeverityBreakdown } from "./SeverityBreakdown";

function scoreTone(score) {
  if (score >= 85) {
    return "from-emerald-400 to-mint";
  }
  if (score >= 65) {
    return "from-amber-400 to-amber-200";
  }
  return "from-rose-500 to-orange-300";
}

export function ResultsSummary({ results }) {
  const repository = results?.source?.repository;
  const aiStage = results?.review_stages?.find((stage) => stage.id === "stage_2_gemini_ai_review");
  const suspiciousDensity = results?.statistics?.suspicious_density ?? 0;

  return (
    <div className="grid gap-5 xl:grid-cols-[1.2fr_0.8fr]">
      <div className="grid gap-5 md:grid-cols-3">
        <article className="glass-panel p-6 md:col-span-2">
          <p className="section-label">Security score</p>
          <div className="mt-5 flex flex-col gap-5 lg:flex-row lg:items-center lg:justify-between">
            <div>
              <h2 className="text-3xl font-semibold text-white">Risk posture for this scan</h2>
              <p className="mt-3 max-w-xl text-sm leading-6 text-slate-300">
                CodeSentinel now runs a three-stage review flow and subtracts weighted penalties from 100 after OWASP
                correlation and severity scoring.
              </p>
              <div className="mt-4 text-sm text-slate-300">
                Source: <span className="font-semibold text-white">{results.source.filename}</span>
                {repository ? ` | ${repository}` : ""}
              </div>
            </div>
            <div className={`rounded-[2rem] bg-gradient-to-br ${scoreTone(results.security_score)} p-[1px]`}>
              <div className="flex h-36 w-36 flex-col items-center justify-center rounded-[calc(2rem-1px)] bg-slate-950/90">
                <span className="text-4xl font-black text-white">{results.security_score}</span>
                <span className="mt-1 text-xs uppercase tracking-[0.24em] text-slate-400">out of 100</span>
              </div>
            </div>
          </div>
        </article>
        <article className="glass-panel p-6">
          <p className="text-sm uppercase tracking-[0.2em] text-slate-400">Total findings</p>
          <p className="mt-4 text-4xl font-black text-white">{results.total_vulnerabilities}</p>
          <p className="mt-3 text-sm text-slate-300">
            Suspicious code density: <span className="font-semibold text-white">{suspiciousDensity}%</span>
          </p>
        </article>
        <article className="glass-panel p-6">
          <p className="text-sm uppercase tracking-[0.2em] text-slate-400">AI review stage</p>
          <p className="mt-4 text-2xl font-black text-white">
            {aiStage?.details?.providers_used?.gemini ? "Gemini" : "Local fallback"}
          </p>
          <p className="mt-3 text-sm text-slate-300">{aiStage?.summary || "Gemini is configured as the primary review stage."}</p>
        </article>
      </div>
      <SeverityBreakdown breakdown={results.severity_breakdown} />
    </div>
  );
}
