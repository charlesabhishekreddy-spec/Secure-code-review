const features = [
  {
    title: "OWASP-focused scanning",
    description: "Detects SQL injection, command injection, XSS, secrets, weak crypto, insecure deserialization, SSRF, and more."
  },
  {
    title: "Actionable AI explanations",
    description: "Each finding includes plain-English risk context, attack scenarios, and secure patched replacements."
  },
  {
    title: "Developer-first workflow",
    description: "Paste code, upload files, or scan public GitHub repositories from one workspace with Monaco editing."
  }
];

export function FeatureGrid() {
  return (
    <div className="grid gap-5 lg:grid-cols-3">
      {features.map((feature) => (
        <article key={feature.title} className="glass-panel p-6">
          <div className="mb-4 inline-flex rounded-2xl bg-white/10 px-3 py-1 text-xs font-semibold uppercase tracking-[0.24em] text-mint">
            Security
          </div>
          <h3 className="text-xl font-semibold text-white">{feature.title}</h3>
          <p className="mt-3 text-sm leading-6 text-slate-300">{feature.description}</p>
        </article>
      ))}
    </div>
  );
}
