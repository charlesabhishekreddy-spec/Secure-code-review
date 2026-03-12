import Editor from "@monaco-editor/react";

export function EditorWorkspace({ code, language, filename, onChange }) {
  return (
    <section className="glass-panel overflow-hidden">
      <div className="flex flex-wrap items-center justify-between gap-3 border-b border-white/10 bg-slate-950/40 px-5 py-4">
        <div>
          <p className="text-sm font-semibold text-white">Monaco Editor</p>
          <p className="text-xs uppercase tracking-[0.2em] text-slate-400">{filename || "Untitled snippet"}</p>
        </div>
        <div className="rounded-full border border-white/10 px-3 py-1 text-xs font-semibold uppercase tracking-[0.22em] text-mint">
          {language}
        </div>
      </div>
      <Editor
        height="560px"
        language={language}
        theme="vs-dark"
        value={code}
        onChange={(value) => onChange(value ?? "")}
        options={{
          automaticLayout: true,
          fontSize: 14,
          minimap: { enabled: false },
          scrollBeyondLastLine: false,
          smoothScrolling: true,
          wordWrap: "on",
          padding: { top: 16 }
        }}
      />
    </section>
  );
}
