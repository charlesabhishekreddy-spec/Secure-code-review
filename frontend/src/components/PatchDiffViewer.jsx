import { DiffEditor } from "@monaco-editor/react";

export function PatchDiffViewer({ originalCode, patchedCode, language }) {
  return (
    <div className="overflow-hidden rounded-2xl border border-white/10 bg-slate-950/40">
      <div className="border-b border-white/10 px-4 py-3 text-xs uppercase tracking-[0.18em] text-slate-500">
        Secure patch diff
      </div>
      <DiffEditor
        height="260px"
        language={language}
        theme="vs-dark"
        original={originalCode || ""}
        modified={patchedCode || ""}
        options={{
          automaticLayout: true,
          readOnly: true,
          renderSideBySide: true,
          minimap: { enabled: false },
          scrollBeyondLastLine: false,
          wordWrap: "on"
        }}
      />
    </div>
  );
}
