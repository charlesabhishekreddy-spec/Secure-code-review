import Editor from "@monaco-editor/react";
import { useEffect, useRef } from "react";

function severityToMonaco(monaco, severity) {
  if (!monaco) {
    return 4;
  }
  if (severity === "CRITICAL" || severity === "HIGH") {
    return monaco.MarkerSeverity.Error;
  }
  if (severity === "MEDIUM") {
    return monaco.MarkerSeverity.Warning;
  }
  return monaco.MarkerSeverity.Info;
}

export function EditorWorkspace({ code, language, filename, markers = [], onChange }) {
  const editorRef = useRef(null);
  const monacoRef = useRef(null);

  useEffect(() => {
    const editor = editorRef.current;
    const monaco = monacoRef.current;
    if (!editor || !monaco) {
      return;
    }

    const model = editor.getModel();
    if (!model) {
      return;
    }

    monaco.editor.setModelMarkers(
      model,
      "codesentinel",
      markers.map((item) => ({
        startLineNumber: Math.max(Number(item.line) || 1, 1),
        endLineNumber: Math.max(Number(item.line) || 1, 1),
        startColumn: 1,
        endColumn: Math.max(String(item.snippet || "").length, 1),
        severity: severityToMonaco(monaco, item.severity),
        message: `${item.type} (${item.severity})${item.fix ? `\n${item.fix}` : ""}`
      }))
    );
  }, [markers, code]);

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
        onMount={(editor, monaco) => {
          editorRef.current = editor;
          monacoRef.current = monaco;
        }}
        onChange={(value) => onChange(value ?? "")}
        options={{
          automaticLayout: true,
          fontSize: 14,
          minimap: { enabled: false },
          scrollBeyondLastLine: false,
          smoothScrolling: true,
          wordWrap: "on",
          padding: { top: 16 },
          glyphMargin: true
        }}
      />
    </section>
  );
}
