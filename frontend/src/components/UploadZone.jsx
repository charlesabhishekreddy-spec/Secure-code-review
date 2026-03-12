import { useRef, useState } from "react";

import { acceptedFileTypes } from "../utils/language";

export function UploadZone({ activeFile, onFileSelected, onClear, disabled }) {
  const inputRef = useRef(null);
  const [dragActive, setDragActive] = useState(false);

  async function consumeFiles(fileList) {
    const file = fileList?.[0];
    if (!file) {
      return;
    }
    await onFileSelected(file);
    setDragActive(false);
  }

  return (
    <section className="glass-panel p-5">
      <div
        className={`rounded-3xl border border-dashed px-5 py-8 text-center transition ${
          dragActive ? "border-mint bg-mint/10" : "border-white/15 bg-slate-950/30"
        }`}
        onDragOver={(event) => {
          event.preventDefault();
          setDragActive(true);
        }}
        onDragLeave={(event) => {
          event.preventDefault();
          setDragActive(false);
        }}
        onDrop={async (event) => {
          event.preventDefault();
          await consumeFiles(event.dataTransfer.files);
        }}
      >
        <p className="text-base font-semibold text-white">Drop a source file here</p>
        <p className="mt-2 text-sm text-slate-300">Supports .py, .js, .jsx, .ts, .tsx, and .java files.</p>
        <button
          type="button"
          className="action-button mt-5 bg-white/10 text-white hover:bg-white/15 disabled:cursor-not-allowed disabled:opacity-60"
          onClick={() => inputRef.current?.click()}
          disabled={disabled}
        >
          Choose file
        </button>
        <input
          ref={inputRef}
          type="file"
          accept={acceptedFileTypes}
          className="hidden"
          onChange={async (event) => consumeFiles(event.target.files)}
        />
      </div>

      <div className="mt-4 flex items-center justify-between gap-3 rounded-2xl border border-white/10 bg-slate-950/30 px-4 py-3">
        <div>
          <p className="text-xs uppercase tracking-[0.2em] text-slate-400">Uploaded file</p>
          <p className="text-sm font-medium text-white">{activeFile?.name || "None selected"}</p>
        </div>
        <button
          type="button"
          className="rounded-xl border border-white/10 px-3 py-2 text-xs font-semibold uppercase tracking-[0.2em] text-slate-300 transition hover:bg-white/5 hover:text-white"
          onClick={onClear}
          disabled={!activeFile || disabled}
        >
          Clear
        </button>
      </div>
    </section>
  );
}
