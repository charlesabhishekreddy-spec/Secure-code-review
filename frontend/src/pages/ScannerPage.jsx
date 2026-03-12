import { useState } from "react";
import { useNavigate } from "react-router-dom";

import { scanCode, scanGitHubRepository, uploadCode } from "../api/client";
import { EditorWorkspace } from "../components/EditorWorkspace";
import { RepositoryScanForm } from "../components/RepositoryScanForm";
import { UploadZone } from "../components/UploadZone";
import { useScanContext } from "../context/ScanContext";
import { detectLanguageFromFilename, filenameForLanguage, languageOptions } from "../utils/language";

export function ScannerPage() {
  const navigate = useNavigate();
  const [repoUrl, setRepoUrl] = useState("");
  const { editorState, setEditorState, setResults, loading, setLoading, error, setError } = useScanContext();

  function updateCode(nextCode) {
    setEditorState((current) => ({
      ...current,
      code: nextCode,
      dirty: current.file ? nextCode !== current.originalFileCode : true
    }));
  }

  async function handleFileSelected(file) {
    const nextCode = await file.text();
    const nextLanguage = detectLanguageFromFilename(file.name);
    setEditorState({
      code: nextCode,
      language: nextLanguage,
      filename: file.name,
      file,
      originalFileCode: nextCode,
      dirty: false
    });
    setError("");
  }

  function handleClearFile() {
    setEditorState((current) => ({
      ...current,
      filename: filenameForLanguage(current.language),
      file: null,
      originalFileCode: "",
      dirty: false
    }));
  }

  async function handleScan() {
    if (!editorState.code.trim()) {
      setError("Paste code or upload a file before scanning.");
      return;
    }

    setLoading(true);
    setError("");

    try {
      const payload =
        editorState.file && !editorState.dirty
          ? await uploadCode(editorState.file)
          : await scanCode({
              code: editorState.code,
              language: editorState.language,
              filename: editorState.filename || filenameForLanguage(editorState.language)
            });

      setResults(payload);
      navigate("/results");
    } catch (scanError) {
      setError(scanError.message || "Scan failed.");
    } finally {
      setLoading(false);
    }
  }

  async function handleRepositoryScan() {
    if (!repoUrl.trim()) {
      setError("Enter a GitHub repository URL to scan.");
      return;
    }

    setLoading(true);
    setError("");

    try {
      const payload = await scanGitHubRepository(repoUrl.trim());
      setResults(payload);
      navigate("/results");
    } catch (scanError) {
      setError(scanError.message || "Repository scan failed.");
    } finally {
      setLoading(false);
    }
  }

  return (
    <div className="space-y-6">
      <section className="glass-panel p-6">
        <div className="flex flex-col gap-4 lg:flex-row lg:items-end lg:justify-between">
          <div>
            <p className="section-label">Scanner workspace</p>
            <h1 className="mt-4 text-3xl font-semibold text-white">Inspect code, uploads, and GitHub repositories</h1>
            <p className="mt-3 max-w-3xl text-sm leading-6 text-slate-300">
              The scanner reports exact lines, runs a three-stage review workflow, maps findings to OWASP categories,
              and returns secure patched replacements.
            </p>
          </div>

          <div className="flex flex-wrap items-center gap-3">
            <label className="flex items-center gap-3 rounded-2xl border border-white/10 bg-slate-950/30 px-4 py-3 text-sm text-slate-300">
              <span>Language</span>
              <select
                value={editorState.language}
                onChange={(event) =>
                  setEditorState((current) => ({
                    ...current,
                    language: event.target.value,
                    filename: current.file ? current.filename : filenameForLanguage(event.target.value)
                  }))
                }
                className="rounded-xl border border-white/10 bg-slate-900 px-3 py-2 text-sm text-white outline-none"
              >
                {languageOptions.map((option) => (
                  <option key={option.value} value={option.value}>
                    {option.label}
                  </option>
                ))}
              </select>
            </label>
            <button
              type="button"
              className="action-button bg-mint text-slate-950 hover:bg-cyan-300 disabled:cursor-not-allowed disabled:opacity-60"
              onClick={handleScan}
              disabled={loading}
            >
              {loading ? "Scanning..." : "Scan code"}
            </button>
          </div>
        </div>

        {error ? (
          <div className="mt-5 rounded-2xl border border-rose-400/30 bg-rose-500/10 px-4 py-3 text-sm text-rose-100">{error}</div>
        ) : null}
      </section>

      <div className="grid gap-6 xl:grid-cols-[1.2fr_0.8fr]">
        <EditorWorkspace
          code={editorState.code}
          language={editorState.language}
          filename={editorState.filename}
          onChange={updateCode}
        />
        <div className="space-y-6">
          <UploadZone
            activeFile={editorState.file}
            onFileSelected={handleFileSelected}
            onClear={handleClearFile}
            disabled={loading}
          />
          <RepositoryScanForm value={repoUrl} onChange={setRepoUrl} onSubmit={handleRepositoryScan} disabled={loading} />
          <section className="glass-panel p-5">
            <p className="text-sm font-semibold text-white">Scan behavior</p>
            <ul className="mt-4 space-y-3 text-sm leading-6 text-slate-300">
              <li>Exact line numbers for detected insecure patterns.</li>
              <li>OWASP Top 10 mapping for each finding.</li>
              <li>Severity-weighted security score from 0 to 100.</li>
              <li>Patched replacement code with one-click copy support.</li>
            </ul>
          </section>
        </div>
      </div>
    </div>
  );
}
