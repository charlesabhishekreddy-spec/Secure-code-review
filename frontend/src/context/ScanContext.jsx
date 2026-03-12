import { createContext, useContext, useEffect, useMemo, useState } from "react";

const demoSnippet = `import hashlib
import os

query = "SELECT * FROM users WHERE id=" + user_input
os.system("cat " + user_input)
digest = hashlib.md5(data.encode("utf-8")).hexdigest()
`;

const STORAGE_KEYS = {
  results: "codesentinel.results",
  history: "codesentinel.history",
  settings: "codesentinel.settings"
};

const defaultSessionSettings = {
  apiToken: "",
  autoOpenResults: true,
  showMonacoMarkers: true,
  repoPollIntervalMs: 2000,
  historyLimit: 8
};

const ScanContext = createContext(null);

function readStorage(key, fallback) {
  if (typeof window === "undefined") {
    return fallback;
  }

  try {
    const rawValue = window.localStorage.getItem(key);
    return rawValue ? JSON.parse(rawValue) : fallback;
  } catch {
    return fallback;
  }
}

function writeStorage(key, value) {
  if (typeof window === "undefined") {
    return;
  }

  try {
    window.localStorage.setItem(key, JSON.stringify(value));
  } catch {
    // Ignore storage quota failures and keep the in-memory state.
  }
}

function nextHistoryId() {
  if (typeof crypto !== "undefined" && typeof crypto.randomUUID === "function") {
    return crypto.randomUUID();
  }
  return `scan_${Date.now()}`;
}

export function ScanProvider({ children }) {
  const [editorState, setEditorState] = useState({
    code: demoSnippet,
    language: "python",
    filename: "demo.py",
    file: null,
    originalFileCode: "",
    dirty: false
  });
  const [results, setResults] = useState(() => readStorage(STORAGE_KEYS.results, null));
  const [scanHistory, setScanHistory] = useState(() => readStorage(STORAGE_KEYS.history, []));
  const [sessionSettings, setSessionSettings] = useState(() => ({
    ...defaultSessionSettings,
    ...readStorage(STORAGE_KEYS.settings, {})
  }));
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState("");

  useEffect(() => {
    writeStorage(STORAGE_KEYS.results, results);
  }, [results]);

  useEffect(() => {
    writeStorage(STORAGE_KEYS.history, scanHistory);
  }, [scanHistory]);

  useEffect(() => {
    writeStorage(STORAGE_KEYS.settings, sessionSettings);
  }, [sessionSettings]);

  function saveResults(payload, metadata = {}) {
    const historyLimit = Math.max(3, Math.min(20, Number(sessionSettings.historyLimit) || defaultSessionSettings.historyLimit));
    const entry = {
      id: nextHistoryId(),
      createdAt: new Date().toISOString(),
      source: payload?.source ?? {},
      summary: {
        securityScore: payload?.security_score ?? 0,
        totalVulnerabilities: payload?.total_vulnerabilities ?? 0,
        severityBreakdown: payload?.severity_breakdown ?? {},
        repository: payload?.source?.repository ?? null,
        filename: payload?.source?.filename ?? "pasted-code",
        mode: metadata.mode ?? "direct"
      },
      results: payload
    };

    setResults(payload);
    setScanHistory((current) => {
      const nextHistory = [entry, ...current.filter((item) => item.id !== entry.id)];
      return nextHistory.slice(0, historyLimit);
    });
  }

  function clearHistory() {
    setScanHistory([]);
  }

  function restoreHistoryEntry(entryId) {
    const entry = scanHistory.find((item) => item.id === entryId);
    if (entry) {
      setResults(entry.results);
    }
  }

  const value = useMemo(
    () => ({
      editorState,
      setEditorState,
      results,
      setResults,
      saveResults,
      scanHistory,
      clearHistory,
      restoreHistoryEntry,
      sessionSettings,
      setSessionSettings,
      loading,
      setLoading,
      error,
      setError
    }),
    [editorState, results, scanHistory, sessionSettings, loading, error]
  );

  return <ScanContext.Provider value={value}>{children}</ScanContext.Provider>;
}

export function useScanContext() {
  const context = useContext(ScanContext);
  if (!context) {
    throw new Error("useScanContext must be used inside ScanProvider");
  }
  return context;
}
