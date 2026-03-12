import { createContext, useContext, useState } from "react";

const demoSnippet = `import hashlib
import os

query = "SELECT * FROM users WHERE id=" + user_input
os.system("cat " + user_input)
digest = hashlib.md5(data.encode("utf-8")).hexdigest()
`;

const ScanContext = createContext(null);

export function ScanProvider({ children }) {
  const [editorState, setEditorState] = useState({
    code: demoSnippet,
    language: "python",
    filename: "demo.py",
    file: null,
    originalFileCode: "",
    dirty: false
  });
  const [results, setResults] = useState(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState("");

  return (
    <ScanContext.Provider
      value={{
        editorState,
        setEditorState,
        results,
        setResults,
        loading,
        setLoading,
        error,
        setError
      }}
    >
      {children}
    </ScanContext.Provider>
  );
}

export function useScanContext() {
  const context = useContext(ScanContext);
  if (!context) {
    throw new Error("useScanContext must be used inside ScanProvider");
  }
  return context;
}
