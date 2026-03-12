export const acceptedFileTypes = ".py,.js,.jsx,.java,.ts,.tsx";

export const languageOptions = [
  { label: "Python", value: "python" },
  { label: "JavaScript", value: "javascript" },
  { label: "Java", value: "java" },
  { label: "TypeScript", value: "typescript" }
];

export function detectLanguageFromFilename(filename = "") {
  const extension = filename.split(".").pop()?.toLowerCase();

  if (extension === "py") {
    return "python";
  }
  if (extension === "js" || extension === "jsx") {
    return "javascript";
  }
  if (extension === "java") {
    return "java";
  }
  if (extension === "ts" || extension === "tsx") {
    return "typescript";
  }

  return "javascript";
}

export function filenameForLanguage(language) {
  if (language === "python") {
    return "snippet.py";
  }
  if (language === "java") {
    return "Snippet.java";
  }
  if (language === "typescript") {
    return "snippet.ts";
  }
  return "snippet.js";
}

export function severityTone(severity) {
  if (severity === "CRITICAL") {
    return "bg-rose-500/15 text-rose-200 ring-1 ring-rose-400/30";
  }
  if (severity === "HIGH") {
    return "bg-orange-500/15 text-orange-100 ring-1 ring-orange-300/30";
  }
  if (severity === "MEDIUM") {
    return "bg-amber-500/15 text-amber-100 ring-1 ring-amber-300/30";
  }
  return "bg-sky-500/15 text-sky-100 ring-1 ring-sky-300/30";
}
