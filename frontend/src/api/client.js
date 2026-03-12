const API_BASE_URL = import.meta.env.VITE_API_BASE_URL ?? "http://127.0.0.1:8000";

async function parseResponse(response) {
  const payload = await response.json().catch(() => ({
    detail: "Unexpected server response."
  }));

  if (!response.ok) {
    throw new Error(payload.detail || "Request failed.");
  }

  return payload;
}

function buildHeaders(apiToken, extraHeaders = {}) {
  const headers = { ...extraHeaders };
  if (apiToken?.trim()) {
    headers.Authorization = `Bearer ${apiToken.trim()}`;
  }
  return headers;
}

export async function scanCode(payload, options = {}) {
  const response = await fetch(`${API_BASE_URL}/scan`, {
    method: "POST",
    headers: buildHeaders(options.apiToken, {
      "Content-Type": "application/json"
    }),
    body: JSON.stringify(payload)
  });

  return parseResponse(response);
}

export async function uploadCode(file, options = {}) {
  const formData = new FormData();
  formData.append("file", file);

  const response = await fetch(`${API_BASE_URL}/upload`, {
    method: "POST",
    headers: buildHeaders(options.apiToken),
    body: formData
  });

  return parseResponse(response);
}

export async function scanGitHubRepository(repoUrl, branch, options = {}) {
  const body = { repo_url: repoUrl };
  if (branch?.trim()) {
    body.branch = branch.trim();
  }

  const response = await fetch(`${API_BASE_URL}/scan-github`, {
    method: "POST",
    headers: buildHeaders(options.apiToken, {
      "Content-Type": "application/json"
    }),
    body: JSON.stringify(body)
  });

  return parseResponse(response);
}

export async function submitGitHubScanJob(repoUrl, branch, options = {}) {
  const body = { repo_url: repoUrl };
  if (branch?.trim()) {
    body.branch = branch.trim();
  }

  const response = await fetch(`${API_BASE_URL}/scan-github/jobs`, {
    method: "POST",
    headers: buildHeaders(options.apiToken, {
      "Content-Type": "application/json"
    }),
    body: JSON.stringify(body)
  });

  return parseResponse(response);
}

export async function getScanJob(jobId, options = {}) {
  const response = await fetch(`${API_BASE_URL}/scan-jobs/${jobId}`, {
    method: "GET",
    headers: buildHeaders(options.apiToken)
  });

  return parseResponse(response);
}
