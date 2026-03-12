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

export async function scanCode(payload) {
  const response = await fetch(`${API_BASE_URL}/scan`, {
    method: "POST",
    headers: {
      "Content-Type": "application/json"
    },
    body: JSON.stringify(payload)
  });

  return parseResponse(response);
}

export async function uploadCode(file) {
  const formData = new FormData();
  formData.append("file", file);

  const response = await fetch(`${API_BASE_URL}/upload`, {
    method: "POST",
    body: formData
  });

  return parseResponse(response);
}

export async function scanGitHubRepository(repoUrl, branch) {
  const body = { repo_url: repoUrl };
  if (branch?.trim()) {
    body.branch = branch.trim();
  }

  const response = await fetch(`${API_BASE_URL}/scan-github`, {
    method: "POST",
    headers: {
      "Content-Type": "application/json"
    },
    body: JSON.stringify(body)
  });

  return parseResponse(response);
}
