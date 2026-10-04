async function request(path, options = {}) {
  const res = await fetch(`/api${path}`, {
    headers: { "Content-Type": "application/json" },
    ...options,
  });
  if (!res.ok) {
    const text = await res.text();
    throw new Error(`${res.status}: ${text}`);
  }
  return res.json();
}

export const api = {
  settings: () => request("/settings"),
  programs: (privateOnly) =>
    request(`/programs${privateOnly === undefined ? "" : `?private_only=${privateOnly}`}`),
  program: (id) => request(`/programs/${id}`),
  authorization: () => request("/authorization"),
  request: (id) => request(`/requests/${id}`),
  draft: (programId, recipient) =>
    request(`/programs/${programId}/authorization-request`, {
      method: "POST",
      body: JSON.stringify({ recipient: recipient || null }),
    }),
  markSent: (requestId) => request(`/requests/${requestId}/mark-sent`, { method: "POST" }),
  recordResponse: (programId, body, sender, subject) =>
    request(`/programs/${programId}/responses`, {
      method: "POST",
      body: JSON.stringify({ body, sender, subject }),
    }),
  applyResponse: (responseId) => request(`/responses/${responseId}/apply`, { method: "POST" }),
  scope: () => request("/scope"),
  researchReady: () => request("/research-ready"),
  blocked: () => request("/blocked"),
  notifications: () => request("/notifications"),
};
