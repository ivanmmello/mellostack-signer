const API_BASE = import.meta.env.VITE_API_BASE_URL ?? "http://localhost:8096";

export type SessionResponse = {
  sessionId: string;
  provider: string;
  environment: string;
  status: string;
  fileName: string;
  reason: string;
  location: string;
  visibleSignature: boolean;
  timestamp: boolean;
  authorized: boolean;
  signerCertificateSubject: string | null;
  validationValid: boolean | null;
  errorMessage: string | null;
  createdAt: string;
};

export type PrepareOptions = {
  provider: string;
  environment: string;
  reason: string;
  location: string;
  visibleSignature: boolean;
  timestamp: boolean;
};

export async function prepareSign(pdf: File, options: PrepareOptions): Promise<SessionResponse> {
  const form = new FormData();
  form.append("pdf", pdf);
  form.append("provider", options.provider);
  form.append("environment", options.environment);
  form.append("reason", options.reason);
  form.append("location", options.location);
  form.append("visibleSignature", String(options.visibleSignature));
  form.append("timestamp", String(options.timestamp));

  const response = await fetch(`${API_BASE}/api/v1/sign/prepare`, {
    method: "POST",
    body: form,
  });
  if (!response.ok) {
    throw new Error(await response.text());
  }
  return response.json();
}

export async function getSession(sessionId: string): Promise<SessionResponse> {
  const response = await fetch(`${API_BASE}/api/v1/sign/${sessionId}`);
  if (!response.ok) {
    throw new Error(await response.text());
  }
  return response.json();
}

export async function updateOptions(
  sessionId: string,
  options: Pick<PrepareOptions, "reason" | "location" | "visibleSignature" | "timestamp">,
): Promise<SessionResponse> {
  const response = await fetch(`${API_BASE}/api/v1/sign/${sessionId}/options`, {
    method: "PUT",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(options),
  });
  if (!response.ok) {
    throw new Error(await response.text());
  }
  return response.json();
}

export async function executeSign(sessionId: string): Promise<SessionResponse> {
  const response = await fetch(`${API_BASE}/api/v1/sign/${sessionId}/execute`, {
    method: "POST",
  });
  if (!response.ok) {
    throw new Error(await response.text());
  }
  return response.json();
}

export function authorizeUrl(sessionId: string): string {
  return `${API_BASE}/api/v1/oauth/authorize?sessionId=${encodeURIComponent(sessionId)}`;
}

export function downloadUrl(sessionId: string): string {
  return `${API_BASE}/api/v1/sign/${sessionId}/download`;
}

export async function healthCheck(): Promise<boolean> {
  try {
    const response = await fetch(`${API_BASE}/health`);
    return response.ok;
  } catch {
    return false;
  }
}
