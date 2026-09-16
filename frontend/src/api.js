/**
 * Backend client.
 *
 * All URLs are relative: Vite proxies /api to the FastAPI server in development,
 * so the browser never makes a cross-origin request and a CORS misconfiguration
 * cannot silently break a demo.
 */

async function request(path, options = {}) {
  const response = await fetch(path, {
    headers: { 'Content-Type': 'application/json' },
    ...options,
  })

  if (!response.ok) {
    // 202 means "accepted, still running" for result endpoints — a legitimate
    // state, not a failure.
    if (response.status === 202) return { pending: true }
    let detail = `Request failed (${response.status})`
    try {
      const body = await response.json()
      detail = body.detail || detail
    } catch {
      /* response had no JSON body */
    }
    throw new Error(detail)
  }

  return response.json()
}

export const api = {
  health: () => request('/api/health'),
  modelCard: () => request('/api/model'),
  signals: () => request('/api/signals'),

  scanProject: (path, includeDev = false, maxPackages = null) =>
    request('/api/scans/project', {
      method: 'POST',
      body: JSON.stringify({ path, include_dev: includeDev, max_packages: maxPackages }),
    }),

  scanManifest: (manifest, filename, projectRoot = null, includeDev = false) =>
    request('/api/scans/manifest', {
      method: 'POST',
      body: JSON.stringify({
        manifest,
        filename,
        project_root: projectRoot || null,
        include_dev: includeDev,
      }),
    }),

  scanPackage: (name, version, ecosystem) =>
    request('/api/scans/package', {
      method: 'POST',
      body: JSON.stringify({ name, version, ecosystem }),
    }),

  status: (scanId) => request(`/api/scans/${scanId}/status`),
  result: (scanId) => request(`/api/scans/${scanId}`),
  history: (limit = 25) => request(`/api/scans?limit=${limit}`),
  remove: (scanId) => request(`/api/scans/${scanId}`, { method: 'DELETE' }),

  samples: (query = '', limit = 40) =>
    request(`/api/samples?query=${encodeURIComponent(query)}&limit=${limit}`),
  scanSample: (name, ecosystem) =>
    request('/api/samples/scan', { method: 'POST', body: JSON.stringify({ name, ecosystem }) }),
}

/**
 * Chat with the analysis assistant.
 *
 * The backend streams newline-delimited JSON events (text / tool / tool_result /
 * error / done); each parsed event is passed to `onEvent` as it arrives.
 */
export async function streamAssistant(messages, scanId, onEvent, signal) {
  const response = await fetch('/api/assistant/chat', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ messages, scan_id: scanId || null }),
    signal,
  })

  if (!response.ok) {
    let detail = `Request failed (${response.status})`
    try {
      const body = await response.json()
      detail = body.detail || detail
    } catch {
      /* no JSON body */
    }
    throw new Error(detail)
  }

  const reader = response.body.getReader()
  const decoder = new TextDecoder()
  let buffer = ''
  for (;;) {
    const { value, done } = await reader.read()
    if (done) break
    buffer += decoder.decode(value, { stream: true })
    let newline
    while ((newline = buffer.indexOf('\n')) >= 0) {
      const line = buffer.slice(0, newline).trim()
      buffer = buffer.slice(newline + 1)
      if (line) onEvent(JSON.parse(line))
    }
  }
  if (buffer.trim()) onEvent(JSON.parse(buffer))
}

/**
 * Poll a scan to completion.
 *
 * Deliberately bounded: a runaway poll loop against a stuck job would hammer the
 * backend forever and look like a hang rather than an error.
 */
export async function pollScan(scanId, onProgress, { intervalMs = 900, maxMs = 15 * 60 * 1000 } = {}) {
  const deadline = Date.now() + maxMs

  while (Date.now() < deadline) {
    const status = await api.status(scanId)
    onProgress?.(status)

    if (status.status === 'completed') return api.result(scanId)
    if (status.status === 'failed') {
      throw new Error(status.error || 'Scan failed')
    }
    await new Promise((resolve) => setTimeout(resolve, intervalMs))
  }

  throw new Error('Scan timed out while waiting for results')
}
