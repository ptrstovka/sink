import type {
  CurlResult,
  InspectionEvent,
  InspectorSession,
  TrafficEventHandlers,
  TrafficSource,
} from '@/api/traffic-source'
import type {
  BodyCompletion,
  BodyPreview,
  BodyRetention,
  HeaderField,
  HeaderRevealTarget,
  PayloadKind,
  TrafficOrigin,
  TrafficTransactionDetail,
  TrafficTransactionSummary,
  TransactionLifecycle,
  TransactionState,
} from '@/domain/traffic'

const API = Object.freeze({
  session: '/api/v1/session',
  transactions: '/api/v1/transactions',
  events: '/api/v1/events',
  pause: '/api/v1/capture/pause',
  resume: '/api/v1/capture/resume',
})

const TOKEN_HEADER = 'x-sink-inspector-token'

type FetchLike = typeof fetch

interface EventSourceLike {
  onopen: ((event: Event) => void) | null
  onerror: ((event: Event) => void) | null
  addEventListener(type: string, listener: EventListener): void
  close(): void
}

type EventSourceFactory = (url: string) => EventSourceLike

export class TrafficSourceError extends Error {
  constructor(readonly kind: 'network' | 'invalid_response' | 'request_failed' | 'not_ready') {
    super('Dashboard request failed')
    this.name = 'TrafficSourceError'
  }
}

function record(value: unknown): Record<string, unknown> {
  if (typeof value !== 'object' || value === null || Array.isArray(value)) {
    throw new TrafficSourceError('invalid_response')
  }
  return value as Record<string, unknown>
}

function string(value: unknown): string {
  if (typeof value !== 'string') throw new TrafficSourceError('invalid_response')
  return value
}

function finiteNumber(value: unknown): number {
  if (typeof value !== 'number' || !Number.isFinite(value) || value < 0) {
    throw new TrafficSourceError('invalid_response')
  }
  return value
}

function nullableNumber(value: unknown): number | null {
  return value === null ? null : finiteNumber(value)
}

function nullableString(value: unknown): string | null {
  return value === null || value === undefined ? null : string(value)
}

function boolean(value: unknown): boolean {
  if (typeof value !== 'boolean') throw new TrafficSourceError('invalid_response')
  return value
}

function oneOf<T extends string>(value: unknown, values: readonly T[]): T {
  const parsed = string(value)
  if (!values.includes(parsed as T)) throw new TrafficSourceError('invalid_response')
  return parsed as T
}

function mapReplay(value: unknown) {
  const dto = record(value)
  return {
    eligible: boolean(dto.eligible),
    reasonCode: nullableString(dto.reasonCode),
    reason: nullableString(dto.reason),
  }
}

export function mapTransactionSummaryDto(value: unknown): TrafficTransactionSummary {
  const dto = record(value)
  const receivedAt = new Date(finiteNumber(dto.receivedAtUnixMs))
  if (Number.isNaN(receivedAt.getTime())) throw new TrafficSourceError('invalid_response')

  return {
    id: string(dto.id),
    receivedAt: receivedAt.toISOString(),
    method: string(dto.method),
    url: string(dto.url),
    path: string(dto.path),
    origin: oneOf<TrafficOrigin>(dto.origin, ['original', 'replay']),
    replaySourceId: nullableString(dto.replaySourceId),
    state: oneOf<TransactionState>(dto.state, ['pending', 'complete', 'failed']),
    status: nullableNumber(dto.status),
    error: nullableString(dto.error),
    durationMs: nullableNumber(dto.durationMs),
    requestBytes: finiteNumber(dto.requestBytes),
    responseBytes: nullableNumber(dto.responseBytes),
    replay: mapReplay(dto.replay),
  }
}

function mapHeader(value: unknown): HeaderField {
  const dto = record(value)
  const sensitive = boolean(dto.sensitive)
  const base = { id: string(dto.id), name: string(dto.name) }
  if (sensitive) {
    // Never let an unexpected sensitive value cross the initial detail boundary.
    return {
      ...base,
      sensitive: true,
      valueState: 'masked',
      ...(typeof dto.sensitivity === 'string' ? { sensitivity: dto.sensitivity } : {}),
    }
  }
  return { ...base, sensitive: false, value: string(dto.value) }
}

function mapBody(value: unknown): BodyPreview {
  const dto = record(value)
  const constraints = record(dto.constraints)
  return {
    kind: oneOf<PayloadKind>(dto.kind, ['json', 'text', 'binary', 'stream', 'empty']),
    contentType: nullableString(dto.contentType),
    text: nullableString(dto.text),
    transferredBytes: finiteNumber(dto.transferredBytes),
    retainedBytes: finiteNumber(dto.retainedBytes),
    truncated: boolean(dto.truncated),
    completion: oneOf<BodyCompletion>(dto.completion, ['in_progress', 'complete', 'incomplete']),
    retention: oneOf<BodyRetention>(dto.retention, ['retained', 'truncated', 'omitted_binary']),
    constraints: {
      streaming: boolean(constraints.streaming),
      serverSentEvents: boolean(constraints.serverSentEvents),
      websocketUpgrade: boolean(constraints.websocketUpgrade),
    },
  }
}

function mapHeaders(value: unknown): readonly HeaderField[] {
  if (!Array.isArray(value)) throw new TrafficSourceError('invalid_response')
  return value.map(mapHeader)
}

function mapLifecycle(value: unknown): TransactionLifecycle {
  const dto = record(value)
  const state = oneOf<TransactionLifecycle['state']>(dto.state, [
    'received',
    'response_started',
    'completed',
    'failed_or_cancelled',
    'upgraded',
  ])
  if (state !== 'failed_or_cancelled') return { state }
  return { state, kind: oneOf<'failed' | 'cancelled'>(dto.kind, ['failed', 'cancelled']) }
}

export function mapTransactionDetailDto(value: unknown): TrafficTransactionDetail {
  const dto = record(value)
  const request = record(dto.request)
  const response = dto.response === null ? null : record(dto.response)
  return {
    ...mapTransactionSummaryDto(dto),
    lifecycle: mapLifecycle(dto.lifecycle),
    responseStartedAfterMs: nullableNumber(dto.responseStartedAfterMs),
    request: {
      method: string(request.method),
      url: string(request.url),
      version: string(request.version),
      headers: mapHeaders(request.headers),
      body: mapBody(request.body),
    },
    response:
      response === null
        ? null
        : {
            status: finiteNumber(response.status),
            version: string(response.version),
            headers: mapHeaders(response.headers),
            body: mapBody(response.body),
          },
  }
}

function parseInspectionEvent(value: unknown): InspectionEvent {
  const dto = record(value)
  const kind = string(dto.kind)
  if (kind === 'resync_required') {
    return {
      kind,
      skipped: finiteNumber(dto.skipped),
      reason: oneOf(dto.reason, ['connection_opened', 'lagged']),
    }
  }
  const sequence = finiteNumber(dto.sequence)
  if (kind === 'transaction_created' || kind === 'transaction_updated') {
    return { kind, sequence, id: string(dto.id) }
  }
  if (kind === 'transaction_removed') {
    return { kind, sequence, id: string(dto.id), cause: oneOf(dto.cause, ['deleted', 'evicted']) }
  }
  if (kind === 'cleared') return { kind, sequence, removed: finiteNumber(dto.removed) }
  if (kind === 'capture_state_changed') return { kind, sequence, paused: boolean(dto.paused) }
  throw new TrafficSourceError('invalid_response')
}

async function safeJson(response: Response): Promise<unknown> {
  try {
    return await response.json()
  } catch {
    throw new TrafficSourceError('invalid_response')
  }
}

function headerIndex(target: HeaderRevealTarget): string {
  const [side, index, extra] = target.headerId.split(':')
  if (side !== target.side || extra !== undefined || !/^\d+$/.test(index ?? '')) {
    throw new TrafficSourceError('invalid_response')
  }
  return index!
}

export function createHttpTrafficSource(
  fetcher: FetchLike = globalThis.fetch.bind(globalThis),
  eventSourceFactory: EventSourceFactory = (url) => new EventSource(url),
): TrafficSource {
  let inspectorToken: string | null = null
  let protectedRequests = new AbortController()
  let sessionRefresh: Promise<InspectorSession> | null = null

  async function fetchSameOrigin(
    path: string,
    init: RequestInit = {},
    token: string | null = null,
  ): Promise<Response> {
    const headers = new Headers(init.headers)
    headers.set('accept', 'application/json')
    if (token !== null) headers.set(TOKEN_HEADER, token)
    try {
      return await fetcher(path, {
        ...init,
        headers,
        credentials: 'same-origin',
        mode: 'same-origin',
        redirect: 'error',
        cache: 'no-store',
      })
    } catch {
      throw new TrafficSourceError('network')
    }
  }

  async function loadSession(signal?: AbortSignal): Promise<InspectorSession> {
    const response = await fetchSameOrigin(API.session, { signal })
    if (!response.ok) throw new TrafficSourceError('request_failed')
    const dto = record(await safeJson(response))
    const token = string(dto.inspectorToken)
    const capture = record(dto.capture)
    if (string(dto.apiVersion) !== 'v1' || token.length === 0 || string(dto.eventsUrl) !== API.events) {
      throw new TrafficSourceError('invalid_response')
    }
    inspectorToken = token
    return { apiVersion: 'v1', capture: { paused: boolean(capture.paused) } }
  }

  async function refreshSession(): Promise<InspectorSession> {
    sessionRefresh ??= loadSession(protectedRequests.signal).finally(() => {
      sessionRefresh = null
    })
    return sessionRefresh
  }

  async function rejectedStaleToken(response: Response): Promise<boolean> {
    if (response.status !== 403) return false
    try {
      const dto = record(await safeJson(response.clone()))
      return record(dto.error).code === 'invalid_inspector_token'
    } catch {
      return false
    }
  }

  async function protectedRequest(path: string, init: RequestInit): Promise<Response> {
    if (inspectorToken === null) throw new TrafficSourceError('not_ready')
    // A dashboard tab can outlive the client process that issued its token. Refreshing
    // immediately before a mutation avoids relying on browser-specific 403 handling.
    await refreshSession()
    if (inspectorToken === null) throw new TrafficSourceError('not_ready')
    const protectedInit = init.signal === undefined
      ? { ...init, signal: protectedRequests.signal }
      : init
    let response = await fetchSameOrigin(path, protectedInit, inspectorToken)
    if (await rejectedStaleToken(response)) {
      await refreshSession()
      if (inspectorToken === null) throw new TrafficSourceError('not_ready')
      response = await fetchSameOrigin(path, protectedInit, inspectorToken)
    }
    return response
  }

  async function request(
    path: string,
    init: RequestInit = {},
    protectedAction = false,
  ): Promise<Response> {
    const response = protectedAction
      ? await protectedRequest(path, init)
      : await fetchSameOrigin(path, init)
    if (!response.ok) throw new TrafficSourceError('request_failed')
    return response
  }

  async function protectedJson(path: string, method: 'POST' | 'DELETE', body?: string) {
    const headers = body === undefined ? undefined : { 'content-type': 'application/json' }
    return request(path, { method, headers, body }, true)
  }

  return {
    async startSession(signal) {
      protectedRequests.abort()
      protectedRequests = new AbortController()
      inspectorToken = null
      sessionRefresh = null
      return loadSession(signal)
    },

    endSession() {
      protectedRequests.abort()
      inspectorToken = null
      sessionRefresh = null
    },

    async listTransactions(signal) {
      const dto = record(await safeJson(await request(API.transactions, { signal })))
      if (!Array.isArray(dto.transactions)) throw new TrafficSourceError('invalid_response')
      const capture = record(dto.capture)
      return {
        transactions: dto.transactions.map(mapTransactionSummaryDto),
        capture: { paused: boolean(capture.paused) },
      }
    },

    async getTransaction(id, signal) {
      return mapTransactionDetailDto(
        await safeJson(await request(`${API.transactions}/${encodeURIComponent(id)}`, { signal })),
      )
    },

    subscribe(handlers: TrafficEventHandlers) {
      const source = eventSourceFactory(API.events)
      source.onopen = () => handlers.connection('open')
      source.onerror = () => handlers.connection('reconnecting')
      const receive = (event: Event) => {
        let parsed: InspectionEvent
        try {
          const message = event as MessageEvent<string>
          parsed = parseInspectionEvent(JSON.parse(message.data))
        } catch {
          parsed = { kind: 'resync_required', skipped: 0, reason: 'invalid_event' }
        }
        handlers.event(parsed)
      }
      source.addEventListener('inspection', receive)
      source.addEventListener('resync', receive)
      return () => source.close()
    },

    async revealHeader(target) {
      const index = headerIndex(target)
      const path = `${API.transactions}/${encodeURIComponent(target.transactionId)}/headers/${target.side}/${index}/reveal`
      const dto = record(await safeJson(await protectedJson(path, 'POST')))
      return string(dto.value)
    },

    async pauseCapture() {
      const dto = record(await safeJson(await protectedJson(API.pause, 'POST')))
      return { paused: boolean(dto.paused) }
    },

    async resumeCapture() {
      const dto = record(await safeJson(await protectedJson(API.resume, 'POST')))
      return { paused: boolean(dto.paused) }
    },

    async deleteTransaction(id) {
      await protectedJson(`${API.transactions}/${encodeURIComponent(id)}`, 'DELETE')
    },

    async clearTransactions() {
      const response = await protectedJson(
        API.transactions,
        'DELETE',
        JSON.stringify({ confirm: true }),
      )
      const dto = record(await safeJson(response))
      return finiteNumber(dto.removed)
    },

    async replayTransaction(id) {
      const dto = record(
        await safeJson(
          await protectedJson(`${API.transactions}/${encodeURIComponent(id)}/replay`, 'POST'),
        ),
      )
      return string(dto.transactionId)
    },

    async generateCurl(id, includeSensitiveHeaders): Promise<CurlResult> {
      const response = await protectedRequest(
        `${API.transactions}/${encodeURIComponent(id)}/curl`,
        {
          method: 'POST',
          headers: { 'content-type': 'application/json' },
          body: JSON.stringify({ includeSensitiveHeaders }),
        },
      )

      if (response.status === 409) {
        const dto = record(await safeJson(response))
        if (dto.status !== 'confirmation_required' || !Array.isArray(dto.headerNames)) {
          throw new TrafficSourceError('invalid_response')
        }
        if (dto.headerNames.length > 64) throw new TrafficSourceError('invalid_response')
        const headerNames = dto.headerNames.map(string)
        if (headerNames.some((name) => !/^[!#$%&'*+\-.^_`|~0-9A-Za-z]{1,128}$/.test(name))) {
          throw new TrafficSourceError('invalid_response')
        }
        return {
          status: 'confirmation_required',
          headerNames,
        }
      }
      if (!response.ok) throw new TrafficSourceError('request_failed')
      const dto = record(await safeJson(response))
      if (dto.status !== 'generated') throw new TrafficSourceError('invalid_response')
      return {
        status: 'generated',
        command: string(dto.command),
        containsSecrets: boolean(dto.containsSecrets),
      }
    },
  }
}

export const httpTrafficSource = createHttpTrafficSource()
