import { describe, expect, it, vi } from 'vitest'
import {
  createHttpTrafficSource,
  mapTransactionDetailDto,
  mapTransactionSummaryDto,
  TrafficSourceError,
} from '@/api/http-traffic-source'

const summaryDto = {
  id: '65f78dba-f386-4f34-8686-15ae9b521683',
  receivedAtUnixMs: 1_777_534_492_130,
  method: 'POST',
  url: 'https://quiet-river.sink.test/api/checkout?currency=EUR',
  path: '/api/checkout?currency=EUR',
  origin: 'original',
  state: 'complete',
  status: 201,
  error: null,
  durationMs: 84,
  requestBytes: 24,
  responseBytes: 17,
  replay: { eligible: true, reasonCode: null, reason: null },
}

const bodyDto = {
  kind: 'json',
  contentType: 'application/json',
  text: '{"ok":true}',
  transferredBytes: 11,
  retainedBytes: 11,
  truncated: false,
  completion: 'complete',
  retention: 'retained',
  constraints: { streaming: false, serverSentEvents: false, websocketUpgrade: false },
}

const detailDto = {
  ...summaryDto,
  lifecycle: { state: 'completed' },
  responseStartedAfterMs: 12,
  request: {
    method: 'POST',
    url: summaryDto.url,
    version: 'HTTP/1.1',
    headers: [
      { id: 'request:0', name: 'content-type', sensitive: false, value: 'application/json' },
      {
        id: 'request:1',
        name: 'authorization',
        sensitive: true,
        valueState: 'masked',
        sensitivity: 'authorization',
      },
    ],
    body: bodyDto,
  },
  response: {
    status: 201,
    version: 'HTTP/1.1',
    headers: [],
    body: bodyDto,
  },
}

function json(body: unknown, status = 200) {
  return new Response(JSON.stringify(body), {
    status,
    headers: { 'content-type': 'application/json' },
  })
}

describe('same-origin v1 adapter', () => {
  it('maps exact summary/detail DTOs and discards unexpected masked values', () => {
    const summary = mapTransactionSummaryDto(summaryDto)
    expect(summary).toMatchObject({
      id: summaryDto.id,
      receivedAt: '2026-04-30T07:34:52.130Z',
      replaySourceId: null,
      requestBytes: 24,
    })

    const rejectedSecret = 'Bearer must-never-enter-detail-state'
    const detail = mapTransactionDetailDto({
      ...detailDto,
      request: {
        ...detailDto.request,
        headers: [
          {
            ...detailDto.request.headers[1],
            value: rejectedSecret,
          },
        ],
      },
    })
    expect(JSON.stringify(detail)).not.toContain(rejectedSecret)
    expect(detail.request.headers[0]).toEqual({
      id: 'request:1',
      name: 'authorization',
      sensitive: true,
      valueState: 'masked',
      sensitivity: 'authorization',
    })
  })

  it('keeps the session token in the adapter and sends it only on protected fixed-relative actions', async () => {
    const calls: Array<{ url: string; init: RequestInit }> = []
    const fetcher = vi.fn(async (input: RequestInfo | URL, init: RequestInit = {}) => {
      const url = String(input)
      calls.push({ url, init })
      if (url === '/api/v1/session') {
        return json({
          apiVersion: 'v1',
          inspectorToken: 'memory-only-inspector-token',
          capture: { paused: false },
          eventsUrl: '/api/v1/events',
        })
      }
      if (url === '/api/v1/transactions' && init.method === undefined) {
        return json({ transactions: [summaryDto], capture: { paused: false } })
      }
      if (url.endsWith('/headers/request/1/reveal')) return json({ value: 'revealed-on-demand' })
      if (url.endsWith('/replay')) return json({ transactionId: 'replay-id' }, 202)
      if (url.endsWith('/curl')) {
        return json({ status: 'generated', command: "curl 'http://127.0.0.1:3000/'", containsSecrets: false })
      }
      if (url.endsWith('/capture/pause')) return json({ paused: true })
      if (url.endsWith('/capture/resume')) return json({ paused: false })
      if (url === '/api/v1/transactions' && init.method === 'DELETE') return json({ removed: 1 })
      if (init.method === 'DELETE') return json({ id: summaryDto.id, deleted: true })
      if (url.endsWith(summaryDto.id)) return json(detailDto)
      throw new Error('unexpected request')
    }) as unknown as typeof fetch
    const source = createHttpTrafficSource(fetcher, () => new FakeEventSource())

    const session = await source.startSession()
    expect(JSON.stringify(session)).not.toContain('memory-only-inspector-token')
    await source.listTransactions()
    await source.getTransaction(summaryDto.id)
    await source.revealHeader({
      transactionId: summaryDto.id,
      side: 'request',
      headerId: 'request:1',
    })
    await source.pauseCapture()
    await source.resumeCapture()
    await source.deleteTransaction(summaryDto.id)
    await source.clearTransactions()
    await source.replayTransaction(summaryDto.id)
    await source.generateCurl(summaryDto.id, false)

    for (const { url, init } of calls) {
      expect(url.startsWith('/api/v1/')).toBe(true)
      expect(init.credentials).toBe('same-origin')
      expect(init.mode).toBe('same-origin')
      expect(init.redirect).toBe('error')
      expect(init.cache).toBe('no-store')
      const token = new Headers(init.headers).get('x-sink-inspector-token')
      const protectedAction = init.method === 'POST' || init.method === 'DELETE'
      expect(token).toBe(protectedAction ? 'memory-only-inspector-token' : null)
    }
    expect(calls.find(({ url }) => url.endsWith('/headers/request/1/reveal'))).toBeDefined()
    expect(calls.find(({ url }) => url.endsWith('/curl'))?.init.body).toBe(
      '{"includeSensitiveHeaders":false}',
    )

    const callCount = calls.length
    source.endSession()
    await expect(source.pauseCapture()).rejects.toMatchObject({ kind: 'not_ready' })
    expect(calls).toHaveLength(callCount)
  })

  it('parses names-only cURL confirmation and retries with explicit consent', async () => {
    const rejectedSecret = 'Bearer must-not-surface-from-error'
    let curlCalls = 0
    const fetcher = vi.fn(async (input: RequestInfo | URL, init: RequestInit = {}) => {
      const url = String(input)
      if (url === '/api/v1/session') {
        return json({
          apiVersion: 'v1',
          inspectorToken: 'token',
          capture: { paused: false },
          eventsUrl: '/api/v1/events',
        })
      }
      curlCalls += 1
      if (curlCalls === 1) {
        return json(
          {
            status: 'confirmation_required',
            headerNames: ['authorization', 'cookie'],
            ignored: rejectedSecret,
          },
          409,
        )
      }
      expect(init.body).toBe('{"includeSensitiveHeaders":true}')
      return json({ status: 'generated', command: 'curl confirmed-command', containsSecrets: true })
    }) as unknown as typeof fetch
    const source = createHttpTrafficSource(fetcher, () => new FakeEventSource())
    await source.startSession()

    const confirmation = await source.generateCurl(summaryDto.id, false)
    expect(confirmation).toEqual({
      status: 'confirmation_required',
      headerNames: ['authorization', 'cookie'],
    })
    expect(JSON.stringify(confirmation)).not.toContain(rejectedSecret)
    await expect(source.generateCurl(summaryDto.id, true)).resolves.toEqual({
      status: 'generated',
      command: 'curl confirmed-command',
      containsSecrets: true,
    })
  })

  it('refreshes before protected actions and retries once if the token rotates between requests', async () => {
    let sessionGeneration = 0
    let revealAttempts = 0
    let curlAttempts = 0
    const fetcher = vi.fn(async (input: RequestInfo | URL, init: RequestInit = {}) => {
      const url = String(input)
      if (url === '/api/v1/session') {
        sessionGeneration += 1
        return json({
          apiVersion: 'v1',
          inspectorToken: `token-${sessionGeneration}`,
          capture: { paused: false },
          eventsUrl: '/api/v1/events',
        })
      }

      const token = new Headers(init.headers).get('x-sink-inspector-token')
      if (url.endsWith('/reveal')) {
        revealAttempts += 1
        if (token === 'token-2') {
          return json({ error: { code: 'invalid_inspector_token', message: 'stale token' } }, 403)
        }
        expect(token).toBe('token-3')
        return json({ value: 'revealed-after-refresh' })
      }
      if (url.endsWith('/curl')) {
        curlAttempts += 1
        if (token === 'token-4') {
          return json({ error: { code: 'invalid_inspector_token', message: 'stale token' } }, 403)
        }
        expect(token).toBe('token-5')
        return json({
          status: 'generated',
          command: "curl 'http://127.0.0.1:3000/'",
          containsSecrets: false,
        })
      }
      throw new Error('unexpected request')
    }) as unknown as typeof fetch
    const source = createHttpTrafficSource(fetcher, () => new FakeEventSource())
    await source.startSession()

    await expect(source.revealHeader({
      transactionId: summaryDto.id,
      side: 'request',
      headerId: 'request:1',
    })).resolves.toBe('revealed-after-refresh')
    await expect(source.generateCurl(summaryDto.id, false)).resolves.toMatchObject({
      status: 'generated',
    })

    expect(sessionGeneration).toBe(5)
    expect(revealAttempts).toBe(2)
    expect(curlAttempts).toBe(2)
  })

  it('uses EventSource reconnect and converts invalid events into a safe resync', () => {
    const eventSource = new FakeEventSource()
    const source = createHttpTrafficSource(vi.fn() as unknown as typeof fetch, (url) => {
      expect(url).toBe('/api/v1/events')
      return eventSource
    })
    const event = vi.fn()
    const connection = vi.fn()
    const close = source.subscribe({ event, connection })

    eventSource.onopen?.(new Event('open'))
    eventSource.dispatch('inspection', JSON.stringify({
      kind: 'transaction_removed',
      sequence: 7,
      id: summaryDto.id,
      cause: 'evicted',
    }))
    eventSource.onerror?.(new Event('error'))
    eventSource.dispatch('resync', '{secret-bearing-invalid-json')

    expect(connection).toHaveBeenNthCalledWith(1, 'open')
    expect(connection).toHaveBeenNthCalledWith(2, 'reconnecting')
    expect(event).toHaveBeenNthCalledWith(1, {
      kind: 'transaction_removed',
      sequence: 7,
      id: summaryDto.id,
      cause: 'evicted',
    })
    expect(event).toHaveBeenNthCalledWith(2, {
      kind: 'resync_required',
      skipped: 0,
      reason: 'invalid_event',
    })
    close()
    expect(eventSource.closed).toBe(true)
  })

  it('returns a generic error object without retaining a rejected response body', async () => {
    const rejectedSecret = 'server-body-secret'
    const source = createHttpTrafficSource(
      vi.fn(async () => new Response(rejectedSecret, { status: 500 })) as unknown as typeof fetch,
      () => new FakeEventSource(),
    )
    const rejection = await source.startSession().catch((error: unknown) => error)
    expect(rejection).toBeInstanceOf(TrafficSourceError)
    expect(String(rejection)).not.toContain(rejectedSecret)
    expect(JSON.stringify(rejection)).not.toContain(rejectedSecret)
  })
})

class FakeEventSource {
  onopen: ((event: Event) => void) | null = null
  onerror: ((event: Event) => void) | null = null
  closed = false
  private listeners = new Map<string, EventListener[]>()

  addEventListener(type: string, listener: EventListener) {
    const listeners = this.listeners.get(type) ?? []
    listeners.push(listener)
    this.listeners.set(type, listeners)
  }

  dispatch(type: string, data: string) {
    const event = new MessageEvent(type, { data })
    for (const listener of this.listeners.get(type) ?? []) listener(event)
  }

  close() {
    this.closed = true
  }
}
