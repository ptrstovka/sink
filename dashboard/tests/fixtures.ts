import type {
  BodyPreview,
  HeaderField,
  TrafficTransactionDetail,
  TrafficTransactionSummary,
} from '@/domain/traffic'

export const emptyBody = (): BodyPreview => ({
  kind: 'empty',
  contentType: null,
  text: null,
  transferredBytes: 0,
  retainedBytes: 0,
  truncated: false,
  completion: 'complete',
  retention: 'retained',
  constraints: { streaming: false, serverSentEvents: false, websocketUpgrade: false },
})

export const textBody = (text: string, kind: 'json' | 'text' = 'text'): BodyPreview => ({
  kind,
  contentType: kind === 'json' ? 'application/json' : 'text/plain; charset=utf-8',
  text,
  transferredBytes: text.length,
  retainedBytes: text.length,
  truncated: false,
  completion: 'complete',
  retention: 'retained',
  constraints: { streaming: false, serverSentEvents: false, websocketUpgrade: false },
})

export const visibleHeader = (id: string, name: string, value: string): HeaderField => ({
  id,
  name,
  value,
  sensitive: false,
})

export const maskedHeader = (id: string, name: string): HeaderField => ({
  id,
  name,
  sensitive: true,
  valueState: 'masked',
})

export function summary(
  id: string,
  receivedAt: string,
  overrides: Partial<TrafficTransactionSummary> = {},
): TrafficTransactionSummary {
  return {
    id,
    receivedAt,
    method: 'GET',
    url: `https://quiet-river.sink.test/${id}`,
    path: `/${id}`,
    origin: 'original',
    replaySourceId: null,
    state: 'complete',
    status: 200,
    error: null,
    durationMs: 12,
    requestBytes: 0,
    responseBytes: 2,
    replay: { eligible: true, reasonCode: null, reason: null },
    ...overrides,
  }
}

export function detail(
  transaction: TrafficTransactionSummary,
  overrides: Partial<TrafficTransactionDetail> = {},
): TrafficTransactionDetail {
  return {
    ...transaction,
    lifecycle: { state: 'completed' },
    responseStartedAfterMs: 4,
    request: {
      method: transaction.method,
      url: transaction.url,
      version: 'HTTP/1.1',
      headers: [visibleHeader('request:0', 'accept', 'application/json')],
      body: emptyBody(),
    },
    response: {
      status: transaction.status ?? 200,
      version: 'HTTP/1.1',
      headers: [visibleHeader('response:0', 'content-type', 'application/json')],
      body: textBody('{}', 'json'),
    },
    ...overrides,
  }
}

export const checkout = summary('tx-checkout', '2026-08-28T07:34:52.130Z', {
  method: 'POST',
  path: '/api/checkout?currency=EUR',
  url: 'https://quiet-river.sink.test/api/checkout?currency=EUR',
  status: 201,
  durationMs: 84,
})

export const avatar = summary('tx-avatar', '2026-08-28T07:34:44.010Z', {
  method: 'PUT',
  path: '/api/users/82/avatar',
  url: 'https://quiet-river.sink.test/api/users/82/avatar',
  status: 413,
  replay: {
    eligible: false,
    reasonCode: 'binary_request_body',
    reason: 'Binary request bodies are not retained for replay.',
  },
})

export const replay = summary('tx-health-replay', '2026-08-28T07:34:41.900Z', {
  path: '/health',
  url: 'https://quiet-river.sink.test/health',
  origin: 'replay',
  replaySourceId: 'tx-health-source',
  status: 204,
})

export const failed = summary('tx-failed', '2026-08-28T07:34:28.770Z', {
  path: '/api/inventory',
  url: 'https://quiet-river.sink.test/api/inventory',
  state: 'failed',
  status: null,
  error: 'Local service refused the connection',
})

export const summaries = [checkout, avatar, replay, failed] as const

export const checkoutDetail = detail(checkout, {
  request: {
    method: 'POST',
    url: checkout.url,
    version: 'HTTP/1.1',
    headers: [
      visibleHeader('request:0', 'content-type', 'application/json'),
      maskedHeader('request:1', 'authorization'),
    ],
    body: textBody('{"cartId":"cart_842"}', 'json'),
  },
  response: {
    status: 201,
    version: 'HTTP/1.1',
    headers: [maskedHeader('response:0', 'set-cookie')],
    body: textBody('{"accepted":true}', 'json'),
  },
})
