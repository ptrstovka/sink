export const HTTP_METHODS = ['GET', 'POST', 'PUT', 'PATCH', 'DELETE', 'OPTIONS', 'HEAD'] as const

export type HttpMethod = (typeof HTTP_METHODS)[number] | (string & {})
export type TrafficOrigin = 'original' | 'replay'
export type TransactionState = 'complete' | 'pending' | 'failed'
export type PayloadKind = 'json' | 'text' | 'binary' | 'stream' | 'empty'
export type BodyCompletion = 'in_progress' | 'complete' | 'incomplete'
export type BodyRetention = 'retained' | 'truncated' | 'omitted_binary'
export type StatusClass = 'all' | '2xx' | '3xx' | '4xx' | '5xx' | 'error'
export type OriginFilter = 'all' | TrafficOrigin
export type MessageSide = 'request' | 'response'

export interface VisibleHeaderField {
  id: string
  name: string
  value: string
  sensitive: false
}

export interface MaskedHeaderField {
  id: string
  name: string
  sensitive: true
  valueState: 'masked'
  sensitivity?: string
}

export type HeaderField = VisibleHeaderField | MaskedHeaderField

export interface HeaderRevealTarget {
  transactionId: string
  side: MessageSide
  headerId: string
}

export interface BodyConstraints {
  streaming: boolean
  serverSentEvents: boolean
  websocketUpgrade: boolean
}

export interface BodyPreview {
  kind: PayloadKind
  contentType: string | null
  text: string | null
  transferredBytes: number
  retainedBytes: number
  truncated: boolean
  completion: BodyCompletion
  retention: BodyRetention
  constraints: BodyConstraints
}

export interface RequestSnapshot {
  method: HttpMethod
  url: string
  version: string
  headers: readonly HeaderField[]
  body: BodyPreview
}

export interface ResponseSnapshot {
  status: number
  version: string
  headers: readonly HeaderField[]
  body: BodyPreview
}

export interface ReplayEligibility {
  eligible: boolean
  reasonCode: string | null
  reason: string | null
}

export interface TrafficTransactionSummary {
  id: string
  receivedAt: string
  method: HttpMethod
  url: string
  path: string
  origin: TrafficOrigin
  replaySourceId: string | null
  state: TransactionState
  status: number | null
  error: string | null
  durationMs: number | null
  requestBytes: number
  responseBytes: number | null
  replay: ReplayEligibility
}

export interface TransactionLifecycle {
  state: 'received' | 'response_started' | 'completed' | 'failed_or_cancelled' | 'upgraded'
  kind?: 'failed' | 'cancelled'
}

export interface TrafficTransactionDetail extends TrafficTransactionSummary {
  lifecycle: TransactionLifecycle
  responseStartedAfterMs: number | null
  request: RequestSnapshot
  response: ResponseSnapshot | null
}

export interface InspectorFilters {
  search: string
  method: 'all' | HttpMethod
  status: StatusClass
  origin: OriginFilter
}

export const emptyFilters = (): InspectorFilters => ({
  search: '',
  method: 'all',
  status: 'all',
  origin: 'all',
})

export function statusClassOf(
  transaction: TrafficTransactionSummary,
): Exclude<StatusClass, 'all'> {
  if (transaction.state === 'failed' || transaction.status === null) return 'error'
  const group = Math.floor(transaction.status / 100)
  if (group < 2 || group > 5) return 'error'
  return `${group}xx` as Exclude<StatusClass, 'all' | 'error'>
}
