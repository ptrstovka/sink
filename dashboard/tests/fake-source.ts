import { vi } from 'vitest'
import type {
  CurlResult,
  InspectionEvent,
  TrafficEventHandlers,
  TrafficSource,
} from '@/api/traffic-source'
import type { HeaderRevealTarget, TrafficTransactionDetail, TrafficTransactionSummary } from '@/domain/traffic'
import { detail } from './fixtures'

export class FakeTrafficSource implements TrafficSource {
  summaries: TrafficTransactionSummary[] = []
  details = new Map<string, TrafficTransactionDetail>()
  paused = false
  handlers: TrafficEventHandlers | null = null

  startSession = vi.fn(async () => ({
    apiVersion: 'v1' as const,
    capture: { paused: this.paused },
  }))

  endSession = vi.fn()

  listTransactions = vi.fn(async () => ({
    transactions: [...this.summaries],
    capture: { paused: this.paused },
  }))

  getTransaction = vi.fn(async (id: string, _signal?: AbortSignal): Promise<TrafficTransactionDetail> => {
    const foundDetail = this.details.get(id)
    if (foundDetail) return foundDetail
    const foundSummary = this.summaries.find((item) => item.id === id)
    if (!foundSummary) throw new Error('not found')
    return detail(foundSummary)
  })

  subscribe = vi.fn((handlers: TrafficEventHandlers) => {
    this.handlers = handlers
    return vi.fn(() => {
      this.handlers = null
    })
  })

  revealHeader = vi.fn(async (_target: HeaderRevealTarget) => 'revealed-test-value')

  pauseCapture = vi.fn(async () => {
    this.paused = true
    return { paused: true }
  })

  resumeCapture = vi.fn(async () => {
    this.paused = false
    return { paused: false }
  })

  deleteTransaction = vi.fn(async (_id: string) => undefined)
  clearTransactions = vi.fn(async () => this.summaries.length)
  replayTransaction = vi.fn(async (_id: string) => 'tx-replayed-pending')
  generateCurl = vi.fn(async (_id: string, _includeSensitiveHeaders: boolean): Promise<CurlResult> => ({
    status: 'generated',
    command: "curl 'http://127.0.0.1:3000/'",
    containsSecrets: false,
  }))

  emit(event: InspectionEvent) {
    this.handlers?.event(event)
  }

  connection(state: 'open' | 'reconnecting') {
    this.handlers?.connection(state)
  }
}
