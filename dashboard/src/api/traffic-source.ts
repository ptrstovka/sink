import type {
  HeaderRevealTarget,
  TrafficTransactionDetail,
  TrafficTransactionSummary,
} from '@/domain/traffic'
import type { InjectionKey } from 'vue'

export interface CaptureState {
  paused: boolean
}

export interface InspectorSession {
  apiVersion: 'v1'
  capture: CaptureState
}

export type RemovalCause = 'deleted' | 'evicted'
export type ResyncReason = 'connection_opened' | 'lagged' | 'invalid_event'

export type InspectionEvent =
  | { kind: 'transaction_created'; sequence: number; id: string }
  | { kind: 'transaction_updated'; sequence: number; id: string }
  | { kind: 'transaction_removed'; sequence: number; id: string; cause: RemovalCause }
  | { kind: 'cleared'; sequence: number; removed: number }
  | { kind: 'capture_state_changed'; sequence: number; paused: boolean }
  | { kind: 'resync_required'; skipped: number; reason: ResyncReason }

export interface TrafficEventHandlers {
  event(event: InspectionEvent): void
  connection(state: 'open' | 'reconnecting'): void
}

export interface CurlGenerated {
  status: 'generated'
  command: string
  containsSecrets: boolean
}

export interface CurlConfirmationRequired {
  status: 'confirmation_required'
  headerNames: readonly string[]
}

export type CurlResult = CurlGenerated | CurlConfirmationRequired

/** Same-origin dashboard API boundary. Implementations must keep the session token private. */
export interface TrafficSource {
  startSession(signal?: AbortSignal): Promise<InspectorSession>
  endSession(): void
  listTransactions(signal?: AbortSignal): Promise<{
    transactions: readonly TrafficTransactionSummary[]
    capture: CaptureState
  }>
  getTransaction(id: string, signal?: AbortSignal): Promise<TrafficTransactionDetail>
  subscribe(handlers: TrafficEventHandlers): () => void
  revealHeader(target: HeaderRevealTarget): Promise<string>
  pauseCapture(): Promise<CaptureState>
  resumeCapture(): Promise<CaptureState>
  deleteTransaction(id: string): Promise<void>
  clearTransactions(): Promise<number>
  replayTransaction(id: string): Promise<string>
  generateCurl(id: string, includeSensitiveHeaders: boolean): Promise<CurlResult>
}

export const trafficSourceKey: InjectionKey<TrafficSource> = Symbol('sink-traffic-source')
