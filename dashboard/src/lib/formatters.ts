import type { TrafficTransactionSummary } from '@/domain/traffic'

const byteFormatter = new Intl.NumberFormat(undefined, { maximumFractionDigits: 1 })
const timeFormatter = new Intl.DateTimeFormat(undefined, {
  hour: '2-digit',
  minute: '2-digit',
  second: '2-digit',
  fractionalSecondDigits: 3,
})

export function formatBytes(bytes: number) {
  if (bytes < 1024) return `${bytes} B`
  if (bytes < 1024 ** 2) return `${byteFormatter.format(bytes / 1024)} KiB`
  return `${byteFormatter.format(bytes / 1024 ** 2)} MiB`
}

export function formatDuration(durationMs: number | null) {
  if (durationMs === null) return 'In progress'
  if (durationMs < 1000) return `${durationMs} ms`
  return `${(durationMs / 1000).toFixed(2)} s`
}

export function formatTime(timestamp: string) {
  return timeFormatter.format(new Date(timestamp))
}

export function statusLabel(transaction: TrafficTransactionSummary) {
  if (transaction.state === 'failed') return 'Error'
  if (transaction.status === null) return 'Pending'
  return String(transaction.status)
}

export function statusTone(transaction: TrafficTransactionSummary) {
  if (transaction.state === 'failed') return 'destructive' as const
  if (transaction.state === 'pending') return 'pending' as const
  if (transaction.status === null) return 'secondary' as const
  if (transaction.status >= 500) return 'destructive' as const
  if (transaction.status >= 400) return 'warning' as const
  if (transaction.status >= 300) return 'secondary' as const
  return 'success' as const
}
