import { computed, readonly, ref, shallowRef, watch } from 'vue'
import { useClipboard } from '@vueuse/core'
import type { InspectionEvent, TrafficSource } from '@/api/traffic-source'
import { useInspector } from '@/composables/use-inspector'
import type { HeaderField, MessageSide, TrafficTransactionDetail } from '@/domain/traffic'

export type InitialState = 'loading' | 'ready' | 'error'
export type ConnectionState = 'connecting' | 'open' | 'reconnecting'
export type DetailState = 'idle' | 'loading' | 'ready' | 'error'

export interface Feedback {
  kind: 'success' | 'error' | 'info'
  message: string
}

export interface CurlConfirmation {
  transactionId: string
  headerNames: readonly string[]
}

export interface GeneratedCurl {
  transactionId: string
  command: string
  containsSecrets: boolean
}

export interface ClipboardWriter {
  copy(text: string): Promise<void>
}

export function useLiveInspector(
  source: TrafficSource,
  clipboard: ClipboardWriter = useClipboard({ legacy: true }),
) {
  const inspector = useInspector()
  const initialState = ref<InitialState>('loading')
  const connectionState = ref<ConnectionState>('connecting')
  const syncError = ref(false)
  const syncing = ref(false)
  const capturePaused = ref(false)
  const selectedDetail = shallowRef<TrafficTransactionDetail | null>(null)
  const detailState = ref<DetailState>('idle')
  const actionPending = ref<string | null>(null)
  const feedback = ref<Feedback | null>(null)
  const curlConfirmation = ref<CurlConfirmation | null>(null)
  const generatedCurl = ref<GeneratedCurl | null>(null)

  const detailCache = new Map<string, TrafficTransactionDetail>()
  let sessionAbort: AbortController | null = null
  let detailAbort: AbortController | null = null
  let unsubscribe: (() => void) | null = null
  let detailRequest = 0
  let lastSequence = 0
  let resyncPromise: Promise<void> | null = null
  let resyncAgain = false
  let invalidateSelectedOnSync = false
  let pendingReplayId: string | null = null
  let startRequest = 0

  const selectedSummary = inspector.selectedTransaction
  const isOffline = computed(() => connectionState.value === 'reconnecting' || syncError.value)

  function announce(kind: Feedback['kind'], message: string) {
    feedback.value = { kind, message }
  }

  function invalidateSelectedDetail() {
    const id = inspector.selectedId.value
    if (id === null) return
    detailCache.delete(id)
    detailAbort?.abort()
    detailRequest += 1
    selectedDetail.value = null
    detailState.value = 'loading'
  }

  function clearFeedback() {
    feedback.value = null
  }

  async function loadDetail(id: string, force = false) {
    detailAbort?.abort()
    const request = ++detailRequest
    if (!force) {
      const cached = detailCache.get(id)
      if (cached) {
        selectedDetail.value = cached
        detailState.value = 'ready'
        return
      }
    }

    selectedDetail.value = null
    detailState.value = 'loading'
    const abort = new AbortController()
    detailAbort = abort
    try {
      const detail = await source.getTransaction(id, abort.signal)
      if (request !== detailRequest || inspector.selectedId.value !== id) return
      detailCache.clear()
      detailCache.set(id, detail)
      selectedDetail.value = detail
      detailState.value = 'ready'
    } catch {
      if (abort.signal.aborted || request !== detailRequest) return
      selectedDetail.value = null
      detailState.value = 'error'
    }
  }

  watch(
    inspector.selectedId,
    (id) => {
      curlConfirmation.value = null
      generatedCurl.value = null
      detailAbort?.abort()
      detailRequest += 1
      detailCache.clear()
      selectedDetail.value = null
      detailState.value = id === null ? 'idle' : 'loading'
      if (id !== null) void loadDetail(id)
    },
    { flush: 'sync' },
  )

  function reconcileList(
    transactions: Awaited<ReturnType<TrafficSource['listTransactions']>>['transactions'],
  ) {
    const retainedIds = new Set(transactions.map(({ id }) => id))
    for (const id of detailCache.keys()) {
      if (!retainedIds.has(id)) detailCache.delete(id)
    }

    inspector.replaceTransactions(transactions)
    if (pendingReplayId && retainedIds.has(pendingReplayId)) {
      const replayId = pendingReplayId
      pendingReplayId = null
      inspector.selectTransaction(replayId)
      announce('success', 'Replay started and selected.')
    }
  }

  function requestResync(invalidateSelected = false): Promise<void> {
    if (invalidateSelected) invalidateSelectedDetail()
    invalidateSelectedOnSync ||= invalidateSelected
    if (resyncPromise) {
      resyncAgain = true
      return resyncPromise
    }

    const owner = startRequest
    let current!: Promise<void>
    current = (async () => {
      syncing.value = true
      try {
        do {
          resyncAgain = false
          const shouldInvalidate = invalidateSelectedOnSync
          invalidateSelectedOnSync = false
          const result = await source.listTransactions(sessionAbort?.signal)
          if (owner !== startRequest) return
          capturePaused.value = result.capture.paused
          const selectedBeforeReconcile = inspector.selectedId.value
          reconcileList(result.transactions)
          const selectedId = inspector.selectedId.value
          if (shouldInvalidate && selectedId !== null && selectedId === selectedBeforeReconcile) {
            detailCache.delete(selectedId)
            await loadDetail(selectedId, true)
          }
          syncError.value = false
        } while (resyncAgain)
      } catch {
        if (owner !== startRequest) return
        syncError.value = true
        throw new Error('sync_failed')
      } finally {
        if (resyncPromise === current) {
          syncing.value = false
          resyncPromise = null
        }
      }
    })()
    resyncPromise = current
    return current
  }

  function resyncSafely(invalidateSelected = false) {
    void requestResync(invalidateSelected).catch(() => undefined)
  }

  function sequenceNeedsResync(event: Exclude<InspectionEvent, { kind: 'resync_required' }>) {
    const gap = lastSequence > 0 && event.sequence > lastSequence + 1
    if (event.sequence <= lastSequence) return { ignore: true, gap: false }
    lastSequence = event.sequence
    return { ignore: false, gap }
  }

  function handleEvent(event: InspectionEvent) {
    if (event.kind === 'resync_required') {
      resyncSafely(true)
      return
    }
    const sequence = sequenceNeedsResync(event)
    if (sequence.ignore) return
    if (sequence.gap) resyncSafely(true)

    switch (event.kind) {
      case 'transaction_created':
        resyncSafely(false)
        break
      case 'transaction_updated':
        resyncSafely(event.id === inspector.selectedId.value)
        break
      case 'transaction_removed':
        detailCache.delete(event.id)
        inspector.removeTransaction(event.id)
        break
      case 'cleared':
        detailCache.clear()
        inspector.clearTransactions()
        break
      case 'capture_state_changed':
        capturePaused.value = event.paused
        break
    }
  }

  function teardown() {
    sessionAbort?.abort()
    detailAbort?.abort()
    source.endSession()
    sessionAbort = null
    detailAbort = null
    unsubscribe?.()
    unsubscribe = null
    resyncPromise = null
    resyncAgain = false
    invalidateSelectedOnSync = false
    syncing.value = false
    detailCache.clear()
    selectedDetail.value = null
    detailState.value = 'idle'
    curlConfirmation.value = null
    generatedCurl.value = null
    pendingReplayId = null
    inspector.clearTransactions()
    actionPending.value = null
    feedback.value = null
  }

  async function start() {
    const request = ++startRequest
    teardown()
    initialState.value = 'loading'
    connectionState.value = 'connecting'
    syncError.value = false
    lastSequence = 0
    const abort = new AbortController()
    sessionAbort = abort
    try {
      const session = await source.startSession(abort.signal)
      if (request !== startRequest) return
      capturePaused.value = session.capture.paused
      unsubscribe = source.subscribe({
        event: handleEvent,
        connection(state) {
          connectionState.value = state
        },
      })
      await requestResync(true)
      if (request !== startRequest) return
      initialState.value = 'ready'
    } catch {
      if (abort.signal.aborted || request !== startRequest) return
      initialState.value = 'error'
      unsubscribe?.()
      unsubscribe = null
    }
  }

  function stop() {
    startRequest += 1
    teardown()
  }

  async function retrySync() {
    if (initialState.value === 'error') {
      await start()
      return
    }
    try {
      await requestResync(true)
      announce('success', 'Traffic list refreshed.')
    } catch {
      announce('error', 'Could not refresh traffic. Check that the inspector is still running.')
    }
  }

  async function retryDetail() {
    const id = inspector.selectedId.value
    if (id !== null) await loadDetail(id, true)
  }

  async function runAction(
    key: string,
    action: (owner: number) => Promise<void>,
    failure: string,
  ) {
    if (actionPending.value !== null) return
    const owner = startRequest
    actionPending.value = key
    clearFeedback()
    try {
      await action(owner)
    } catch {
      if (owner === startRequest) announce('error', failure)
    } finally {
      if (owner === startRequest) actionPending.value = null
    }
  }

  async function toggleCapture() {
    const pausing = !capturePaused.value
    await runAction(
      pausing ? 'pause' : 'resume',
      async (owner) => {
        const capture = pausing ? await source.pauseCapture() : await source.resumeCapture()
        if (owner !== startRequest) return
        capturePaused.value = capture.paused
        announce('success', capture.paused ? 'Capture paused.' : 'Capture resumed.')
      },
      pausing ? 'Could not pause capture. Try again.' : 'Could not resume capture. Try again.',
    )
  }

  async function deleteSelected() {
    const id = inspector.selectedId.value
    if (id === null) return
    await runAction(
      'delete',
      async (owner) => {
        await source.deleteTransaction(id)
        if (owner !== startRequest) return
        detailCache.delete(id)
        inspector.removeTransaction(id)
        announce('success', 'Transaction deleted.')
      },
      'Could not delete this transaction. It may no longer be retained.',
    )
  }

  async function clearAll() {
    await runAction(
      'clear',
      async (owner) => {
        const removed = await source.clearTransactions()
        if (owner !== startRequest) return
        detailCache.clear()
        inspector.clearTransactions()
        announce('success', `${removed} ${removed === 1 ? 'transaction' : 'transactions'} cleared.`)
      },
      'Could not clear captured traffic. Try again.',
    )
  }

  async function replaySelected() {
    const id = inspector.selectedId.value
    if (id === null) return
    await runAction(
      'replay',
      async (owner) => {
        const replayId = await source.replayTransaction(id)
        if (owner !== startRequest) return
        pendingReplayId = replayId
        try {
          await requestResync(false)
        } catch {
          // SSE reconciliation can still reveal the pending replay after this one-shot refresh.
        }
      },
      'Could not replay this request. Resume capture and try again.',
    )
  }

  async function copy(text: string | null, success: string, owner?: number) {
    if (text === null) {
      announce('error', 'Nothing to copy.')
      return false
    }
    try {
      await clipboard.copy(text)
      if (owner !== undefined && owner !== startRequest) return false
      announce('success', success)
      return true
    } catch {
      if (owner !== undefined && owner !== startRequest) return false
      announce('error', 'Could not copy to the clipboard. Check browser permissions and try again.')
      return false
    }
  }

  function headerText(headers: readonly HeaderField[]) {
    return headers
      .map((header) => `${header.name}: ${header.sensitive ? '[masked]' : header.value}`)
      .join('\n')
  }

  async function copyUrl() {
    await copy(selectedDetail.value?.url ?? selectedSummary.value?.url ?? null, 'Request URL copied.')
  }

  async function copyHeaders(side: MessageSide) {
    const snapshot = side === 'request' ? selectedDetail.value?.request : selectedDetail.value?.response
    await copy(snapshot ? headerText(snapshot.headers) : null, `${side === 'request' ? 'Request' : 'Response'} headers copied. Masked values were excluded.`)
  }

  async function copyBody(side: MessageSide) {
    const snapshot = side === 'request' ? selectedDetail.value?.request : selectedDetail.value?.response
    await copy(snapshot?.body.text ?? null, `${side === 'request' ? 'Request' : 'Response'} body copied.`)
  }

  async function requestCurl() {
    const id = inspector.selectedId.value
    if (id === null) return
    generatedCurl.value = null
    await runAction(
      'curl',
      async (owner) => {
        const result = await source.generateCurl(id, false)
        if (owner !== startRequest || inspector.selectedId.value !== id) return
        if (result.status === 'confirmation_required') {
          curlConfirmation.value = { transactionId: id, headerNames: [...result.headerNames] }
          return
        }
        generatedCurl.value = {
          transactionId: id,
          command: result.command,
          containsSecrets: result.containsSecrets,
        }
      },
      'Could not generate a cURL command for this request.',
    )
  }

  async function confirmSensitiveCurl() {
    const confirmation = curlConfirmation.value
    if (!confirmation) return
    curlConfirmation.value = null
    await runAction(
      'curl',
      async (owner) => {
        const result = await source.generateCurl(confirmation.transactionId, true)
        if (
          owner !== startRequest ||
          inspector.selectedId.value !== confirmation.transactionId
        ) return
        if (result.status !== 'generated') throw new Error('confirmation_not_accepted')
        generatedCurl.value = {
          transactionId: confirmation.transactionId,
          command: result.command,
          containsSecrets: result.containsSecrets,
        }
      },
      'Could not generate the confirmed cURL command. Try again.',
    )
  }

  function cancelSensitiveCurl() {
    curlConfirmation.value = null
  }

  async function copyGeneratedCurl() {
    const generated = generatedCurl.value
    if (!generated || generated.transactionId !== inspector.selectedId.value) return
    await copy(generated.command, 'cURL command copied.')
  }

  function closeGeneratedCurl() {
    generatedCurl.value = null
  }

  return {
    ...inspector,
    initialState: readonly(initialState),
    connectionState: readonly(connectionState),
    syncError: readonly(syncError),
    syncing: readonly(syncing),
    capturePaused: readonly(capturePaused),
    selectedSummary,
    selectedDetail: readonly(selectedDetail),
    detailState: readonly(detailState),
    actionPending: readonly(actionPending),
    feedback: readonly(feedback),
    curlConfirmation: readonly(curlConfirmation),
    generatedCurl: readonly(generatedCurl),
    isOffline,
    start,
    stop,
    retrySync,
    retryDetail,
    clearFeedback,
    toggleCapture,
    deleteSelected,
    clearAll,
    replaySelected,
    copyUrl,
    copyHeaders,
    copyBody,
    requestCurl,
    confirmSensitiveCurl,
    cancelSensitiveCurl,
    copyGeneratedCurl,
    closeGeneratedCurl,
    revealHeader: source.revealHeader.bind(source),
    handleEvent,
  }
}

export type LiveInspectorState = ReturnType<typeof useLiveInspector>
