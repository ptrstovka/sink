import { flushPromises } from '@vue/test-utils'
import { describe, expect, it, vi } from 'vitest'
import { useLiveInspector } from '@/composables/use-live-inspector'
import { avatar, checkout, detail, replay, summary } from './fixtures'
import { FakeTrafficSource } from './fake-source'

describe('live inspector reconciliation', () => {
  it('loads only selected detail and ignores stale detail responses', async () => {
    const source = new FakeTrafficSource()
    source.summaries = [checkout, avatar]
    let resolveCheckout!: (value: ReturnType<typeof detail>) => void
    let resolveAvatar!: (value: ReturnType<typeof detail>) => void
    source.getTransaction.mockImplementation(
      (id) =>
        new Promise((resolve) => {
          if (id === checkout.id) resolveCheckout = resolve
          else resolveAvatar = resolve
        }),
    )
    const state = useLiveInspector(source, { copy: vi.fn() })

    const started = state.start()
    await flushPromises()
    expect(source.getTransaction).toHaveBeenCalledTimes(1)
    expect(source.getTransaction).toHaveBeenLastCalledWith(checkout.id, expect.any(AbortSignal))

    state.selectTransaction(avatar.id)
    await flushPromises()
    resolveAvatar(detail(avatar))
    await flushPromises()
    expect(state.selectedDetail.value?.id).toBe(avatar.id)

    resolveCheckout(detail(checkout))
    await started
    await flushPromises()
    expect(state.selectedDetail.value?.id).toBe(avatar.id)
    state.stop()
  })

  it('retains no unselected detail cache and invalidates selected detail immediately on update', async () => {
    const source = new FakeTrafficSource()
    source.summaries = [checkout, avatar]
    const state = useLiveInspector(source, { copy: vi.fn() })
    await state.start()
    await flushPromises()
    expect(state.selectedDetail.value?.id).toBe(checkout.id)

    state.selectTransaction(avatar.id)
    await flushPromises()
    state.selectTransaction(checkout.id)
    await flushPromises()
    expect(source.getTransaction.mock.calls.filter(([id]) => id === checkout.id)).toHaveLength(2)

    source.emit({ kind: 'transaction_updated', sequence: 1, id: checkout.id })
    expect(state.selectedDetail.value).toBeNull()
    expect(state.detailState.value).toBe('loading')
    await flushPromises()
    expect(state.selectedDetail.value?.id).toBe(checkout.id)
    state.stop()
  })

  it('handles initial/lag resync, updates, removals, clear, capture state, and reconnect state', async () => {
    const source = new FakeTrafficSource()
    source.summaries = [checkout, avatar]
    const state = useLiveInspector(source, { copy: vi.fn() })
    await state.start()
    await flushPromises()

    source.connection('reconnecting')
    expect(state.isOffline.value).toBe(true)
    source.connection('open')
    expect(state.connectionState.value).toBe('open')

    source.emit({ kind: 'resync_required', skipped: 0, reason: 'connection_opened' })
    await flushPromises()
    expect(source.listTransactions).toHaveBeenCalledTimes(2)

    const created = summary('tx-created', '2026-08-28T08:00:00.000Z')
    source.summaries.unshift(created)
    source.emit({ kind: 'transaction_created', sequence: 1, id: created.id })
    await flushPromises()
    expect(state.transactions.value[0]?.id).toBe(created.id)

    source.emit({ kind: 'transaction_updated', sequence: 3, id: checkout.id })
    await flushPromises()
    expect(source.listTransactions.mock.calls.length).toBeGreaterThanOrEqual(4)

    source.emit({ kind: 'transaction_removed', sequence: 4, id: avatar.id, cause: 'evicted' })
    expect(state.transactions.value.some(({ id }) => id === avatar.id)).toBe(false)

    source.emit({ kind: 'capture_state_changed', sequence: 5, paused: true })
    expect(state.capturePaused.value).toBe(true)
    source.emit({ kind: 'cleared', sequence: 6, removed: 2 })
    expect(state.transactions.value).toEqual([])
    expect(state.selectedId.value).toBeNull()
    state.stop()
  })

  it('keeps filters while selecting the pending replay after refresh', async () => {
    const source = new FakeTrafficSource()
    source.summaries = [checkout]
    const pending = summary('tx-replayed-pending', '2026-08-28T08:01:00.000Z', {
      origin: 'replay',
      replaySourceId: checkout.id,
      state: 'pending',
      status: null,
      durationMs: null,
    })
    source.replayTransaction.mockImplementation(async () => {
      source.summaries.unshift(pending)
      return pending.id
    })
    const state = useLiveInspector(source, { copy: vi.fn() })
    await state.start()
    state.filters.origin = 'original'

    await state.replaySelected()
    await flushPromises()
    expect(state.selectedId.value).toBe(pending.id)
    expect(state.filters.origin).toBe('original')
    expect(state.selectedDetail.value?.id).toBe(pending.id)
    state.stop()
  })

  it('performs pause/resume, delete, and confirmed-clear controller actions', async () => {
    const source = new FakeTrafficSource()
    source.summaries = [checkout, replay]
    const state = useLiveInspector(source, { copy: vi.fn() })
    await state.start()

    await state.toggleCapture()
    expect(source.pauseCapture).toHaveBeenCalledOnce()
    expect(state.capturePaused.value).toBe(true)
    await state.toggleCapture()
    expect(source.resumeCapture).toHaveBeenCalledOnce()

    await state.deleteSelected()
    expect(source.deleteTransaction).toHaveBeenCalledWith(checkout.id)
    expect(state.selectedId.value).toBe(replay.id)

    await state.clearAll()
    expect(source.clearTransactions).toHaveBeenCalledOnce()
    expect(state.transactions.value).toEqual([])
    state.stop()
  })

  it('releases client-held detail, confirmation, summaries, and session ownership on stop', async () => {
    const source = new FakeTrafficSource()
    source.summaries = [checkout]
    source.details.set(checkout.id, detail(checkout))
    source.generateCurl.mockResolvedValue({
      status: 'confirmation_required',
      headerNames: ['authorization'],
    })
    const state = useLiveInspector(source, { copy: vi.fn() })
    await state.start()
    await flushPromises()
    await state.requestCurl()
    expect(state.selectedDetail.value).not.toBeNull()
    expect(state.curlConfirmation.value).not.toBeNull()

    state.stop()

    expect(source.endSession).toHaveBeenCalled()
    expect(state.transactions.value).toEqual([])
    expect(state.selectedId.value).toBeNull()
    expect(state.selectedDetail.value).toBeNull()
    expect(state.detailState.value).toBe('idle')
    expect(state.curlConfirmation.value).toBeNull()
  })
})
