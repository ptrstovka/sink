import { describe, expect, it } from 'vitest'
import { useInspector } from '@/composables/use-inspector'
import { avatar, checkout, failed, replay, summaries } from './fixtures'

describe('inspector summary state', () => {
  it('orders newest first and keeps an older selection when live traffic arrives', () => {
    const state = useInspector([replay, avatar])
    expect(state.transactions.value.map(({ id }) => id)).toEqual(['tx-avatar', 'tx-health-replay'])

    state.selectTransaction(replay.id)
    state.replaceTransactions([avatar, checkout, replay])

    expect(state.transactions.value.map(({ id }) => id)).toEqual([
      checkout.id,
      avatar.id,
      replay.id,
    ])
    expect(state.selectedId.value).toBe(replay.id)
  })

  it('preserves selection through filtering and applies every filter', () => {
    const state = useInspector(summaries)
    state.selectTransaction(checkout.id)
    state.filters.search = 'USERS/82'
    expect(state.filteredTransactions.value.map(({ id }) => id)).toEqual([avatar.id])
    expect(state.selectedId.value).toBe(checkout.id)

    state.filters.search = ''
    state.filters.method = 'GET'
    state.filters.status = '2xx'
    state.filters.origin = 'replay'
    expect(state.filteredTransactions.value.map(({ id }) => id)).toEqual([replay.id])

    state.filters.method = 'all'
    state.filters.status = 'error'
    state.filters.origin = 'original'
    expect(state.filteredTransactions.value.map(({ id }) => id)).toEqual([failed.id])
  })

  it('selects the adjacent retained entry after deletion or eviction', () => {
    const state = useInspector(summaries)
    state.selectTransaction(avatar.id)
    state.removeTransaction(avatar.id)
    expect(state.selectedId.value).toBe(replay.id)

    state.replaceTransactions([checkout])
    expect(state.selectedId.value).toBe(checkout.id)

    state.clearTransactions()
    expect(state.selectedId.value).toBeNull()
    expect(state.mobilePane.value).toBe('list')
  })
})
