import { computed, reactive, ref, shallowRef } from 'vue'
import {
  emptyFilters,
  statusClassOf,
  type InspectorFilters,
  type TrafficTransactionSummary,
} from '@/domain/traffic'

export type DetailTab = 'request' | 'response'
export type MobilePane = 'list' | 'detail'

function newestFirst(transactions: readonly TrafficTransactionSummary[]) {
  return [...transactions].sort((left, right) => {
    const byTime = Date.parse(right.receivedAt) - Date.parse(left.receivedAt)
    return byTime || right.id.localeCompare(left.id)
  })
}

export function useInspector(initialTransactions: readonly TrafficTransactionSummary[] = []) {
  const transactions = shallowRef(newestFirst(initialTransactions))
  const selectedId = ref<string | null>(transactions.value[0]?.id ?? null)
  const activeTab = ref<DetailTab>('request')
  const mobilePane = ref<MobilePane>('list')
  const filters = reactive<InspectorFilters>(emptyFilters())

  const availableMethods = computed(() =>
    [...new Set(transactions.value.map((transaction) => transaction.method))].sort(),
  )

  const filteredTransactions = computed(() => {
    const query = filters.search.trim().toLocaleLowerCase()

    return transactions.value.filter((transaction) => {
      const matchesSearch =
        query.length === 0 ||
        transaction.url.toLocaleLowerCase().includes(query) ||
        transaction.path.toLocaleLowerCase().includes(query)
      const matchesMethod = filters.method === 'all' || transaction.method === filters.method
      const matchesStatus = filters.status === 'all' || statusClassOf(transaction) === filters.status
      const matchesOrigin = filters.origin === 'all' || transaction.origin === filters.origin

      return matchesSearch && matchesMethod && matchesStatus && matchesOrigin
    })
  })

  const selectedTransaction = computed(
    () => transactions.value.find((transaction) => transaction.id === selectedId.value) ?? null,
  )

  const hasActiveFilters = computed(
    () =>
      filters.search !== '' ||
      filters.method !== 'all' ||
      filters.status !== 'all' ||
      filters.origin !== 'all',
  )

  function replaceTransactions(nextTransactions: readonly TrafficTransactionSummary[]) {
    const sorted = newestFirst(nextTransactions)
    const previousIndex = transactions.value.findIndex(({ id }) => id === selectedId.value)
    transactions.value = sorted

    if (selectedId.value === null || !sorted.some((transaction) => transaction.id === selectedId.value)) {
      selectedId.value = sorted[Math.max(0, previousIndex)]?.id ?? sorted.at(-1)?.id ?? null
      if (selectedId.value === null) mobilePane.value = 'list'
    }
  }

  function removeTransaction(id: string) {
    if (!transactions.value.some((transaction) => transaction.id === id)) return
    replaceTransactions(transactions.value.filter((transaction) => transaction.id !== id))
  }

  function clearTransactions() {
    transactions.value = []
    selectedId.value = null
    mobilePane.value = 'list'
  }

  function selectTransaction(id: string) {
    if (!transactions.value.some((transaction) => transaction.id === id)) return
    selectedId.value = id
    activeTab.value = 'request'
    mobilePane.value = 'detail'
  }

  function showList() {
    mobilePane.value = 'list'
  }

  function clearFilters() {
    Object.assign(filters, emptyFilters())
  }

  return {
    transactions,
    selectedId,
    selectedTransaction,
    activeTab,
    mobilePane,
    filters,
    availableMethods,
    filteredTransactions,
    hasActiveFilters,
    replaceTransactions,
    removeTransaction,
    clearTransactions,
    selectTransaction,
    showList,
    clearFilters,
  }
}

export type InspectorState = ReturnType<typeof useInspector>
