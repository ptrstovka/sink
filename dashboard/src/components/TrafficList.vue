<script setup lang="ts">
import { nextTick } from 'vue'
import { SearchX } from '@lucide/vue'
import Button from '@/components/ui/button/Button.vue'
import TrafficListItem from '@/components/TrafficListItem.vue'
import type { TrafficTransactionSummary } from '@/domain/traffic'

const props = defineProps<{
  transactions: readonly TrafficTransactionSummary[]
  selectedId: string | null
  hasFilters: boolean
}>()

const emit = defineEmits<{
  select: [id: string]
  clearFilters: []
}>()

async function moveFocus(event: KeyboardEvent, index: number) {
  let next = index
  if (event.key === 'ArrowDown') next = Math.min(props.transactions.length - 1, index + 1)
  else if (event.key === 'ArrowUp') next = Math.max(0, index - 1)
  else if (event.key === 'Home') next = 0
  else if (event.key === 'End') next = props.transactions.length - 1
  else return

  event.preventDefault()
  const transaction = props.transactions[next]
  if (!transaction) return
  const list = (event.currentTarget as HTMLElement).closest('ul')
  emit('select', transaction.id)
  await nextTick()
  const buttons = list?.querySelectorAll('button')
  ;(buttons?.item(next) as HTMLButtonElement | null)?.focus()
}
</script>

<template>
  <ul v-if="transactions.length" aria-label="Captured traffic" class="divide-y-0">
    <TrafficListItem
      v-for="(transaction, index) in transactions"
      :key="transaction.id"
      :transaction="transaction"
      :selected="transaction.id === selectedId"
      @select="$emit('select', transaction.id)"
      @keydown="moveFocus($event, index)"
    />
  </ul>
  <div v-else class="flex min-h-56 flex-col items-center justify-center px-6 py-10 text-center">
    <span class="mb-3 rounded-full bg-muted p-3"><SearchX class="size-5 text-muted-foreground" aria-hidden="true" /></span>
    <p class="text-sm font-medium">{{ hasFilters ? 'No matching traffic' : 'Waiting for traffic' }}</p>
    <Button v-if="hasFilters" variant="outline" size="sm" class="mt-4" @click="$emit('clearFilters')">Clear filters</Button>
  </div>
</template>
