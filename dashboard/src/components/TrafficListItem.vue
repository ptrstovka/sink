<script setup lang="ts">
import { ChevronRight, Clock3, RotateCcw } from '@lucide/vue'
import Badge from '@/components/ui/badge/Badge.vue'
import type { TrafficTransactionSummary } from '@/domain/traffic'
import { formatDuration, formatTime, statusLabel, statusTone } from '@/lib/formatters'

defineProps<{
  transaction: TrafficTransactionSummary
  selected: boolean
}>()

defineEmits<{
  select: []
}>()
</script>

<template>
  <li>
    <button
      type="button"
      class="group grid w-full grid-cols-[auto_1fr_auto] items-start gap-3 border-b px-4 py-3.5 text-left outline-none transition-colors hover:bg-accent/60 focus-visible:relative focus-visible:z-10 focus-visible:ring-[3px] focus-visible:ring-inset focus-visible:ring-ring/55"
      :class="selected && 'bg-accent hover:bg-accent'"
      :aria-current="selected ? 'true' : undefined"
      :aria-label="`${transaction.method} ${transaction.path}, ${statusLabel(transaction)}`"
      @click="$emit('select')"
    >
      <span class="mt-0.5 min-w-12 rounded border bg-background px-1.5 py-0.5 text-center font-mono text-[11px] font-semibold text-foreground">
        {{ transaction.method }}
      </span>
      <span class="min-w-0">
        <span class="flex min-w-0 items-center gap-1.5">
          <span class="truncate text-sm font-medium">{{ transaction.path }}</span>
          <RotateCcw v-if="transaction.origin === 'replay'" class="size-3.5 shrink-0 text-muted-foreground" aria-label="Replay" />
        </span>
        <span class="mt-1 flex flex-wrap items-center gap-x-2 gap-y-1 text-xs text-muted-foreground">
          <span>{{ formatTime(transaction.receivedAt) }}</span>
          <span aria-hidden="true">·</span>
          <span class="inline-flex items-center gap-1"><Clock3 class="size-3" aria-hidden="true" />{{ formatDuration(transaction.durationMs) }}</span>
        </span>
      </span>
      <span class="flex items-center gap-1.5">
        <Badge :variant="statusTone(transaction)">{{ statusLabel(transaction) }}</Badge>
        <ChevronRight class="size-4 text-muted-foreground lg:hidden" aria-hidden="true" />
      </span>
    </button>
  </li>
</template>
