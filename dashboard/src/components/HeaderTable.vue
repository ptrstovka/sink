<script setup lang="ts">
import CopyButton from '@/components/CopyButton.vue'
import MaskedValue from '@/components/MaskedValue.vue'
import type { TrafficSource } from '@/api/traffic-source'
import type { HeaderField, MessageSide } from '@/domain/traffic'

const props = defineProps<{
  headers: readonly HeaderField[]
  label: string
  transactionId: string
  side: MessageSide
  source: Pick<TrafficSource, 'revealHeader'>
}>()

defineEmits<{
  copy: []
}>()

function reveal(header: HeaderField) {
  return props.source.revealHeader({
    transactionId: props.transactionId,
    side: props.side,
    headerId: header.id,
  })
}
</script>

<template>
  <section :aria-label="label" class="space-y-3">
    <div class="flex items-center justify-between gap-3">
      <h3 class="text-sm font-semibold">Headers</h3>
      <CopyButton
        :disabled="headers.length === 0"
        :label="`Copy ${label.toLowerCase()} headers; sensitive values stay masked`"
        @click="$emit('copy')"
      />
    </div>

    <div v-if="headers.length" class="overflow-hidden rounded-lg border bg-card">
      <dl class="divide-y divide-border">
        <div
          v-for="header in headers"
          :key="`${transactionId}:${side}:${header.id}`"
          class="grid gap-1 px-3 py-2.5 sm:grid-cols-[minmax(8rem,0.35fr)_1fr] sm:gap-4"
        >
          <dt class="break-all font-mono text-xs font-medium text-muted-foreground">{{ header.name }}</dt>
          <dd class="min-w-0">
            <MaskedValue
              :header="header"
              :label="`${header.name} header`"
              :reveal="() => reveal(header)"
            />
          </dd>
        </div>
      </dl>
    </div>
    <p v-else class="rounded-lg border border-dashed px-4 py-5 text-sm text-muted-foreground">No headers captured.</p>
  </section>
</template>
