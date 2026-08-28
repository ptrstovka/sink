<script setup lang="ts">
import { nextTick, ref, watch } from 'vue'
import {
  ArrowLeft,
  CircleAlert,
  Copy,
  FileCode2,
  LoaderCircle,
  RotateCcw,
  ShieldAlert,
  Trash2,
  X,
} from '@lucide/vue'
import Badge from '@/components/ui/badge/Badge.vue'
import Button from '@/components/ui/button/Button.vue'
import { Tabs, TabsContent, TabsList, TabsTrigger } from '@/components/ui/tabs'
import HeaderTable from '@/components/HeaderTable.vue'
import PayloadViewer from '@/components/PayloadViewer.vue'
import type { TrafficSource } from '@/api/traffic-source'
import type { DetailTab } from '@/composables/use-inspector'
import type { DetailState } from '@/composables/use-live-inspector'
import type { GeneratedCurl } from '@/composables/use-live-inspector'
import type { TrafficTransactionDetail, TrafficTransactionSummary } from '@/domain/traffic'
import { formatDuration, formatTime, statusLabel, statusTone } from '@/lib/formatters'

const props = defineProps<{
  summary: TrafficTransactionSummary
  detail: TrafficTransactionDetail | null
  detailState: DetailState
  activeTab: DetailTab
  source: Pick<TrafficSource, 'revealHeader'>
  actionPending: string | null
  capturePaused: boolean
  generatedCurl: GeneratedCurl | null
}>()

const emit = defineEmits<{
  back: []
  retry: []
  replay: []
  curl: []
  copyCurl: []
  closeCurl: []
  delete: []
  copyUrl: []
  copyHeaders: [side: 'request' | 'response']
  copyBody: [side: 'request' | 'response']
  'update:activeTab': [tab: DetailTab]
}>()

const article = ref<HTMLElement | null>(null)
const commandText = ref<HTMLTextAreaElement | null>(null)

watch(
  () => props.generatedCurl,
  async (generated) => {
    if (!generated || generated.transactionId !== props.summary.id) return
    await nextTick()
    commandText.value?.focus()
    commandText.value?.select()
  },
  { flush: 'post' },
)

defineExpose({ focus: () => article.value?.focus() })

function updateActiveTab(value: unknown) {
  if (value === 'request' || value === 'response') emit('update:activeTab', value)
}
</script>

<template>
  <article ref="article" tabindex="-1" class="flex min-h-0 flex-1 flex-col outline-none" :aria-label="`Transaction ${summary.method} ${summary.path}`">
    <header class="shrink-0 border-b bg-background px-4 py-4 sm:px-6">
      <div class="flex items-start gap-3">
        <Button variant="ghost" size="icon-sm" class="-ml-2 lg:hidden" aria-label="Back to traffic list" @click="$emit('back')">
          <ArrowLeft />
        </Button>
        <div class="min-w-0 flex-1">
          <div class="flex flex-wrap items-center gap-2">
            <span class="rounded border bg-muted px-2 py-0.5 font-mono text-xs font-semibold">{{ summary.method }}</span>
            <Badge :variant="statusTone(summary)">{{ statusLabel(summary) }}</Badge>
            <Badge v-if="summary.origin === 'replay'" variant="secondary"><RotateCcw />Replay</Badge>
          </div>
          <div class="mt-2 flex min-w-0 items-start gap-1">
            <h2 class="min-w-0 break-all text-base font-semibold leading-6">{{ summary.url }}</h2>
            <Button variant="ghost" size="icon-sm" class="-mt-1 shrink-0" aria-label="Copy request URL" @click="$emit('copyUrl')">
              <Copy />
            </Button>
          </div>
          <div class="mt-2 flex flex-wrap gap-x-4 gap-y-1 text-xs text-muted-foreground">
            <span>{{ formatTime(summary.receivedAt) }}</span>
            <span>{{ formatDuration(summary.durationMs) }}</span>
            <span v-if="summary.origin === 'replay' && summary.replaySourceId">
              Replayed from {{ summary.replaySourceId.slice(0, 8) }}
            </span>
          </div>
        </div>
      </div>
    </header>

    <Tabs :model-value="activeTab" class="min-h-0 flex-1 gap-0" @update:model-value="updateActiveTab">
      <div class="flex flex-wrap items-center justify-between gap-3 border-b bg-muted/20 px-4 py-2.5 sm:px-6">
        <TabsList aria-label="Transaction details">
          <TabsTrigger value="request" class="px-3">Request</TabsTrigger>
          <TabsTrigger value="response" class="px-3">Response</TabsTrigger>
        </TabsList>

      <div class="flex flex-wrap items-center gap-1.5">
        <Button
          variant="ghost"
          size="sm"
          :disabled="actionPending !== null || !summary.replay.eligible"
          :title="summary.replay.eligible ? 'Generate cURL command' : summary.replay.reason ?? 'cURL unavailable'"
          :aria-label="summary.replay.eligible ? 'Generate cURL command' : `Generate cURL unavailable: ${summary.replay.reason}`"
          @click="$emit('curl')"
        >
          <LoaderCircle v-if="actionPending === 'curl'" class="animate-spin motion-reduce:animate-none" />
          <FileCode2 v-else />
          cURL
        </Button>
        <Button
          variant="outline"
          size="sm"
          :disabled="actionPending !== null || !summary.replay.eligible || capturePaused"
          :title="capturePaused ? 'Resume capture before replaying' : summary.replay.eligible ? 'Replay request' : summary.replay.reason ?? 'Replay unavailable'"
          :aria-label="capturePaused ? 'Replay unavailable: capture is paused' : summary.replay.eligible ? 'Replay request' : `Replay unavailable: ${summary.replay.reason}`"
          @click="$emit('replay')"
        >
          <LoaderCircle v-if="actionPending === 'replay'" class="animate-spin motion-reduce:animate-none" />
          <RotateCcw v-else />
          Replay
        </Button>
        <Button
          variant="ghost"
          size="icon-sm"
          :disabled="actionPending !== null"
          aria-label="Delete transaction"
          @click="$emit('delete')"
        >
          <Trash2 />
        </Button>
      </div>
      </div>

      <section
        v-if="generatedCurl?.transactionId === summary.id"
        aria-label="Generated cURL command"
        class="shrink-0 border-b bg-muted/20 px-4 py-3 sm:px-6"
      >
      <div class="mb-2 flex flex-wrap items-center justify-between gap-2">
        <div class="flex items-center gap-2">
          <h3 class="text-sm font-semibold">cURL command</h3>
          <Badge v-if="generatedCurl.containsSecrets" variant="warning">Sensitive headers included</Badge>
        </div>
        <div class="flex items-center gap-1">
          <Button variant="outline" size="sm" aria-label="Copy generated cURL command" @click="$emit('copyCurl')">
            <Copy />
            Copy
          </Button>
          <Button variant="ghost" size="icon-sm" aria-label="Close generated cURL command" @click="$emit('closeCurl')">
            <X />
          </Button>
        </div>
      </div>
      <textarea
        ref="commandText"
        :value="generatedCurl.command"
        readonly
        spellcheck="false"
        aria-label="Generated cURL command text"
        class="max-h-40 min-h-20 w-full resize-y rounded-md border bg-code p-3 font-mono text-xs leading-5 text-code-foreground outline-none focus-visible:ring-[3px] focus-visible:ring-ring/50"
        @focus="($event.target as HTMLTextAreaElement).select()"
      ></textarea>
      </section>

      <div class="min-h-0 flex-1 overflow-y-auto">
      <div
        v-if="!summary.replay.eligible"
        class="m-4 flex gap-3 rounded-lg border border-amber-500/25 bg-amber-500/8 p-3 text-sm sm:mx-6 sm:mt-5"
        role="note"
      >
        <ShieldAlert class="mt-0.5 size-4 shrink-0 text-amber-700 dark:text-amber-300" aria-hidden="true" />
        <div>
          <p class="font-medium">Replay unavailable</p>
          <p class="mt-0.5 text-muted-foreground">{{ summary.replay.reason }}</p>
        </div>
      </div>

      <div v-if="detailState === 'loading'" class="flex min-h-64 items-center justify-center p-8" role="status" aria-live="polite">
        <div class="text-center text-sm text-muted-foreground">
          <LoaderCircle class="mx-auto mb-3 size-5 animate-spin motion-reduce:animate-none" aria-hidden="true" />
          Loading selected transaction…
        </div>
      </div>

      <div v-else-if="detailState === 'error'" class="flex min-h-64 items-center justify-center p-8">
        <div class="max-w-sm rounded-lg border border-destructive/25 bg-destructive/8 p-5 text-center" role="alert">
          <CircleAlert class="mx-auto size-5 text-destructive" aria-hidden="true" />
          <p class="mt-2 text-sm font-medium">Could not load transaction details</p>
          <Button variant="outline" size="sm" class="mt-4" aria-label="Retry transaction details" @click="$emit('retry')">Retry</Button>
        </div>
      </div>

      <template v-else-if="detail">
        <TabsContent
          value="request"
          tabindex="0"
          class="space-y-7 p-4 outline-none focus-visible:ring-[3px] focus-visible:ring-inset focus-visible:ring-ring/50 sm:p-6"
        >
          <HeaderTable
            :headers="detail.request.headers"
            label="Request"
            :transaction-id="detail.id"
            side="request"
            :source="source"
            @copy="$emit('copyHeaders', 'request')"
          />
          <PayloadViewer :body="detail.request.body" label="Request" @copy="$emit('copyBody', 'request')" />
        </TabsContent>

        <TabsContent
          value="response"
          tabindex="0"
          class="space-y-7 p-4 outline-none focus-visible:ring-[3px] focus-visible:ring-inset focus-visible:ring-ring/50 sm:p-6"
        >
          <template v-if="detail.response">
            <HeaderTable
              :headers="detail.response.headers"
              label="Response"
              :transaction-id="detail.id"
              side="response"
              :source="source"
              @copy="$emit('copyHeaders', 'response')"
            />
            <PayloadViewer :body="detail.response.body" label="Response" @copy="$emit('copyBody', 'response')" />
          </template>
          <div v-else-if="summary.state === 'pending'" class="flex gap-3 rounded-lg border bg-muted/35 p-4" role="status">
            <LoaderCircle class="mt-0.5 size-5 shrink-0 animate-spin text-muted-foreground motion-reduce:animate-none" aria-hidden="true" />
            <div>
              <p class="font-medium">Waiting for response</p>
            </div>
          </div>
          <div v-else class="flex gap-3 rounded-lg border border-destructive/25 bg-destructive/8 p-4" role="alert">
            <CircleAlert class="mt-0.5 size-5 shrink-0 text-destructive" aria-hidden="true" />
            <div>
              <p class="font-medium">No response received</p>
              <p class="mt-1 text-sm text-muted-foreground">{{ detail.error ?? 'The transaction ended before response headers arrived.' }}</p>
            </div>
          </div>
        </TabsContent>
      </template>
      </div>
    </Tabs>
  </article>
</template>
