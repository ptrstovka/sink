<script setup lang="ts">
import { computed, nextTick, ref, watch } from 'vue'
import { toast } from 'vue-sonner'
import {
  Circle,
  LoaderCircle,
  Moon,
  Pause,
  Play,
  Radio,
  RefreshCw,
  Sun,
  SunMoon,
  Trash2,
  WifiOff,
} from '@lucide/vue'
import { Alert, AlertDescription, AlertTitle } from '@/components/ui/alert'
import Button from '@/components/ui/button/Button.vue'
import ConfirmDialog from '@/components/ConfirmDialog.vue'
import FilterBar from '@/components/FilterBar.vue'
import InspectorDetail from '@/components/InspectorDetail.vue'
import TrafficList from '@/components/TrafficList.vue'
import type { LiveInspectorState } from '@/composables/use-live-inspector'
import type { ThemePreference } from '@/composables/use-theme'

const props = defineProps<{
  state: LiveInspectorState
  theme: {
    preference: { value: ThemePreference }
    cycle(): void
  }
}>()

const clearOpen = ref(false)
const root = ref<HTMLElement | null>(null)
const detailView = ref<{ focus(): void } | null>(null)
const liveLabel = computed(() => {
  if (props.state.capturePaused.value) return 'Paused'
  if (props.state.connectionState.value === 'reconnecting') return 'Reconnecting'
  if (props.state.connectionState.value === 'connecting') return 'Connecting'
  return 'Live'
})
const themeLabel = computed(() => `Theme: ${props.theme.preference.value}. Change theme`)

watch(
  () => props.state.feedback.value,
  (feedback) => {
    if (!feedback) return
    const options = { id: 'inspector-feedback' }
    if (feedback.kind === 'error') toast.error(feedback.message, options)
    else if (feedback.kind === 'success') toast.success(feedback.message, options)
    else toast.info(feedback.message, options)
    props.state.clearFeedback()
  },
  { flush: 'post' },
)

async function confirmClear() {
  await props.state.clearAll()
  clearOpen.value = false
}

async function selectTransaction(id: string) {
  props.state.selectTransaction(id)
  if (window.matchMedia('(max-width: 1023px)').matches) {
    await nextTick()
    detailView.value?.focus()
  }
}

async function showList() {
  props.state.showList()
  await nextTick()
  root.value?.querySelector<HTMLButtonElement>('[aria-current="true"]')?.focus()
}

async function deleteSelected() {
  await props.state.deleteSelected()
  await nextTick()
  detailView.value?.focus()
}
</script>

<template>
  <div
    ref="root"
    class="grid h-dvh min-h-[36rem] grid-cols-1 overflow-hidden bg-background text-foreground lg:grid-cols-[minmax(21rem,34rem)_minmax(0,1fr)]"
    :data-mobile-view="state.mobilePane.value"
  >
    <aside
      class="min-h-0 flex-col border-r bg-card"
      :class="state.mobilePane.value === 'detail' ? 'hidden lg:flex' : 'flex'"
      aria-label="Traffic list"
    >
      <header class="shrink-0 border-b px-4 py-4">
        <div class="flex items-start justify-between gap-3">
          <h1 class="text-base font-semibold tracking-tight">Traffic inspector</h1>
          <div class="flex items-center gap-0.5">
            <Button
              variant="ghost"
              size="icon-sm"
              :aria-label="themeLabel"
              :title="themeLabel"
              @click="theme.cycle"
            >
              <Sun v-if="theme.preference.value === 'light'" />
              <Moon v-else-if="theme.preference.value === 'dark'" />
              <SunMoon v-else />
            </Button>
            <Button
              variant="ghost"
              size="icon-sm"
              :disabled="state.actionPending.value !== null || state.transactions.value.length === 0"
              aria-label="Clear all captured traffic"
              title="Clear all captured traffic"
              @click="clearOpen = true"
            >
              <Trash2 />
            </Button>
            <Button
              variant="outline"
              size="sm"
              :disabled="state.actionPending.value !== null"
              :aria-label="state.capturePaused.value ? 'Resume capture' : 'Pause capture'"
              @click="state.toggleCapture"
            >
              <LoaderCircle v-if="state.actionPending.value === 'pause' || state.actionPending.value === 'resume'" class="animate-spin motion-reduce:animate-none" />
              <Play v-else-if="state.capturePaused.value" />
              <Pause v-else />
              {{ state.capturePaused.value ? 'Resume' : 'Pause' }}
            </Button>
          </div>
        </div>

        <Alert
          v-if="state.isOffline.value"
          class="mt-3 border-amber-500/25 bg-amber-500/8"
          role="status"
        >
          <WifiOff class="text-amber-700 dark:text-amber-300" aria-hidden="true" />
          <AlertTitle>
            {{ state.connectionState.value === 'reconnecting' ? 'Live updates offline' : 'Traffic refresh failed' }}
          </AlertTitle>
          <AlertDescription class="flex flex-wrap items-center justify-between gap-x-3 gap-y-1">
            <span>Existing captured data remains available.</span>
            <Button
              class="-my-1"
              variant="ghost"
              size="sm"
              :disabled="state.syncing.value"
              aria-label="Retry traffic refresh"
              @click="state.retrySync"
            >
              <RefreshCw :class="state.syncing.value && 'animate-spin motion-reduce:animate-none'" />Retry
            </Button>
          </AlertDescription>
        </Alert>

        <div class="mt-4">
          <FilterBar :state="state" />
        </div>
      </header>

      <div class="flex shrink-0 items-center justify-between border-b bg-muted/25 px-4 py-2 text-xs text-muted-foreground">
        <span aria-live="polite">{{ state.filteredTransactions.value.length }} of {{ state.transactions.value.length }} requests</span>
        <span class="inline-flex items-center gap-1">
          <LoaderCircle v-if="state.syncing.value" class="size-3 animate-spin motion-reduce:animate-none" aria-hidden="true" />
          Newest first
        </span>
      </div>

      <nav class="min-h-0 flex-1 overflow-y-auto" aria-label="Captured requests">
        <TrafficList
          :transactions="state.filteredTransactions.value"
          :selected-id="state.selectedId.value"
          :has-filters="state.hasActiveFilters.value"
          @select="selectTransaction"
          @clear-filters="state.clearFilters"
        />
      </nav>

      <footer class="flex shrink-0 items-center gap-3 border-t bg-muted/25 px-4 py-2.5 text-xs text-muted-foreground">
        <span class="flex items-center gap-2" :aria-label="`Capture ${liveLabel.toLowerCase()}`">
          <span class="relative flex size-2">
            <span
              v-if="liveLabel === 'Live'"
              class="absolute inline-flex size-full animate-ping rounded-full bg-emerald-500 opacity-60 motion-reduce:animate-none"
            ></span>
            <Circle
              class="relative size-2"
              :class="liveLabel === 'Live' ? 'fill-emerald-500 text-emerald-500' : liveLabel === 'Paused' ? 'fill-amber-500 text-amber-500' : 'fill-muted-foreground text-muted-foreground'"
              aria-hidden="true"
            />
          </span>
          {{ liveLabel }}
        </span>
      </footer>
    </aside>

    <main
      class="min-h-0 flex-col bg-background"
      :class="state.mobilePane.value === 'list' ? 'hidden lg:flex' : 'flex'"
      aria-label="Transaction details"
    >
      <InspectorDetail
        v-if="state.selectedSummary.value"
        ref="detailView"
        :key="state.selectedSummary.value.id"
        :summary="state.selectedSummary.value"
        :detail="state.selectedDetail.value"
        :detail-state="state.detailState.value"
        :active-tab="state.activeTab.value"
        :source="state"
        :action-pending="state.actionPending.value"
        :capture-paused="state.capturePaused.value"
        :generated-curl="state.generatedCurl.value"
        @update:active-tab="state.activeTab.value = $event"
        @back="showList"
        @retry="state.retryDetail"
        @replay="state.replaySelected"
        @curl="state.requestCurl"
        @copy-curl="state.copyGeneratedCurl"
        @close-curl="state.closeGeneratedCurl"
        @delete="deleteSelected"
        @copy-url="state.copyUrl"
        @copy-headers="state.copyHeaders"
        @copy-body="state.copyBody"
      />
      <div v-else class="flex flex-1 flex-col items-center justify-center px-6 text-center">
        <span class="mb-3 rounded-full bg-muted p-3"><Radio class="size-5 text-muted-foreground" aria-hidden="true" /></span>
        <p class="text-sm font-medium">{{ state.transactions.value.length ? 'Select a request' : 'Waiting for traffic' }}</p>
      </div>
    </main>

    <ConfirmDialog
      id="clear-traffic"
      :open="clearOpen"
      title="Clear all captured traffic?"
      description="This cannot be undone."
      confirm-label="Clear all"
      destructive
      :busy="state.actionPending.value === 'clear'"
      @cancel="clearOpen = false"
      @confirm="confirmClear"
    />

    <ConfirmDialog
      id="curl-sensitive"
      :open="state.curlConfirmation.value !== null"
      title="Include sensitive headers in cURL?"
      description="The generated command will include values for these headers:"
      confirm-label="Include and generate"
      :busy="state.actionPending.value === 'curl'"
      @cancel="state.cancelSensitiveCurl"
      @confirm="state.confirmSensitiveCurl"
    >
      <ul v-if="state.curlConfirmation.value" class="max-h-40 list-disc overflow-auto rounded-md bg-muted/50 px-8 py-3 font-mono text-xs" aria-label="Sensitive header names">
        <li v-for="(name, index) in state.curlConfirmation.value.headerNames" :key="`${name}:${index}`">{{ name }}</li>
      </ul>
    </ConfirmDialog>
  </div>
</template>
