<script setup lang="ts">
import { inject, onBeforeUnmount, onMounted } from 'vue'
import { CircleAlert, LoaderCircle } from '@lucide/vue'
import Button from '@/components/ui/button/Button.vue'
import { Toaster } from '@/components/ui/sonner'
import InspectorShell from '@/components/InspectorShell.vue'
import { httpTrafficSource } from '@/api/http-traffic-source'
import { trafficSourceKey } from '@/api/traffic-source'
import { useLiveInspector } from '@/composables/use-live-inspector'
import { useTheme } from '@/composables/use-theme'
import 'vue-sonner/style.css'

const source = inject(trafficSourceKey, httpTrafficSource)
const inspector = useLiveInspector(source)
const theme = useTheme()

onMounted(() => {
  void inspector.start()
})
onBeforeUnmount(inspector.stop)
</script>

<template>
  <div v-if="inspector.initialState.value === 'loading'" class="flex h-dvh items-center justify-center p-6" role="status" aria-live="polite">
    <div class="text-center text-sm text-muted-foreground">
      <LoaderCircle class="mx-auto mb-3 size-6 animate-spin motion-reduce:animate-none" aria-hidden="true" />
      Connecting to the local traffic inspector…
    </div>
  </div>
  <div v-else-if="inspector.initialState.value === 'error'" class="flex h-dvh items-center justify-center p-6">
    <div class="max-w-md rounded-xl border border-destructive/25 bg-card p-6 text-center shadow-sm" role="alert">
      <CircleAlert class="mx-auto size-6 text-destructive" aria-hidden="true" />
      <h1 class="mt-3 text-base font-semibold">Could not connect to the inspector</h1>
      <p class="mt-2 text-sm text-muted-foreground">Check that this dashboard belongs to a running sink client, then retry.</p>
      <Button variant="outline" class="mt-5" aria-label="Retry inspector connection" @click="inspector.start">Retry</Button>
    </div>
  </div>
  <InspectorShell v-else :state="inspector" :theme="theme" />
  <Toaster :theme="theme.preference.value" />
</template>
