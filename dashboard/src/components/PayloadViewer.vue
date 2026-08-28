<script setup lang="ts">
import { computed, ref, watch } from 'vue'
import { Braces, FileText, TriangleAlert } from '@lucide/vue'
import Badge from '@/components/ui/badge/Badge.vue'
import Button from '@/components/ui/button/Button.vue'
import CopyButton from '@/components/CopyButton.vue'
import type { BodyPreview } from '@/domain/traffic'
import { formatBytes } from '@/lib/formatters'

const props = defineProps<{
  body: BodyPreview
  label: string
}>()

defineEmits<{
  copy: []
}>()

type Presentation = 'formatted' | 'raw'
const presentation = ref<Presentation>('formatted')

const formatted = computed(() => {
  if (props.body.text === null) return { text: null, failed: false }
  if (props.body.kind !== 'json') return { text: props.body.text, failed: false }

  try {
    return { text: JSON.stringify(JSON.parse(props.body.text), null, 2), failed: false }
  } catch {
    return { text: props.body.text, failed: true }
  }
})

const jsonFormattingFailed = computed(() => formatted.value.failed)

const displayedText = computed(() =>
  presentation.value === 'raw' ? props.body.text : formatted.value.text,
)

const canChangePresentation = computed(() => props.body.kind === 'json' && props.body.text !== null)

watch(
  () => props.body,
  () => {
    presentation.value = 'formatted'
  },
)
</script>

<template>
  <section :aria-label="`${label} body`" class="space-y-3">
    <div class="flex flex-wrap items-center justify-between gap-3">
      <div class="flex flex-wrap items-center gap-2">
        <h3 class="text-sm font-semibold">Body</h3>
        <Badge v-if="body.kind !== 'empty'" variant="outline">{{ body.contentType ?? body.kind }}</Badge>
        <Badge v-if="body.truncated" variant="warning">
          <TriangleAlert />
          Truncated
        </Badge>
      </div>

      <div class="flex items-center gap-1">
        <div v-if="canChangePresentation" role="group" :aria-label="`${label} body presentation`" class="flex rounded-md border p-0.5">
          <Button
            variant="ghost"
            size="sm"
            :class="presentation === 'formatted' && 'bg-accent text-accent-foreground'"
            :aria-pressed="presentation === 'formatted'"
            @click="presentation = 'formatted'"
          >
            <Braces />
            JSON
          </Button>
          <Button
            variant="ghost"
            size="sm"
            :class="presentation === 'raw' && 'bg-accent text-accent-foreground'"
            :aria-pressed="presentation === 'raw'"
            @click="presentation = 'raw'"
          >
            <FileText />
            Raw
          </Button>
        </div>
        <CopyButton
          :disabled="body.text === null"
          :label="`Copy ${label.toLowerCase()} body`"
          @click="$emit('copy')"
        />
      </div>
    </div>

    <div v-if="body.kind === 'empty'" class="rounded-lg border border-dashed px-4 py-6 text-center text-sm text-muted-foreground">
      No body
    </div>

    <div v-else-if="body.kind === 'binary'" class="rounded-lg border bg-muted/35 px-4 py-5">
      <div class="flex items-start gap-3">
        <FileText class="mt-0.5 size-5 text-muted-foreground" aria-hidden="true" />
        <p class="text-sm font-medium">Binary body</p>
      </div>
    </div>

    <div v-else class="overflow-hidden rounded-lg border bg-code text-code-foreground">
      <pre class="max-h-[28rem] overflow-auto p-4 text-xs leading-5"><code>{{ displayedText }}</code></pre>
    </div>

    <div v-if="body.kind !== 'empty'" class="text-xs text-muted-foreground">
      <span>{{ formatBytes(body.transferredBytes) }} transferred</span>
    </div>
    <p v-if="jsonFormattingFailed" class="text-xs text-muted-foreground">Invalid JSON; showing raw body.</p>
  </section>
</template>
