<script setup lang="ts">
import { computed, onBeforeUnmount, ref, watch } from 'vue'
import { Eye, EyeOff } from '@lucide/vue'
import Button from '@/components/ui/button/Button.vue'
import type { HeaderField } from '@/domain/traffic'

const props = defineProps<{
  header: HeaderField
  label: string
  reveal: () => Promise<string>
}>()

const revealedValue = ref<string | null>(null)
const revealError = ref<string | null>(null)
const revealing = ref(false)
const ordinaryValue = computed(() => (props.header.sensitive ? null : props.header.value))
let revealAttempt = 0

function clearRevealedValue() {
  revealAttempt += 1
  revealedValue.value = null
  revealError.value = null
  revealing.value = false
}

async function toggle() {
  if (!props.header.sensitive || revealing.value) return
  if (revealedValue.value !== null) {
    clearRevealedValue()
    return
  }

  const attempt = ++revealAttempt
  revealError.value = null
  revealing.value = true
  try {
    const value = await props.reveal()
    if (attempt === revealAttempt) revealedValue.value = value
  } catch {
    if (attempt === revealAttempt) {
      revealedValue.value = null
      revealError.value = 'Could not reveal this header value. Try again.'
    }
  } finally {
    if (attempt === revealAttempt) revealing.value = false
  }
}

watch(() => props.header.id, clearRevealedValue)
onBeforeUnmount(clearRevealedValue)
</script>

<template>
  <div class="min-w-0">
    <div class="flex min-w-0 items-center gap-2">
      <code class="min-w-0 flex-1 break-all font-mono text-xs text-foreground">
        <template v-if="ordinaryValue !== null">{{ ordinaryValue }}</template>
        <template v-else-if="revealedValue !== null">{{ revealedValue }}</template>
        <span v-else class="tracking-wider text-muted-foreground" aria-label="Masked sensitive value">••••••••••••</span>
      </code>
      <Button
        v-if="header.sensitive"
        variant="ghost"
        size="icon-sm"
        :disabled="revealing"
        :aria-label="`${revealing ? 'Revealing' : revealedValue !== null ? 'Hide' : 'Reveal'} ${label}`"
        :aria-pressed="revealedValue !== null"
        :aria-busy="revealing"
        @click="toggle"
      >
        <EyeOff v-if="revealedValue !== null" />
        <Eye v-else />
      </Button>
    </div>
    <p v-if="revealError" class="mt-1 text-xs text-destructive" role="alert">{{ revealError }}</p>
  </div>
</template>
