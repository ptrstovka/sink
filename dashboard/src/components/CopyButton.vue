<script setup lang="ts">
import { Copy } from '@lucide/vue'
import Button from '@/components/ui/button/Button.vue'

withDefaults(
  defineProps<{
    label: string
    disabled?: boolean
  }>(),
  { disabled: false },
)

defineEmits<{
  click: [event: MouseEvent]
}>()
</script>

<template>
  <Button
    data-slot="copy-action"
    variant="ghost"
    size="sm"
    :disabled="disabled"
    :aria-label="label"
    @click="$emit('click', $event)"
  >
    <Copy />
    Copy
  </Button>
</template>
