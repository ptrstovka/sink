<script setup lang="ts">
import { ref, type HTMLAttributes } from 'vue'
import { cn } from '@/lib/utils'
import { buttonVariants, type ButtonVariants } from './variants'

const element = ref<HTMLButtonElement | null>(null)
defineExpose({ focus: () => element.value?.focus() })

withDefaults(
  defineProps<{
    variant?: ButtonVariants['variant']
    size?: ButtonVariants['size']
    class?: HTMLAttributes['class']
    type?: 'button' | 'submit' | 'reset'
  }>(),
  {
    variant: 'default',
    size: 'default',
    class: undefined,
    type: 'button',
  },
)
</script>

<template>
  <button ref="element" :type="type" :class="cn(buttonVariants({ variant, size }), $props.class)">
    <slot />
  </button>
</template>
