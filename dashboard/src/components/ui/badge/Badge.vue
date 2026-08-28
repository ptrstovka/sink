<script setup lang="ts">
import type { HTMLAttributes } from 'vue'
import { cva, type VariantProps } from 'class-variance-authority'
import { cn } from '@/lib/utils'

const badgeVariants = cva(
  'inline-flex w-fit shrink-0 items-center justify-center gap-1 overflow-hidden rounded-md border px-2 py-0.5 text-xs font-medium whitespace-nowrap transition-colors [&>svg]:size-3',
  {
    variants: {
      variant: {
        default: 'border-transparent bg-primary text-primary-foreground',
        secondary: 'border-transparent bg-secondary text-secondary-foreground',
        destructive: 'border-transparent bg-destructive/12 text-destructive dark:bg-destructive/22',
        outline: 'text-foreground',
        success: 'border-transparent bg-emerald-500/12 text-emerald-700 dark:text-emerald-400',
        warning: 'border-transparent bg-amber-500/14 text-amber-800 dark:text-amber-300',
        pending: 'border-transparent bg-blue-500/12 text-blue-700 dark:text-blue-300',
      },
    },
    defaultVariants: {
      variant: 'default',
    },
  },
)

type BadgeVariants = VariantProps<typeof badgeVariants>

withDefaults(
  defineProps<{
    variant?: BadgeVariants['variant']
    class?: HTMLAttributes['class']
  }>(),
  {
    variant: 'default',
    class: undefined,
  },
)
</script>

<template>
  <span :class="cn(badgeVariants({ variant }), $props.class)">
    <slot />
  </span>
</template>
