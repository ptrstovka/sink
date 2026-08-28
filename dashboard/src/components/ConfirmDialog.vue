<script setup lang="ts">
import { useSlots } from 'vue'
import {
  AlertDialog,
  AlertDialogAction,
  AlertDialogCancel,
  AlertDialogContent,
  AlertDialogDescription,
  AlertDialogFooter,
  AlertDialogHeader,
  AlertDialogTitle,
} from '@/components/ui/alert-dialog'
import { buttonVariants } from '@/components/ui/button'

defineOptions({ inheritAttrs: false })

const props = withDefaults(
  defineProps<{
    open: boolean
    title: string
    description: string
    confirmLabel: string
    destructive?: boolean
    busy?: boolean
  }>(),
  { destructive: false, busy: false },
)

const emit = defineEmits<{
  cancel: []
  confirm: []
}>()
const slots = useSlots()

function guardBusyDismiss(event: Event) {
  if (props.busy) {
    event.preventDefault()
    return
  }
  emit('cancel')
}
</script>

<template>
  <AlertDialog :open="open">
    <AlertDialogContent v-bind="$attrs" class="sm:max-w-md" @escape-key-down="guardBusyDismiss">
      <AlertDialogHeader>
        <AlertDialogTitle>{{ title }}</AlertDialogTitle>
        <AlertDialogDescription>{{ description }}</AlertDialogDescription>
      </AlertDialogHeader>
      <div v-if="slots.default"><slot /></div>
      <AlertDialogFooter>
        <AlertDialogCancel :disabled="busy" @click="$emit('cancel')">Cancel</AlertDialogCancel>
        <AlertDialogAction
          :disabled="busy"
          :class="destructive ? buttonVariants({ variant: 'destructive' }) : undefined"
          @click="$emit('confirm')"
        >
          {{ busy ? 'Working…' : confirmLabel }}
        </AlertDialogAction>
      </AlertDialogFooter>
    </AlertDialogContent>
  </AlertDialog>
</template>
