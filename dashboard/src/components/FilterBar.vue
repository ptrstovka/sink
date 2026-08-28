<script setup lang="ts">
import { Search, X } from '@lucide/vue'
import Button from '@/components/ui/button/Button.vue'
import Input from '@/components/ui/input/Input.vue'
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from '@/components/ui/select'
import type { InspectorState } from '@/composables/use-inspector'

defineProps<{
  state: InspectorState
}>()

</script>

<template>
  <form class="space-y-2" aria-label="Traffic filters" @submit.prevent>
    <div class="relative">
      <Search class="pointer-events-none absolute left-3 top-1/2 size-4 -translate-y-1/2 text-muted-foreground" aria-hidden="true" />
      <Input
        v-model="state.filters.search"
        type="search"
        class="pl-9 pr-9"
        aria-label="Search traffic by URL or path"
        placeholder="Search URL or path…"
      />
      <Button
        v-if="state.filters.search"
        variant="ghost"
        size="icon-sm"
        class="absolute right-0.5 top-0.5"
        aria-label="Clear search"
        @click="state.filters.search = ''"
      >
        <X />
      </Button>
    </div>

    <div class="grid grid-cols-3 gap-2">
      <Select v-model="state.filters.method">
        <SelectTrigger class="min-w-0 w-full" aria-label="Filter by HTTP method">
          <SelectValue>{{ state.filters.method === 'all' ? 'All methods' : state.filters.method }}</SelectValue>
        </SelectTrigger>
        <SelectContent>
          <SelectItem value="all">All methods</SelectItem>
          <SelectItem v-for="method in state.availableMethods.value" :key="method" :value="method">{{ method }}</SelectItem>
        </SelectContent>
      </Select>

      <Select v-model="state.filters.status">
        <SelectTrigger class="min-w-0 w-full" aria-label="Filter by response status class">
          <SelectValue>{{ state.filters.status === 'all' ? 'All statuses' : state.filters.status === 'error' ? 'Errors' : state.filters.status }}</SelectValue>
        </SelectTrigger>
        <SelectContent>
          <SelectItem value="all">All statuses</SelectItem>
          <SelectItem value="2xx">2xx</SelectItem>
          <SelectItem value="3xx">3xx</SelectItem>
          <SelectItem value="4xx">4xx</SelectItem>
          <SelectItem value="5xx">5xx</SelectItem>
          <SelectItem value="error">Errors</SelectItem>
        </SelectContent>
      </Select>

      <Select v-model="state.filters.origin">
        <SelectTrigger class="min-w-0 w-full" aria-label="Filter by traffic origin">
          <SelectValue>{{ state.filters.origin === 'all' ? 'All traffic' : state.filters.origin === 'original' ? 'Original' : 'Replays' }}</SelectValue>
        </SelectTrigger>
        <SelectContent>
          <SelectItem value="all">All traffic</SelectItem>
          <SelectItem value="original">Original</SelectItem>
          <SelectItem value="replay">Replays</SelectItem>
        </SelectContent>
      </Select>
    </div>
  </form>
</template>
