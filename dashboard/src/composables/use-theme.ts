import { computed, onBeforeUnmount, ref, watch, type Ref } from 'vue'

export type ThemePreference = 'system' | 'light' | 'dark'

const STORAGE_KEY = 'sink-inspector-theme'

function savedPreference(storage: Pick<Storage, 'getItem'> | null): ThemePreference {
  try {
    const saved = storage?.getItem(STORAGE_KEY)
    if (saved === 'light' || saved === 'dark' || saved === 'system') return saved
  } catch {
    // Theme persistence is optional; the dashboard remains usable without storage.
  }
  return 'system'
}

export function useTheme(
  root: HTMLElement = document.documentElement,
  media: MediaQueryList = window.matchMedia('(prefers-color-scheme: dark)'),
  storage: Pick<Storage, 'getItem' | 'setItem'> | null = window.localStorage,
) {
  const preference = ref<ThemePreference>(savedPreference(storage))
  const systemDark = ref(media.matches)
  const effective = computed<'light' | 'dark'>(() =>
    preference.value === 'system' ? (systemDark.value ? 'dark' : 'light') : preference.value,
  )

  function apply() {
    const dark = effective.value === 'dark'
    root.classList.toggle('dark', dark)
  }

  function systemChanged(event: MediaQueryListEvent) {
    systemDark.value = event.matches
    apply()
  }

  watch(
    [preference, effective],
    () => {
      apply()
      try {
        storage?.setItem(STORAGE_KEY, preference.value)
      } catch {
        // A blocked storage backend must not break theme switching.
      }
    },
    { immediate: true },
  )
  media.addEventListener('change', systemChanged)
  onBeforeUnmount(() => media.removeEventListener('change', systemChanged))

  function cycle() {
    const choices: readonly ThemePreference[] = ['system', 'light', 'dark']
    const index = choices.indexOf(preference.value)
    preference.value = choices[(index + 1) % choices.length]!
  }

  return { preference: preference as Ref<ThemePreference>, effective, cycle }
}
