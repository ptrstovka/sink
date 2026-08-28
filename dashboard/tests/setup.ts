import { afterEach } from 'vitest'

Object.defineProperty(window, 'matchMedia', {
  configurable: true,
  value: (query: string) => ({
    matches: false,
    media: query,
    onchange: null,
    addEventListener: () => undefined,
    removeEventListener: () => undefined,
    addListener: () => undefined,
    removeListener: () => undefined,
    dispatchEvent: () => true,
  }),
})

afterEach(() => {
  document.body.innerHTML = ''
  document.documentElement.classList.remove('dark')
  window.localStorage.clear()
})
