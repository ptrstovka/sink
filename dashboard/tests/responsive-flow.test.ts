import { flushPromises, mount } from '@vue/test-utils'
import { describe, expect, it } from 'vitest'
import App from '@/App.vue'
import { trafficSourceKey } from '@/api/traffic-source'
import { avatar, checkout, checkoutDetail, detail } from './fixtures'
import { FakeTrafficSource } from './fake-source'

function mountApp(source: FakeTrafficSource) {
  return mount(App, {
    attachTo: document.body,
    global: {
      provide: { [trafficSourceKey as symbol]: source },
      stubs: { Toaster: true },
    },
  })
}

describe('responsive and accessible inspector flow', () => {
  it('keeps initial failures generic and offers an explicit retry', async () => {
    const rejectedSecret = 'secret-from-session-error'
    const source = new FakeTrafficSource()
    source.startSession.mockRejectedValueOnce(new Error(rejectedSecret))
    const wrapper = mountApp(source)
    await flushPromises()

    expect(wrapper.text()).toContain('Could not connect to the inspector')
    expect(wrapper.html()).not.toContain(rejectedSecret)
    const retry = wrapper.get('[aria-label="Retry inspector connection"]')
    expect(retry.text()).toBe('Retry')
    await retry.trigger('click')
    await flushPromises()
    expect(source.startSession).toHaveBeenCalledTimes(2)
    expect(wrapper.text()).toContain('Waiting for traffic')
    wrapper.unmount()
  })

  it('uses a concise retry label when transaction details fail', async () => {
    const source = new FakeTrafficSource()
    source.summaries = [checkout]
    source.getTransaction.mockRejectedValueOnce(new Error('temporary detail failure'))
    const wrapper = mountApp(source)
    await flushPromises()

    const retry = wrapper.get('[aria-label="Retry transaction details"]')
    expect(retry.text()).toBe('Retry')
    await retry.trigger('click')
    await flushPromises()
    expect(wrapper.find('[aria-label="Retry transaction details"]').exists()).toBe(false)
    expect(wrapper.get('article').attributes('aria-label')).toContain('POST /api/checkout')
    wrapper.unmount()
  })

  it('shows loading, empty, reconnecting, and retry states without polling', async () => {
    const source = new FakeTrafficSource()
    let resolveSession!: () => void
    source.startSession.mockImplementation(
      () =>
        new Promise((resolve) => {
          resolveSession = () => resolve({ apiVersion: 'v1', capture: { paused: false } })
        }),
    )
    const wrapper = mountApp(source)
    expect(wrapper.text()).toContain('Connecting to the local traffic inspector')

    resolveSession()
    await flushPromises()
    expect(wrapper.text()).toContain('Waiting for traffic')

    source.connection('reconnecting')
    await flushPromises()
    const offlineAlert = wrapper.get('[data-slot="alert"]')
    expect(offlineAlert.attributes('role')).toBe('status')
    expect(offlineAlert.get('[data-slot="alert-title"]').text()).toBe('Live updates offline')
    expect(offlineAlert.get('[data-slot="alert-description"]').text()).toContain('Existing captured data remains available.')
    expect(wrapper.get('[aria-label="Retry traffic refresh"]')).toBeTruthy()
    expect(source.listTransactions).toHaveBeenCalledTimes(1)

    source.connection('open')
    source.listTransactions.mockRejectedValueOnce(new Error('temporary refresh failure'))
    source.emit({ kind: 'resync_required', skipped: 0, reason: 'connection_opened' })
    await flushPromises()
    expect(wrapper.get('[data-slot="alert-title"]').text()).toBe('Traffic refresh failed')

    await wrapper.get('[aria-label="Retry traffic refresh"]').trigger('click')
    await flushPromises()
    expect(wrapper.find('[data-slot="alert"]').exists()).toBe(false)
    wrapper.unmount()
  })

  it('moves list to detail and back, supports list keyboard navigation, and exposes labeled controls', async () => {
    const source = new FakeTrafficSource()
    source.summaries = [checkout, avatar]
    source.details.set(checkout.id, checkoutDetail)
    source.details.set(avatar.id, detail(avatar))
    const wrapper = mountApp(source)
    await flushPromises()

    expect(wrapper.get('[aria-label="Traffic list"]')).toBeTruthy()
    expect(wrapper.get('[aria-label="Pause capture"]')).toBeTruthy()
    expect(wrapper.get('[aria-label^="Theme: system"]')).toBeTruthy()
    expect(wrapper.findAll('[role="combobox"]')).toHaveLength(3)
    const listButtons = wrapper.findAll('nav li button')
    expect(listButtons).toHaveLength(2)

    await listButtons[0]!.trigger('keydown', { key: 'ArrowDown' })
    await flushPromises()
    expect(wrapper.get('[data-mobile-view="detail"]')).toBeTruthy()
    expect(wrapper.get('article').attributes('aria-label')).toContain('PUT /api/users/82/avatar')
    expect(wrapper.findAll('[role="tab"]')).toHaveLength(2)
    const copyActions = wrapper.findAll('[data-slot="copy-action"]')
    expect(copyActions).toHaveLength(2)
    expect(copyActions.every((button) => button.text() === 'Copy')).toBe(true)

    await wrapper.get('[aria-label="Back to traffic list"]').trigger('click')
    expect(wrapper.get('[data-mobile-view="list"]')).toBeTruthy()
    expect(wrapper.get('[aria-current="true"]').attributes('aria-label')).toContain('PUT')

    await wrapper.get('[aria-label="Clear all captured traffic"]').trigger('click')
    const clearDialog = document.body.querySelector<HTMLElement>('[role="alertdialog"]')
    expect(clearDialog?.textContent).toContain('Clear all captured traffic?')
    expect(source.clearTransactions).not.toHaveBeenCalled()
    wrapper.unmount()
  })

  it('cycles light/dark/system theme and renders names-only cURL consent', async () => {
    const rejectedSecret = 'Bearer must-not-appear-in-confirmation'
    const source = new FakeTrafficSource()
    source.summaries = [checkout]
    source.details.set(checkout.id, checkoutDetail)
    source.generateCurl.mockResolvedValue({
      status: 'confirmation_required',
      headerNames: ['authorization', 'cookie'],
    })
    const wrapper = mountApp(source)
    await flushPromises()

    const theme = wrapper.get('[aria-label^="Theme: system"]')
    await theme.trigger('click')
    expect(wrapper.get('[aria-label^="Theme: light"]')).toBeTruthy()
    expect(document.documentElement.classList.contains('dark')).toBe(false)
    await wrapper.get('[aria-label^="Theme: light"]').trigger('click')
    expect(document.documentElement.classList.contains('dark')).toBe(true)

    await wrapper.get('[aria-label="Generate cURL command"]').trigger('click')
    await flushPromises()
    const dialog = document.body.querySelector<HTMLElement>('[role="alertdialog"]')
    expect(dialog?.textContent).toContain('authorization')
    expect(dialog?.textContent).toContain('cookie')
    expect(dialog?.innerHTML).not.toContain(rejectedSecret)
    expect(dialog?.textContent).not.toContain('Bearer')
    dialog?.querySelector<HTMLButtonElement>('button')?.click()
    await flushPromises()
    expect(source.generateCurl).toHaveBeenCalledTimes(1)
    wrapper.unmount()
  })

  it('keeps generated cURL selectable until an explicit copy action', async () => {
    const source = new FakeTrafficSource()
    source.summaries = [checkout]
    source.details.set(checkout.id, checkoutDetail)
    const command = "curl 'http://127.0.0.1:3000/'"
    source.generateCurl.mockResolvedValue({
      status: 'generated',
      command,
      containsSecrets: false,
    })
    const wrapper = mountApp(source)
    await flushPromises()

    await wrapper.get('[aria-label="Generate cURL command"]').trigger('click')
    await flushPromises()

    const commandText = wrapper.get('[aria-label="Generated cURL command text"]')
    expect(commandText.element).toHaveProperty('value', command)
    expect(document.activeElement).toBe(commandText.element)
    expect((commandText.element as HTMLTextAreaElement).selectionStart).toBe(0)
    expect((commandText.element as HTMLTextAreaElement).selectionEnd).toBe(command.length)
    expect(wrapper.get('[aria-label="Copy generated cURL command"]')).toBeTruthy()
    expect(wrapper.text()).not.toContain('Captured in memory')
    expect(wrapper.text()).not.toContain('Same-origin API')
    wrapper.unmount()
  })
})
