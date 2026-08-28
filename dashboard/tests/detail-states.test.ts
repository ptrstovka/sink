import { flushPromises, mount } from '@vue/test-utils'
import { describe, expect, it, vi } from 'vitest'
import InspectorDetail from '@/components/InspectorDetail.vue'
import PayloadViewer from '@/components/PayloadViewer.vue'
import { avatar, checkout, checkoutDetail, textBody } from './fixtures'

describe('detail states', () => {
  it('renders lazy loading, body truncation, and replay ineligibility', async () => {
    const truncated = textBody('bounded preview')
    truncated.truncated = true
    truncated.retention = 'truncated'
    truncated.transferredBytes = 2048
    truncated.retainedBytes = 15

    const wrapper = mount(InspectorDetail, {
      props: {
        summary: avatar,
        detail: null,
        detailState: 'loading',
        activeTab: 'request',
        source: { revealHeader: vi.fn() },
        actionPending: null,
        capturePaused: false,
        generatedCurl: null,
      },
    })
    expect(wrapper.text()).toContain('Loading selected transaction')
    expect(wrapper.text()).toContain('Replay unavailable')

    await wrapper.setProps({
      detail: {
        ...checkoutDetail,
        ...avatar,
        request: { ...checkoutDetail.request, body: truncated },
      },
      detailState: 'ready',
    })
    expect(wrapper.text()).toContain('Truncated')
    expect(wrapper.text()).toContain('2 KiB transferred')
    expect(wrapper.getComponent(PayloadViewer).text()).not.toContain('retained')
    expect(wrapper.text()).not.toContain('Captured bodies may contain application secrets')
    expect(wrapper.get('[aria-label^="Replay unavailable:"]').attributes()).toHaveProperty('disabled')
  })

  it('formats JSON and exposes raw fallback without a runtime dependency', async () => {
    const body = checkoutDetail.request.body
    const wrapper = mount(PayloadViewer, { props: { body, label: 'Request' } })
    expect(wrapper.get('pre').text()).toContain('\n  "cartId": "cart_842"')

    await wrapper.get('button[aria-pressed="false"]').trigger('click')
    expect(wrapper.get('pre').text()).toBe(body.text)
  })

  it('distinguishes valid scalar JSON from invalid raw fallback', async () => {
    const scalar = textBody('1', 'json')
    const scalarWrapper = mount(PayloadViewer, { props: { body: scalar, label: 'Request' } })
    expect(scalarWrapper.text()).not.toContain('Invalid JSON')

    const invalid = textBody('{not-json', 'json')
    const invalidWrapper = mount(PayloadViewer, { props: { body: invalid, label: 'Request' } })
    expect(invalidWrapper.get('pre').text()).toBe('{not-json')
    expect(invalidWrapper.text()).toContain('Invalid JSON; showing raw body.')
  })

  it('reveals one identified header only after success and clears it on hide', async () => {
    const revealedSecret = 'Bearer revealed-only-after-success'
    let resolveReveal!: (value: string) => void
    const revealHeader = vi.fn(
      () =>
        new Promise<string>((resolve) => {
          resolveReveal = resolve
        }),
    )
    const wrapper = mount(InspectorDetail, {
      props: {
        summary: checkout,
        detail: checkoutDetail,
        detailState: 'ready',
        activeTab: 'request',
        source: { revealHeader },
        actionPending: null,
        capturePaused: false,
        generatedCurl: null,
      },
    })

    await wrapper.get('[aria-label="Reveal authorization header"]').trigger('click')
    resolveReveal(revealedSecret)
    await flushPromises()
    expect(wrapper.text()).toContain(revealedSecret)

    await wrapper.get('[aria-label="Hide authorization header"]').trigger('click')
    expect(wrapper.text()).not.toContain(revealedSecret)
    wrapper.unmount()
  })
})
