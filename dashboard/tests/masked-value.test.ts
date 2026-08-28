import { flushPromises, mount } from '@vue/test-utils'
import { describe, expect, it, vi } from 'vitest'
import MaskedValue from '@/components/MaskedValue.vue'

describe('MaskedValue', () => {
  it('shows a generic reveal failure without exposing the rejected error', async () => {
    const rejectedSecret = 'Bearer leaked-from-rejected-error'
    const reveal = vi.fn().mockRejectedValue(new Error(rejectedSecret))
    const wrapper = mount(MaskedValue, {
      props: {
        header: {
          id: 'authorization',
          name: 'authorization',
          sensitive: true,
          valueState: 'masked',
        },
        label: 'authorization header',
        reveal,
      },
    })

    await wrapper.get('[aria-label="Reveal authorization header"]').trigger('click')
    await flushPromises()

    expect(reveal).toHaveBeenCalledOnce()
    expect(wrapper.text()).toContain('Could not reveal this header value. Try again.')
    expect(wrapper.html()).not.toContain(rejectedSecret)
  })

  it('shows ordinary values without a reveal control', () => {
    const reveal = vi.fn()
    const wrapper = mount(MaskedValue, {
      props: {
        header: {
          id: 'content-type',
          name: 'content-type',
          value: 'application/json',
          sensitive: false,
        },
        label: 'content-type header',
        reveal,
      },
    })

    expect(wrapper.text()).toContain('application/json')
    expect(wrapper.find('button').exists()).toBe(false)
    expect(reveal).not.toHaveBeenCalled()
  })

  it('clears a revealed value on hide and when the selected header changes', async () => {
    const firstSecret = 'revealed-first-header-only'
    const reveal = vi.fn().mockResolvedValue(firstSecret)
    const wrapper = mount(MaskedValue, {
      props: {
        header: {
          id: 'request:1',
          name: 'authorization',
          sensitive: true,
          valueState: 'masked',
        },
        label: 'authorization header',
        reveal,
      },
    })

    await wrapper.get('[aria-label="Reveal authorization header"]').trigger('click')
    await flushPromises()
    expect(wrapper.text()).toContain(firstSecret)
    await wrapper.get('[aria-label="Hide authorization header"]').trigger('click')
    expect(wrapper.text()).not.toContain(firstSecret)

    await wrapper.get('[aria-label="Reveal authorization header"]').trigger('click')
    await flushPromises()
    await wrapper.setProps({
      header: {
        id: 'request:2',
        name: 'cookie',
        sensitive: true,
        valueState: 'masked',
      },
      label: 'cookie header',
    })
    expect(wrapper.text()).not.toContain(firstSecret)
    expect(wrapper.get('[aria-label="Reveal cookie header"]').attributes('aria-pressed')).toBe('false')
  })

  it('keeps a revealed value across live refreshes of the same identified header', async () => {
    const reveal = vi.fn().mockResolvedValue('Bearer stable-across-refresh')
    const header = {
      id: 'request:1',
      name: 'authorization',
      sensitive: true as const,
      valueState: 'masked' as const,
    }
    const wrapper = mount(MaskedValue, {
      props: { header, label: 'authorization header', reveal },
    })

    await wrapper.get('[aria-label="Reveal authorization header"]').trigger('click')
    await flushPromises()
    await wrapper.setProps({ header: { ...header } })

    expect(wrapper.text()).toContain('Bearer stable-across-refresh')
    expect(wrapper.get('[aria-label="Hide authorization header"]')).toBeTruthy()
  })
})
