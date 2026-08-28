import { flushPromises } from '@vue/test-utils'
import { describe, expect, it, vi } from 'vitest'
import { useLiveInspector } from '@/composables/use-live-inspector'
import { checkout, checkoutDetail } from './fixtures'
import { FakeTrafficSource } from './fake-source'

describe('copy, replay, and cURL actions', () => {
  it('copies URL, masked-safe headers, and bodies with visible success feedback', async () => {
    const source = new FakeTrafficSource()
    source.summaries = [checkout]
    source.details.set(checkout.id, checkoutDetail)
    const copy = vi.fn().mockResolvedValue(undefined)
    const state = useLiveInspector(source, { copy })
    await state.start()
    await flushPromises()

    await state.copyUrl()
    expect(copy).toHaveBeenLastCalledWith(checkout.url)
    expect(state.feedback.value?.message).toBe('Request URL copied.')

    await state.copyHeaders('request')
    expect(copy).toHaveBeenLastCalledWith(
      'content-type: application/json\nauthorization: [masked]',
    )
    expect(copy.mock.calls.at(-1)?.[0]).not.toContain('Bearer')

    await state.copyBody('request')
    expect(copy).toHaveBeenLastCalledWith('{"cartId":"cart_842"}')
    state.stop()
  })

  it('keeps ordinary clipboard failures generic', async () => {
    const rejectedSecret = 'clipboard-rejection-secret'
    const source = new FakeTrafficSource()
    source.summaries = [checkout]
    const state = useLiveInspector(source, {
      copy: vi.fn().mockRejectedValue(new Error(rejectedSecret)),
    })
    await state.start()
    await state.copyUrl()

    expect(state.feedback.value?.message).toContain('Could not copy to the clipboard')
    expect(JSON.stringify(state.feedback.value)).not.toContain(rejectedSecret)
    state.stop()
  })

  it('shows a generated non-sensitive cURL command and copies only on a fresh user action', async () => {
    const source = new FakeTrafficSource()
    source.summaries = [checkout]
    const copy = vi.fn().mockResolvedValue(undefined)
    const state = useLiveInspector(source, { copy })
    await state.start()

    await state.requestCurl()
    expect(source.generateCurl).toHaveBeenCalledWith(checkout.id, false)
    expect(copy).not.toHaveBeenCalled()
    expect(state.curlConfirmation.value).toBeNull()
    expect(state.generatedCurl.value).toEqual({
      transactionId: checkout.id,
      command: "curl 'http://127.0.0.1:3000/'",
      containsSecrets: false,
    })

    await state.copyGeneratedCurl()
    expect(copy).toHaveBeenCalledWith("curl 'http://127.0.0.1:3000/'")
    expect(state.feedback.value?.message).toBe('cURL command copied.')
    state.stop()
  })

  it('shows names-only consent, then displays secrets without copying until a fresh action', async () => {
    const commandWithSecret = "curl -H 'authorization: Bearer confirmed-only' http://127.0.0.1"
    const source = new FakeTrafficSource()
    source.summaries = [checkout]
    source.generateCurl
      .mockResolvedValueOnce({
        status: 'confirmation_required',
        headerNames: ['authorization', 'cookie'],
      })
      .mockResolvedValueOnce({
        status: 'generated',
        command: commandWithSecret,
        containsSecrets: true,
      })
    const copy = vi.fn().mockResolvedValue(undefined)
    const state = useLiveInspector(source, { copy })
    await state.start()

    await state.requestCurl()
    expect(source.generateCurl).toHaveBeenCalledWith(checkout.id, false)
    expect(state.curlConfirmation.value).toEqual({
      transactionId: checkout.id,
      headerNames: ['authorization', 'cookie'],
    })
    expect(JSON.stringify(state.curlConfirmation.value)).not.toContain('confirmed-only')
    expect(copy).not.toHaveBeenCalled()

    await state.confirmSensitiveCurl()
    expect(source.generateCurl).toHaveBeenLastCalledWith(checkout.id, true)
    expect(copy).not.toHaveBeenCalled()
    expect(state.curlConfirmation.value).toBeNull()
    expect(state.generatedCurl.value).toEqual({
      transactionId: checkout.id,
      command: commandWithSecret,
      containsSecrets: true,
    })

    await state.copyGeneratedCurl()
    expect(copy).toHaveBeenCalledWith(commandWithSecret)
    expect(JSON.stringify(state.feedback.value)).not.toContain(commandWithSecret)
    state.stop()
  })

  it('cancels cURL confirmation without a second API or clipboard call', async () => {
    const source = new FakeTrafficSource()
    source.summaries = [checkout]
    source.generateCurl.mockResolvedValue({
      status: 'confirmation_required',
      headerNames: ['authorization'],
    })
    const copy = vi.fn()
    const state = useLiveInspector(source, { copy })
    await state.start()
    await state.requestCurl()
    state.cancelSensitiveCurl()

    expect(source.generateCurl).toHaveBeenCalledTimes(1)
    expect(copy).not.toHaveBeenCalled()
    expect(state.feedback.value).toBeNull()
    state.stop()
  })

  it('discards a late cURL result after stop without reaching state or clipboard', async () => {
    let resolveCurl!: (value: {
      status: 'generated'
      command: string
      containsSecrets: boolean
    }) => void
    const source = new FakeTrafficSource()
    source.summaries = [checkout]
    source.generateCurl.mockImplementation(
      () =>
        new Promise((resolve) => {
          resolveCurl = resolve
        }),
    )
    const copy = vi.fn().mockResolvedValue(undefined)
    const state = useLiveInspector(source, { copy })
    await state.start()

    const request = state.requestCurl()
    state.stop()
    resolveCurl({
      status: 'generated',
      command: "curl -H 'authorization: late-value' http://127.0.0.1",
      containsSecrets: true,
    })
    await request

    expect(copy).not.toHaveBeenCalled()
    expect(state.curlConfirmation.value).toBeNull()
    expect(state.generatedCurl.value).toBeNull()
    expect(state.feedback.value).toBeNull()
  })
})
