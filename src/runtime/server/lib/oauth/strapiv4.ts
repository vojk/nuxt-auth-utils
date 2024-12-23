import type { H3Event } from 'h3'
import { eventHandler, createError, readBody } from 'h3'
import { useRuntimeConfig } from '#imports'
import { handleMissingConfiguration, handleAccessTokenErrorResponse } from '../utils'

export interface EmailAuthStrapiConfig {
  /**
   * Strapi email provider URL
   * @default process.env.NUXT_OAUTH_STRAPI_DOMAIN
   */
  domain?: string
}

export function defineEmailAuthStrapiEventHandler({
  config,
  onSuccess,
  onError,
}: {
  config: EmailAuthStrapiConfig
  onSuccess: (event: H3Event, data: { tokens: { access_token: string }; user: object }) => Promise<void>
  onError: (event: H3Event, error: Error) => Promise<void>
}) {
  return eventHandler(async (event: H3Event) => {
    // Merge runtime configuration with provided config
    config = { ...useRuntimeConfig(event).oauth?.strapi, ...config } as EmailAuthStrapiConfig

    if (!config.domain) {
      return handleMissingConfiguration(event, 'strapi', ['domain'], onError)
    }

    // Extract user credentials from the request body
    const body = await readBody(event) // Use `readBody` to get the POST request payload
    if (!body || !body.identifier || !body.password) {
      throw createError({
        statusCode: 400,
        statusMessage: 'Missing identifier or password',
      })
    }

    const userCredentials = {
      identifier: body.identifier,
      password: body.password,
    }

    // Request access token from Strapi
    let response
    try {
      response = await $fetch(`${config.domain}/auth/local`, {
        method: 'POST',
        body: userCredentials,
      })
    } catch (error) {
      return onError(event, error)
    }

    // Check for errors in Strapi's response
    if (!response || response.error) {
      return handleAccessTokenErrorResponse(event, 'strapi', response, onError)
    }

    const accessToken = response.jwt

    // Fetch authenticated user information
    let user
    try {
      user = await $fetch(`${config.domain}/users/me`, {
        headers: {
          Authorization: `Bearer ${accessToken}`,
        },
      })
    } catch (error) {
      return onError(event, error)
    }

    // Call success callback with tokens and user data
    return onSuccess(event, {
      tokens: { access_token: accessToken },
      user,
    })
  })
}
