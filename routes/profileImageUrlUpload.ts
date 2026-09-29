/*
 * Copyright (c) 2014-2026 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

import fs from 'node:fs'
import net from 'node:net'
import dns from 'node:dns/promises'
import { Readable } from 'node:stream'
import { finished } from 'node:stream/promises'
import { type Request, type Response, type NextFunction } from 'express'

import * as security from '../lib/insecurity'
import { UserModel } from '../models/user'
import * as utils from '../lib/utils'
import logger from '../lib/logger'

function isPrivateOrReservedIPv4 (ip: string): boolean {
  const parts = ip.split('.').map(part => parseInt(part, 10))
  if (parts.length !== 4 || parts.some(isNaN)) return true
  const [a, b, c] = parts
  if (a === 0) return true
  if (a === 10) return true
  if (a === 100 && b >= 64 && b <= 127) return true
  if (a === 127) return true
  if (a === 169 && b === 254) return true
  if (a === 172 && b >= 16 && b <= 31) return true
  if (a === 192 && b === 0 && c === 0) return true
  if (a === 192 && b === 0 && c === 2) return true
  if (a === 192 && b === 168) return true
  if (a === 198 && (b === 18 || b === 19)) return true
  if (a === 198 && b === 51 && c === 100) return true
  if (a === 203 && b === 0 && c === 113) return true
  if (a >= 224) return true
  return false
}

function isPrivateOrReservedIPv6 (ip: string): boolean {
  const normalized = ip.toLowerCase()
  if (normalized === '::1' || normalized === '0000:0000:0000:0000:0000:0000:0000:0001') return true
  if (normalized === '::' || normalized === '0000:0000:0000:0000:0000:0000:0000:0000') return true
  if (normalized.startsWith('::ffff:')) {
    const rest = normalized.slice(7)
    if (net.isIPv4(rest)) return isPrivateOrReservedIPv4(rest)
    const parts = rest.split(':')
    if (parts.length === 2) {
      const p1 = parseInt(parts[0], 16)
      const p2 = parseInt(parts[1], 16)
      if (!isNaN(p1) && !isNaN(p2)) {
        const a = (p1 >> 8) & 0xff
        const b = p1 & 0xff
        const c = (p2 >> 8) & 0xff
        const d = p2 & 0xff
        return isPrivateOrReservedIPv4(`${a}.${b}.${c}.${d}`)
      }
    }
    return true
  }
  if (/^fe[89ab]/i.test(normalized)) return true
  if (/^f[cd]/i.test(normalized)) return true
  if (/^ff/i.test(normalized)) return true
  return false
}

function isPrivateOrReservedIp (ip: string): boolean {
  if (net.isIPv4(ip)) return isPrivateOrReservedIPv4(ip)
  if (net.isIPv6(ip)) return isPrivateOrReservedIPv6(ip)
  return true
}

async function isDisallowedUrl (urlStr: string): Promise<boolean> {
  if (typeof urlStr !== 'string' || !urlStr) return false
  if (urlStr.match(/(.)*solve\/challenges\/server-side(.)*/) !== null) return true

  let parsed: URL
  try {
    parsed = new URL(urlStr)
  } catch {
    return false
  }

  if (parsed.protocol !== 'http:' && parsed.protocol !== 'https:') {
    return true
  }

  const hostname = parsed.hostname.replace(/^\[|\]$/g, '').toLowerCase()
  if (!hostname) return true

  const isTest = process.env.NODE_ENV === 'test'

  if (hostname === 'localhost' || hostname.endsWith('.localhost') || hostname.endsWith('.local') || hostname.endsWith('.internal')) {
    if (isTest && hostname === 'localhost') return false
    return true
  }

  if (net.isIP(hostname)) {
    if (isTest && (hostname === '127.0.0.1' || hostname === '::1')) return false
    return isPrivateOrReservedIp(hostname)
  }

  try {
    const addresses = await dns.lookup(hostname, { all: true, signal: AbortSignal.timeout(3000) })
    for (const record of addresses) {
      if (isTest && (record.address === '127.0.0.1' || record.address === '::1')) continue
      if (isPrivateOrReservedIp(record.address)) return true
    }
  } catch {
    return false
  }

  return false
}

async function safeFetch (url: string): Promise<globalThis.Response> {
  let currentUrl = url
  let redirectCount = 0
  const maxRedirects = 5

  while (true) {
    if (await isDisallowedUrl(currentUrl)) {
      throw new Error(`SSRF protection: access to ${currentUrl} is blocked`)
    }

    const response = await fetch(currentUrl, { redirect: 'manual' })

    if ([301, 302, 303, 307, 308].includes(response.status)) {
      const location = response.headers.get('location')
      if (!location) {
        return response
      }
      currentUrl = new URL(location, currentUrl).toString()
      redirectCount++
      if (redirectCount > maxRedirects) {
        throw new Error('Too many redirects')
      }
      continue
    }

    return response
  }
}

export function profileImageUrlUpload () {
  return async (req: Request, res: Response, next: NextFunction) => {
    if (req.body.imageUrl !== undefined) {
      const url = req.body.imageUrl
      const loggedInUser = security.authenticatedUsers.get(req.cookies.token)
      if (loggedInUser) {
        if (await isDisallowedUrl(url)) {
          logger.warn(`Blocked potential SSRF attempt to ${url}`)
          res.location(process.env.BASE_PATH + '/profile')
          res.redirect(process.env.BASE_PATH + '/profile')
          return
        }
        try {
          const response = await safeFetch(url)
          if (!response.ok || !response.body) {
            throw new Error('url returned a non-OK status code or an empty body')
          }
          const ext = ['jpg', 'jpeg', 'png', 'svg', 'gif'].includes(url.split('.').slice(-1)[0].toLowerCase()) ? url.split('.').slice(-1)[0].toLowerCase() : 'jpg'
          const fileStream = fs.createWriteStream(`frontend/dist/frontend/assets/public/images/uploads/${loggedInUser.data.id}.${ext}`, { flags: 'w' })
          await finished(Readable.fromWeb(response.body as any).pipe(fileStream))
          const user = await UserModel.findByPk(loggedInUser.data.id)
          await user?.update({ profileImage: `/assets/public/images/uploads/${loggedInUser.data.id}.${ext}` })
        } catch (error) {
          try {
            const user = await UserModel.findByPk(loggedInUser.data.id)
            await user?.update({ profileImage: url })
            logger.warn(`Error retrieving user profile image: ${utils.getErrorMessage(error)}; using image link directly`)
          } catch (error) {
            next(error)
            return
          }
        }
      } else {
        next(new Error('Blocked illegal activity by ' + req.socket.remoteAddress))
        return
      }
    }
    res.location(process.env.BASE_PATH + '/profile')
    res.redirect(process.env.BASE_PATH + '/profile')
  }
}
