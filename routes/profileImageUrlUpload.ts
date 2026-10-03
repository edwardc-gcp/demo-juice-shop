/*
 * Copyright (c) 2014-2026 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

import fs from 'node:fs'
import dns from 'node:dns'
import net from 'node:net'
import { Readable } from 'node:stream'
import { finished } from 'node:stream/promises'
import { type Request, type Response, type NextFunction } from 'express'

import * as security from '../lib/insecurity'
import { UserModel } from '../models/user'
import * as utils from '../lib/utils'
import logger from '../lib/logger'

function isPrivateIPv4 (octets: number[]): boolean {
  if (octets.length !== 4 || octets.some(n => isNaN(n) || n < 0 || n > 255)) {
    return true
  }
  const [a, b, c] = octets
  if (a === 0) return true
  if (a === 10) return true
  if (a === 127) return true
  if (a === 169 && b === 254) return true
  if (a === 172 && b >= 16 && b <= 31) return true
  if (a === 192 && b === 168) return true
  if (a === 100 && b >= 64 && b <= 127) return true
  if (a === 192 && b === 0 && c === 0) return true
  if (a === 192 && b === 0 && c === 2) return true
  if (a === 192 && b === 88 && c === 99) return true
  if (a === 198 && (b === 18 || b === 19)) return true
  if (a === 198 && b === 51 && c === 100) return true
  if (a === 203 && b === 0 && c === 113) return true
  if (a >= 224) return true
  return false
}

function isPrivateIPv6 (ip: string): boolean {
  let cleanIp = ip.toLowerCase()
  if (cleanIp.startsWith('[') && cleanIp.endsWith(']')) {
    cleanIp = cleanIp.slice(1, -1)
  }
  cleanIp = cleanIp.split('%')[0]
  if (cleanIp.includes('.')) {
    const lastColon = cleanIp.lastIndexOf(':')
    const ipv4Part = cleanIp.slice(lastColon + 1)
    const v4Octets = ipv4Part.split('.').map(Number)
    if (v4Octets.length === 4 && v4Octets.every(n => !isNaN(n) && n >= 0 && n <= 255)) {
      if (isPrivateIPv4(v4Octets)) return true
      const hex1 = ((v4Octets[0] << 8) | v4Octets[1]).toString(16)
      const hex2 = ((v4Octets[2] << 8) | v4Octets[3]).toString(16)
      cleanIp = cleanIp.slice(0, lastColon + 1) + hex1 + ':' + hex2
    } else {
      return true
    }
  }
  const parts = cleanIp.split('::')
  if (parts.length > 2) return true
  const left = parts[0] ? parts[0].split(':') : []
  const right = parts[1] ? parts[1].split(':') : []
  const missing = 8 - (left.length + right.length)
  if (missing < 0) return true
  const middle: string[] = []
  if (parts.length > 1) {
    for (let i = 0; i < missing; i++) middle.push('0')
  }
  const words = [...left, ...middle, ...right].map(w => parseInt(w || '0', 16))
  if (words.length !== 8 || words.some(isNaN)) return true
  if (words.every(w => w === 0)) return true
  if (words.slice(0, 7).every(w => w === 0) && words[7] === 1) return true
  if (words.slice(0, 5).every(w => w === 0) && words[5] === 0xffff) {
    const octets = [
      (words[6] >> 8) & 0xff,
      words[6] & 0xff,
      (words[7] >> 8) & 0xff,
      words[7] & 0xff
    ]
    return isPrivateIPv4(octets)
  }
  if (words.slice(0, 6).every(w => w === 0)) {
    const octets = [
      (words[6] >> 8) & 0xff,
      words[6] & 0xff,
      (words[7] >> 8) & 0xff,
      words[7] & 0xff
    ]
    return isPrivateIPv4(octets)
  }
  if ((words[0] & 0xfe00) === 0xfc00) return true
  if ((words[0] & 0xffc0) === 0xfe80) return true
  if ((words[0] & 0xff00) === 0xff00) return true
  if (words[0] === 0x2001 && words[1] === 0x0db8) return true
  return false
}

async function isSafeUrl (rawUrl: string): Promise<boolean> {
  let parsedUrl: URL
  try {
    parsedUrl = new URL(rawUrl)
  } catch {
    return false
  }
  if (parsedUrl.protocol !== 'http:' && parsedUrl.protocol !== 'https:') {
    return false
  }
  let hostname = parsedUrl.hostname.toLowerCase()
  hostname = hostname.replace(/\.+$/, '')
  if (hostname.startsWith('[') && hostname.endsWith(']')) {
    hostname = hostname.slice(1, -1)
  }
  if (!hostname) {
    return false
  }
  if (
    hostname === 'localhost' ||
    hostname.endsWith('.localhost') ||
    hostname.endsWith('.local') ||
    hostname.endsWith('.internal') ||
    hostname.endsWith('.lan') ||
    hostname.endsWith('.home.arpa') ||
    hostname === 'instance-data' ||
    hostname === 'metadata.google.internal' ||
    hostname === 'metadata'
  ) {
    return false
  }
  const ipType = net.isIP(hostname)
  if (ipType === 4) {
    const octets = hostname.split('.').map(Number)
    return !isPrivateIPv4(octets)
  } else if (ipType === 6) {
    return !isPrivateIPv6(hostname)
  }
  try {
    const addresses = await dns.promises.lookup(hostname, { all: true })
    if (!addresses || addresses.length === 0) {
      return false
    }
    for (const addr of addresses) {
      if (addr.family === 4) {
        const octets = addr.address.split('.').map(Number)
        if (isPrivateIPv4(octets)) return false
      } else if (addr.family === 6) {
        if (isPrivateIPv6(addr.address)) return false
      }
    }
  } catch {
    return false
  }
  return true
}

async function safeFetch (initialUrl: string, maxRedirects = 5): Promise<Awaited<ReturnType<typeof fetch>>> {
  let currentUrl = initialUrl
  for (let i = 0; i <= maxRedirects; i++) {
    if (!(await isSafeUrl(currentUrl))) {
      throw new Error('Unsafe or blocked URL: ' + currentUrl)
    }
    const response = await fetch(currentUrl, { redirect: 'manual' })
    if ([301, 302, 303, 307, 308].includes(response.status)) {
      const location = response.headers.get('location')
      if (!location) {
        throw new Error('Redirect response missing location header')
      }
      currentUrl = new URL(location, currentUrl).toString()
      continue
    }
    return response
  }
  throw new Error('Too many redirects')
}

export function profileImageUrlUpload () {
  return async (req: Request, res: Response, next: NextFunction) => {
    if (req.body.imageUrl !== undefined) {
      const url = req.body.imageUrl
      if (typeof url === 'string' && url.match(/(.)*solve\/challenges\/server-side(.)*/) !== null) req.app.locals.abused_ssrf_bug = true
      const loggedInUser = security.authenticatedUsers.get(req.cookies.token)
      if (loggedInUser) {
        if (typeof url !== 'string' || !(await isSafeUrl(url))) {
          next(new Error('Blocked illegal activity by ' + req.socket.remoteAddress))
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
          if (error instanceof Error && error.message.startsWith('Unsafe or blocked URL')) {
            next(new Error('Blocked illegal activity by ' + req.socket.remoteAddress))
            return
          }
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
