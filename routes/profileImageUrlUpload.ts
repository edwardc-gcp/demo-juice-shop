/*
 * Copyright (c) 2014-2026 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

import fs from 'node:fs'
import { Readable } from 'node:stream'
import { finished } from 'node:stream/promises'
import { type Request, type Response, type NextFunction } from 'express'
import net from 'node:net'
import dns from 'node:dns'

import * as security from '../lib/insecurity'
import { UserModel } from '../models/user'
import * as utils from '../lib/utils'
import logger from '../lib/logger'

function isPrivateOrReservedIPv4 (ip: string): boolean {
  const parts = ip.split('.').map(part => Number(part))
  if (parts.length !== 4 || parts.some(p => isNaN(p) || p < 0 || p > 255)) {
    return true
  }
  const [a, b, c, d] = parts
  if (a === 0) return true
  if (a === 10) return true
  if (a === 100 && b >= 64 && b <= 127) return true
  if (a === 127) return true
  if (a === 169 && b === 254) return true
  if (a === 172 && b >= 16 && b <= 31) return true
  if (a === 192 && b === 0 && c === 0) return true
  if (a === 192 && b === 0 && c === 2) return true
  if (a === 192 && b === 88 && c === 99) return true
  if (a === 192 && b === 168) return true
  if (a === 198 && (b === 18 || b === 19)) return true
  if (a === 198 && b === 51 && c === 100) return true
  if (a === 203 && b === 0 && c === 113) return true
  if (a >= 224) return true
  return false
}

function isPrivateOrReservedIPv6 (ip: string): boolean {
  try {
    const parts = ip.split('::')
    let head = parts[0] ? parts[0].split(':') : []
    let tail = parts[1] ? parts[1].split(':') : []
    if (parts.length === 1) {
      head = ip.split(':')
      tail = []
    }
    const lastPart = (tail.length > 0 ? tail : head)[(tail.length > 0 ? tail : head).length - 1]
    if (lastPart && lastPart.includes('.')) {
      const octets = lastPart.split('.').map(Number)
      if (octets.length !== 4 || octets.some(p => isNaN(p) || p < 0 || p > 255)) return true
      const h1 = ((octets[0] << 8) | octets[1]).toString(16)
      const h2 = ((octets[2] << 8) | octets[3]).toString(16)
      if (tail.length > 0) {
        tail.pop()
        tail.push(h1, h2)
      } else {
        head.pop()
        head.push(h1, h2)
      }
    }
    const fill = 8 - (head.length + tail.length)
    if (fill < 0) return true
    const full = [...head, ...Array(fill).fill('0'), ...tail]
    const num = full.reduce((acc, h) => (acc << 16n) + BigInt(parseInt(h || '0', 16)), 0n)

    if (num === 0n || num === 1n) return true

    if ((num >> 32n) === 0xffffn) {
      const ipv4Int = Number(num & 0xffffffffn)
      const a = (ipv4Int >>> 24) & 0xff
      const b = (ipv4Int >>> 16) & 0xff
      const c = (ipv4Int >>> 8) & 0xff
      const d = ipv4Int & 0xff
      return isPrivateOrReservedIPv4(`${a}.${b}.${c}.${d}`)
    }

    const firstHextet = Number(num >> 112n)
    if ((firstHextet & 0xffc0) === 0xfe80) return true
    if ((firstHextet & 0xfe00) === 0xfc00) return true
    if ((firstHextet & 0xff00) === 0xff00) return true

    const firstTwoHextets = Number(num >> 96n)
    if (firstTwoHextets === 0x20010db8) return true
    if ((num >> 64n) === 0x1000000000000n) return true

    return false
  } catch {
    return true
  }
}

async function isSafeUrl (url: string): Promise<boolean> {
  if (typeof url !== 'string' || !url.trim()) {
    return false
  }
  let parsedUrl: URL
  try {
    parsedUrl = new URL(url)
  } catch {
    return false
  }

  if (parsedUrl.protocol !== 'http:' && parsedUrl.protocol !== 'https:') {
    return false
  }

  const hostname = parsedUrl.hostname.toLowerCase().replace(/^\[|\]$/g, '')
  if (!hostname) {
    return false
  }

  if (
    hostname === 'localhost' ||
    hostname.endsWith('.localhost') ||
    hostname.endsWith('.local') ||
    hostname.endsWith('.internal')
  ) {
    return false
  }

  const ipFamily = net.isIP(hostname)
  if (ipFamily === 4) {
    return !isPrivateOrReservedIPv4(hostname)
  }
  if (ipFamily === 6) {
    return !isPrivateOrReservedIPv6(hostname)
  }

  try {
    const addresses = await dns.promises.lookup(hostname, { all: true })
    if (addresses.length === 0) {
      return false
    }
    for (const addr of addresses) {
      if (addr.family === 4 && isPrivateOrReservedIPv4(addr.address)) {
        return false
      }
      if (addr.family === 6 && isPrivateOrReservedIPv6(addr.address)) {
        return false
      }
    }
  } catch {
    return false
  }

  return true
}

export function profileImageUrlUpload () {
  return async (req: Request, res: Response, next: NextFunction) => {
    if (req.body.imageUrl !== undefined) {
      const url = req.body.imageUrl
      const loggedInUser = security.authenticatedUsers.get(req.cookies.token)
      if (loggedInUser) {
        if (!await isSafeUrl(url)) {
          next(new Error('Blocked illegal activity by ' + req.socket.remoteAddress))
          return
        }
        try {
          let currentUrl = url
          let response: any = null
          for (let redirectCount = 0; redirectCount < 5; redirectCount++) {
            if (!await isSafeUrl(currentUrl)) {
              next(new Error('Blocked illegal activity by ' + req.socket.remoteAddress))
              return
            }
            const res: any = await fetch(currentUrl, { redirect: 'manual' })
            if (res.status >= 300 && res.status < 400 && res.headers.has('location')) {
              const location = res.headers.get('location')
              if (!location) {
                response = res
                break
              }
              currentUrl = new URL(location, currentUrl).toString()
            } else {
              response = res
              break
            }
          }
          if (!response || !response.ok || !response.body) {
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
