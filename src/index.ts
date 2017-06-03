/*
 * Copyright 2017 Stephane M. Catala
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *  http://www.apache.org/licenses/LICENSE-2.0
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * Limitations under the License.
 */
;
import { isString, isNumber, isArrayBuffer } from './utils'

export interface Pbkdf2Sha512Factory {
  (config?: Partial<Pbkdf2Sha512Config&Pbkdf2Sha512Opts>): (password: Buffer|Uint8Array|string) => Promise<Pbkdf2sha512Digest>
}

export interface Pbkdf2Sha512Config {
  encoding: string
  salt: Buffer|Uint8Array|string|number
  iterations: number
  length: number
  relaxed: boolean
}

export interface Pbkdf2Sha512Opts {
  pbkdf2: (password: string|Buffer, salt: string|Buffer, iterations: number,
  length: number, digest: string, callback: (err: any, digest: Buffer) => void) => void
  randombytes: (length: number) => Buffer
}

export interface Pbkdf2sha512Digest {
  value: Buffer|string
  spec: Pbkdf2sha512DigestSpec
}

export interface Pbkdf2sha512DigestSpec {
  encoding: string
  salt: Buffer|string
  iterations: number
  length: number
  hmac: 'sha512'
}

interface Pbkdf2Sha512Spec {
  encoding: string
  salt: { bytes: Buffer, chars?: string }
  iterations: number
  length: number
}

const PBKDF2_CONFIG_DEFAULTS = {
  encoding: [ 'base64', 'utf8', 'latin1', 'binary', 'ascii', 'hex', 'none' ], // default: encoding[0]
  salt: { default: 64, min: 32 },
  iterations: { default: 65536, min: 8192 },
  length: { default: 64, min: 32, max: 64 } // limit to sha512 length
}

class Pbkdf2Sha512Class implements Pbkdf2Sha512Spec {
  static getKdf: Pbkdf2Sha512Factory =
  function (config?: Partial<Pbkdf2Sha512Config&Pbkdf2Sha512Opts>) {
    const pbkdf2 = config && config.pbkdf2 || require('pbkdf2').pbkdf2
    const randombytes = config && config.randombytes || require('randombytes')
    const spec = getPbkdf2Sha512Spec(randombytes, config)
    const pbkdf2sha512 =
    new Pbkdf2Sha512Class(pbkdf2, spec.encoding, spec.salt, spec.iterations, spec.length)

    return function (password: Buffer|Uint8Array|string): Promise<Pbkdf2sha512Digest> {
      const pwbytes = toBufferIfUintArray(toBufferIfString(password, 'utf8'))

      return Buffer.isBuffer(pwbytes)
      ? pbkdf2sha512.hash(pwbytes)
      : Promise.reject(new TypeError('invalid password'))
    }
  }

  hash (password: Buffer): Promise<Pbkdf2sha512Digest> {
    const spec: Pbkdf2sha512DigestSpec = {
      encoding: this.encoding,
      salt: this.salt.chars || this.salt.bytes,
      iterations: this.iterations,
      length: this.length,
      hmac: this.hmac
    }

    return new Promise<Pbkdf2sha512Digest>((resolve, reject) => {
      this.pbkdf2(password, this.salt.bytes, this.iterations, this.length, this.hmac,
      (err: any, digest: Buffer) => {
        if (err) { reject(err) }
        const hash: Pbkdf2sha512Digest = {
          value: this.encoding === 'none' ? digest : digest.toString(this.encoding),
          spec: spec
        }
        resolve(hash)
      })
    })
  }

  readonly hmac = 'sha512'

  private constructor (
    readonly pbkdf2: (password: string|Buffer, salt: string|Buffer,
    iterations: number, length: number, hmac: string,
    callback: (err: any, digest: Buffer) => void) => void,
    readonly encoding: string,
    readonly salt: { bytes: Buffer, chars?: string },
    readonly iterations: number,
    readonly length: number
  ) {}
}

function getPbkdf2Sha512Spec (randombytes: (length: number) => Buffer, opts?: any): Pbkdf2Sha512Spec {
  const config = { ...opts }
  const encoding = getEncoding(config.encoding)
  const saltbytes = getSaltBuffer(randombytes, config.salt, encoding)

  const spec: Pbkdf2Sha512Spec = {
    encoding: encoding,
    salt: { bytes: saltbytes },
    iterations: getIterations(config.iterations, config.relaxed),
    length: getLength(config.length)
  }
  if (encoding !== 'none') { spec.salt.chars = saltbytes.toString(encoding) }
  return spec
}

function getSaltBuffer (randombytes: (length: number) => Buffer, val: any, encoding: string): Buffer {
  const salt = toBufferIfUintArray(toRandomBufferIfNumber(randombytes, toBufferIfString(val, encoding)))
  return Buffer.isBuffer(salt) && (salt.length >= PBKDF2_CONFIG_DEFAULTS.salt.min)
  ? Buffer.from(salt)
  : randombytes(PBKDF2_CONFIG_DEFAULTS.salt.default)
}

function toRandomBufferIfNumber (randombytes: (length: number) => Buffer, val: any): any {
  return isNumber(val) ? randombytes(val.valueOf()) : val
}

function toBufferIfUintArray (val: any): any {
  try {
    return val && isArrayBuffer(val.buffer) ? Buffer.from(val.buffer) : val
  } catch (err) {
    return val
  }
}

function getEncoding (val: any): string {
  const encoding = isString(val) && val.valueOf()
  return (PBKDF2_CONFIG_DEFAULTS.encoding.indexOf(encoding) >= 0)
  ? encoding
  : PBKDF2_CONFIG_DEFAULTS.encoding[0]
}

function getIterations (val: any, relaxed?: boolean): number {
  const iterations = isNumber(val) && Math.floor(val.valueOf())
  const min = !relaxed ? PBKDF2_CONFIG_DEFAULTS.iterations.min : 1
  return val >= min
  ? iterations
  : PBKDF2_CONFIG_DEFAULTS.iterations.default
}

function getLength (val: any): number {
  const length = isNumber(val) && val.valueOf()
  return (val >= PBKDF2_CONFIG_DEFAULTS.length.min)
  && (val <= PBKDF2_CONFIG_DEFAULTS.length.max)
  ? length
  : PBKDF2_CONFIG_DEFAULTS.length.default
}

function toBufferIfString (val: any, encoding: string): any {
  return (encoding !== 'none') && isString(val)
  ? Buffer.from(val.valueOf(), encoding)
  : val
}

const getPbkdf2Sha512: Pbkdf2Sha512Factory = Pbkdf2Sha512Class.getKdf
export default getPbkdf2Sha512
