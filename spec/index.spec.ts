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
import getPbkdf2Sha512 from '../src'
import { __assign as assign } from 'tslib'
let mock: {
  pbkdf2: jasmine.Spy
  randombytes: jasmine.Spy
}
let digest: Buffer
let randombytes: Buffer

beforeEach(() => {
  digest = Buffer.alloc(64)
  randombytes = Buffer.alloc(64)
  function fakePbkdf2 (password: string|Uint8Array, salt: string|Uint8Array, iterations: number,
  length: number, hmac: string, callback: (err: any, digest: Uint8Array) => void): void {
    callback(null, digest)
  }
  mock = {
    pbkdf2: jasmine.createSpy('pbkdf2').and.callFake(fakePbkdf2),
    randombytes: jasmine.createSpy('randombytes').and.returnValue(randombytes)
  }
})

describe('getPbkdf2Sha512 (config?: Partial<Pbkdf2Sha512Config>): ' +
'(password: Buffer|string) => Promise<Pbkdf2sha512Digest>', () => {
  it('returns a function', () => {
    expect(getPbkdf2Sha512()).toEqual(jasmine.any(Function))
  })
  describe('when called without args', () => {
    let digest: any
    beforeEach((done) => {
      getPbkdf2Sha512(mock)('passphrase')
      .then(hash => digest = hash)
      .then(() => setTimeout(done))
      .catch(err => setTimeout(() => done.fail(err)))
    })
    it('configures the returned pbkdf2 function with the following defaults: ' +
    'random salt string of 64 bytes, base64 encoding, 65536 iterations, ' +
    'digest length of 64 bytes, sha512 hmac', () => {
      expect(mock.pbkdf2)
      .toHaveBeenCalledWith(jasmine.any(Buffer), randombytes, 65536, 64, 'sha512', jasmine.any(Function))
      expect(mock.randombytes).toHaveBeenCalledWith(64)
      expect(digest.spec.encoding).toBe('base64')
    })
  })
  describe('when called with a valid config object', () => { // TODO
    let config: any
    let digest: any
    beforeEach((done) => {
      config = assign({
        encoding: 'ascii',
        salt: Buffer.alloc(32),
        iterations: 8192,
        length: 32
      }, mock)
      getPbkdf2Sha512(config)('passphrase')
      .then(hash => digest = hash)
      .then(() => setTimeout(done))
      .catch(err => setTimeout(() => done.fail(err)))
    })
    it('configures the returned pbkdf2 function with the properties of the config object', () => {
      expect(mock.pbkdf2)
      .toHaveBeenCalledWith(
        jasmine.any(Buffer),
        config.salt,
        config.iterations,
        config.length,
        'sha512',
        jasmine.any(Function))
      expect(mock.randombytes).not.toHaveBeenCalled()
      expect(digest.spec.encoding).toBe(config.encoding)
    })
  })
  describe('when called with an invalid config object, ' +
  'or a config object with invalid properties', () => { // TODO
    let config: any
    let digest: any
    beforeEach((done) => {
      config = assign({
        encoding: 'foo',
        salt: Buffer.alloc(31),
        iterations: 8191,
        length: 31
      }, mock)
      getPbkdf2Sha512(config)('passphrase')
      .then(hash => digest = hash)
      .then(() => setTimeout(done))
      .catch(err => setTimeout(() => done.fail(err)))
    })
    it('configures the returned pbkdf2 function of each invalid property to its default value',
    () => {
      expect(mock.pbkdf2)
      .toHaveBeenCalledWith(jasmine.any(Buffer), randombytes, 65536, 64, 'sha512', jasmine.any(Function))
      expect(mock.randombytes).toHaveBeenCalledWith(64)
      expect(digest.spec.encoding).toBe('base64')
    })
  })
  describe('when called with `relaxed: true`', () => { // TODO
    let config: any
    let digest: any
    beforeEach((done) => {
      config = assign({
        iterations: 1,
        relaxed: true
      }, mock)
      getPbkdf2Sha512(config)('passphrase')
      .then(hash => digest = hash)
      .then(() => setTimeout(done))
      .catch(err => setTimeout(() => done.fail(err)))
    })
    it('accepts any strictly positive iteration count', () => {
      expect(mock.pbkdf2)
      .toHaveBeenCalledWith(
        jasmine.any(Buffer), randombytes, 1, 64, 'sha512', jasmine.any(Function))
      expect(mock.randombytes).toHaveBeenCalledWith(64)
      expect(digest.spec.encoding).toBe('base64')
    })
  })
})

describe('pbkdf2Sha512 (password: Buffer|Uint8Array|string) => Promise<Pbkdf2sha512Digest>', () => {
  describe('when called with a string, Buffer, or Uint8Array', () => { // TODO
    let config: any
    let digests: any
    beforeEach((done) => {
      config = assign({
        encoding: 'ascii'
      }, mock)
      const buf = Buffer.from('passphrase', 'ascii')
      const arr = new Uint8Array(buf.buffer)
      const args = [ 'passphrase', buf, arr ]
      const pbkdf2 = getPbkdf2Sha512(config)
      Promise.all(args.map(arg => pbkdf2(arg)))
      .then(hashes => digests = hashes)
      .then(() => setTimeout(done))
      .catch(err => setTimeout(() => done.fail(err)))
    })
    it('returns the pbkdf2 digest of the given argument ' +
    'together with the corresponding pbkdf2 parameters', () => {
      mock.pbkdf2.calls.allArgs()
      .every(args => expect(args[0].toString()).toBe('passphrase'))
      digests.every((hash: any) =>
      expect(hash.value.toString('ascii')).toBe(digest.toString())
      && expect(hash.spec).toEqual({
        encoding: 'ascii',
        salt: randombytes.toString(),
        iterations: 65536,
        length: 64
      }))
    })
  })
  describe('when instantiated with `{ encoding: "none" }`', () => { // TODO
    let config: any
    let digests: any
    beforeEach((done) => {
      config = assign({
        encoding: 'none'
      }, mock)
      const buf = Buffer.from('passphrase', 'ascii')
      const arr = new Uint8Array(buf.buffer)
      const args = [ 'passphrase', buf, arr ]
      const pbkdf2 = getPbkdf2Sha512(config)
      Promise.all(args.map(arg =>
        pbkdf2(arg)))
      .then(hashes => digests = hashes)
      .then(() => setTimeout(done))
      .catch(err => setTimeout(() => done.fail(err)))
    })
    it('returns the raw (Buffer) pbkdf2 digest of the given argument ' +
    'together with the corresponding pbkdf2 parameters', () => {
      mock.pbkdf2.calls.allArgs()
      .every(args => expect(args[0].toString()).toBe('passphrase'))
      digests.every((hash: any) => expect(hash.value).toEqual(digest)
      && expect(hash.spec).toEqual({
        encoding: 'none',
        salt: randombytes.toString(),
        iterations: 65536,
        length: 64
      }))
    })
  })
  describe('when called with anything else', () => { // TODO
    let config: any
    let errors: any
    beforeEach((done) => {
      config = assign({
        encoding: 'ascii'
      }, mock)
      const args = [ null, undefined, 42, [], {} ]
      const pbkdf2 = <any>getPbkdf2Sha512(config)
      Promise.all(args.map(arg => pbkdf2(arg).catch((err: any) => err)))
      .then(errs => errors = errs)
      .then(() => setTimeout(done))
      .catch(err => setTimeout(() => done.fail(err)))
    })
    it('throws an "invalid arguments" TypeError', () => {
      errors
      .every((err: any) => expect(err).toEqual(jasmine.any(TypeError))
      && expect(err.message).toBe('invalid argument'))
    })
  })
})