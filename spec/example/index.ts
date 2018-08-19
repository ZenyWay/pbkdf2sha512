/**
 * Copyright 2018 Stephane M. Catala
 * @author  Stephane M. Catala
 * @license Apache@2.0
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
//
import getPbkdf2OSha512 from '../../src'
import log from './console'

const pbkdf2 = getPbkdf2OSha512({
  // generate random 64-byte long salt string, base64-encoded (default)
  iterations: 8192, // min 8192, default 65536
  length: 32 // min 32, max 64, default 64
  // digest is always 'sha512'
})

const rawpbkdf2 = getPbkdf2OSha512({
  encoding: 'none',
  iterations: 8192,
  length: 32
})

log('example:')('digest passphrase...')

pbkdf2('secret passphrase')
.then(log('example:digest:'))
// { value: "...", spec: { encoding: "base64", salt: "...", iterations: 16384, length: 64, hmac: "sha512" }}

rawpbkdf2('secret passphrase')
.then(log('example:raw-digest:'))
// { value: Buffer, spec: { encoding: "none", salt: Buffer, iterations: 8192, length: 32, hmac: "sha512" }}
