# secp256k1-js
[![CircleCI](https://circleci.com/gh/lionello/secp256k1-js.svg?style=svg)](https://circleci.com/gh/lionello/secp256k1-js)

Pure JS implementation of secp256k1 signing, verification, recovery ECDSA.

The code works as-is both in browsers and NodeJS, without the need of a bundler.

## Node.js Usage

```sh
npm install @lionello/secp256k1-js
```

### Example

```javascript
const crypto = require('crypto')
const assert = require('assert')
const Secp256k1 = require('@lionello/secp256k1-js')

// Generating private key
const privateKeyBuf = crypto.randomBytes(32)
const privateKey = Secp256k1.uint256(privateKeyBuf, 16)

// Generating public key
const publicKey = Secp256k1.generatePublicKeyFromPrivateKeyData(privateKey)
const pubX = Secp256k1.uint256(publicKey.x, 16)
const pubY = Secp256k1.uint256(publicKey.y, 16)

// Signing a digest
const digest = Secp256k1.uint256("483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8", 16)
const sig = Secp256k1.ecsign(privateKey, digest)
const sigR = Secp256k1.uint256(sig.r,16)
const sigS = Secp256k1.uint256(sig.s,16)

// Verifying signature
const isValidSig = Secp256k1.ecverify(pubX, pubY, sigR, sigS, digest)
assert(isValidSig === true, 'Signature must be valid')
```

## Browser Usage

Include this library and [bn.js](https://github.com/indutny/bn.js/)

```html
<script src="https://unpkg.com/bn.js@4.11.8/lib/bn.js" type="text/javascript"></script>
<script src="https://unpkg.com/@lionello/secp256k1-js@1.0.0/src/secp256k1.js" type="text/javascript"></script>
```

### Example
```javascript
// Generating private key
const privateKeyBuf = window.crypto.getRandomValues(new Uint8Array(32))
const privateKey = Secp256k1.uint256(privateKeyBuf, 16)

// Generating public key
const publicKey = Secp256k1.generatePublicKeyFromPrivateKeyData(privateKey)
const pubX = Secp256k1.uint256(publicKey.x, 16)
const pubY = Secp256k1.uint256(publicKey.y, 16)

// Signing a digest
const digest = Secp256k1.uint256("483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8", 16)
const sig = Secp256k1.ecsign(privateKey, digest)
const sigR = Secp256k1.uint256(sig.r,16)
const sigS = Secp256k1.uint256(sig.s,16)

// Verifying signature
const isValidSig = Secp256k1.ecverify(pubX, pubY, sigR, sigS, digest)
console.assert(isValidSig === true, 'Signature must be valid')
````

## Development
```sh
npm install
npm test
```

Open `test/test.html` to run the same tests in the browser.

# The MIT License
Copyright 2018 Enuma Technologies Limited.

Permission is hereby granted, free of charge, to any person obtaining a copy of this software and associated documentation files (the "Software"), to deal in the Software without restriction, including without limitation the rights to use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of the Software, and to permit persons to whom the Software is furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
