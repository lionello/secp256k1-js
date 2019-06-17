/* eslint-env mocha */
if (typeof module !== 'undefined') {
    Secp256r1 = module.require('../src/secp256r1')
    chai = module.require('chai')
    var B = bn => Buffer.from(('00000000'+bn.toString(16)).slice(-64), 'hex')
    var Secp256r1Node// = require('secp256r1')
}

const Assert = chai.assert

describe('secp256r1', () => {
    const P = Secp256r1.uint256("ffffffff00000001000000000000000000000000ffffffffffffffffffffffff", 16)
    const d = Secp256r1.uint256("79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798", 16)
    const pubX = Secp256r1.uint256('95cee273a6c921945fc720370411dc52a037e9b8dbc661804d71201fa2a6e7c0', 16)
    const pubY = Secp256r1.uint256('6ce2abb965ffdae1adf2d9bc9d369e58f87b5c6aa1a67fa95871ffaf5ca9117a', 16)
    const z = Secp256r1.uint256("483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8", 16)
    const N  = Secp256r1.uint256("ffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551", 16)

    // Known good sig
    let r = 'f6c33e664c11093b7e670a063e89e1aeb2660e9f237af872627a82cae8271829'
    let s = '246b47e7230184b61f5aabbd87b428ccbd121c276d004b006dd58f8368eb1a62'
    let v = 1

    it('valid point', () => {
        Assert.ok(Secp256r1.isValidPoint(pubX, pubY))
    })

    it('decompress', () => {
        Assert.equal(Secp256r1.decompressKey(pubX, 1).toString(16), pubY.toString(16))
    })

    it('can gen pubkey', () => {
        const pub = Secp256r1.generatePublicKeyFromPrivateKeyData(d)
        Assert.deepStrictEqual(pub, {x: pubX.toString(16), y: pubY.toString(16)})
        // if (Secp256r1Node) {
        //     const pub = Secp256r1Node.publicKeyCreate(B(d), true)
        //     console.log(pub.toString('hex'))
        //     const pubd = Secp256r1Node.publicKeyCreate(B(d), false)
        //     console.log(pubd.toString('hex'))
        // }
    })

    it('test vector', () => {
        const pub = Secp256r1.generatePublicKeyFromPrivateKeyData(Secp256r1.uint256('D30519BCAE8D180DBFCC94FE0B8383DC310185B0BE97B4365083EBCECCD75759',16))
        Assert.deepStrictEqual(pub, {x: "5097865a263e1f2b77e27df40502ce794a2ccedf45b913ae1be9f253c5711235", y: "7fbcfae76a1bb1a1f71d1fc540b52bf1f6a3601b338a18c767d2f71ce3837405"})
    })

    it('can sign', () => {
        const sig = Secp256r1.ecsign(d, z)
        Assert.ok(/^[0-9a-f]{64}$/.test(sig.r), 'sig.r is not a hex string')
        Assert.ok(/^[0-9a-f]{64}$/.test(sig.s), 'sig.s is not a hex string')
        Assert.ok(sig.v===0 || sig.v===1, 'sig.v is not a 0 or 1')
        if (Secp256r1Node) {
            const success = Secp256r1Node.verify(B(z), Buffer.concat([B(sig.r), B(sig.s)]), Buffer.concat([Buffer('\04'), B(pubX), B(pubY)]))
            Assert.ok(success, JSON.stringify(sig))
        }
    })

    it('has recovery bit', () => {
        const sig = Secp256r1.ecsign(d, z)
        if (Secp256r1Node) {
            const success = Secp256r1Node.verify(B(z), Buffer.concat([B(sig.r), B(sig.s)]), Buffer.concat([Buffer('\04'), B(pubX), B(pubY)]))
            Assert.ok(success, JSON.stringify(sig))
            const Q = Secp256r1Node.recover(B(z), Buffer.concat([B(sig.r), B(sig.s)]), sig.v, false)
            Assert.deepStrictEqual({x: Q.toString('hex').substr(2,64), y: Q.toString('hex').slice(-64)}, {x: pubX.toString(16), y: pubY.toString(16)})
        }
    })

    it('can verify self', () =>  {
        const sig = Secp256r1.ecsign(d, z)
        Assert.ok(Secp256r1.ecverify(pubX, pubY, Secp256r1.uint256(sig.r,16), Secp256r1.uint256(sig.s,16), z))
    })

    it('can verify fff...', () =>  {
        const z = Secp256r1.uint256("ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff", 16)
        const sig = Secp256r1.ecsign(d, z)
        Assert.ok(Secp256r1.ecverify(pubX, pubY, Secp256r1.uint256(sig.r,16), Secp256r1.uint256(sig.s,16), z))
    })

    it('can verify other sig', () => {
        if (Secp256r1Node) {
            const sig = Secp256r1Node.sign(B(z), B(d))
            r = sig.signature.toString('hex').substr(0,64)
            s = sig.signature.toString('hex').slice(-64)
        }
        Assert.ok(Secp256r1.ecverify(pubX, pubY, Secp256r1.uint256(r,16), Secp256r1.uint256(s,16), z))
    })

    it('can recover other sig', () => {
        if (Secp256r1Node) {
            const sig = Secp256r1Node.sign(B(z), B(d))
            r = sig.signature.toString('hex').substr(0,64)
            s = sig.signature.toString('hex').slice(-64)
            v = sig.recovery
        }
        const Q = Secp256r1.ecrecover(v, Secp256r1.uint256(r,16), Secp256r1.uint256(s,16), z)
        Assert.deepStrictEqual(Q, {x: pubX.toString(16), y: pubY.toString(16)})
    })

    it('can recover self', () =>  {
        const sig = Secp256r1.ecsign(d, z)
        const Q = Secp256r1.ecrecover(sig.v, Secp256r1.uint256(sig.r,16), Secp256r1.uint256(sig.s,16), z)
        Assert.deepStrictEqual(Q, {x: pubX.toString(16), y: pubY.toString(16)})
    })
})
