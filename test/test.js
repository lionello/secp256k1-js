/* eslint-env mocha */
if (typeof module !== 'undefined') {
    Secp256k1 = module.require('../src/secp256k1')
    chai = module.require('chai')
    var B = bn => Buffer.from(('00000000'+bn.toString(16)).slice(-64), 'hex')
    var Secp256k1Node = require('secp256k1')
}

const Assert = chai.assert

describe('secp256k1', () => {
    const P = Secp256k1.uint256("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F", 16)
    const d = Secp256k1.uint256("79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798", 16)
    const pubX = Secp256k1.uint256('5b75fd5f49e78191a45e1c9438644fe5d065ea98920c63e9eef86e151e99b809', 16)
    const pubY = Secp256k1.uint256('4eef2a826f1e6d13a4dde4e54800e8d282a2089a873072002e0a3a21eae5763a', 16)
    const z = Secp256k1.uint256("483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8", 16)
    const N  = Secp256k1.uint256("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141", 16)

    // Known good sig
    let r = 'c9861bad8887039fa990d24f2cc7ded1027e79ca1c5033741345c4aeb4b2fbe4'
    let s = '303eee7b176509f6a48d66ec1bf891a2826c04b1a99790a33b96d2606ae75c60'
    let v = 0

    it('valid point', () => {
        Assert.ok(Secp256k1.isValidPoint(pubX, pubY))
    })

    it('decompress', () => {
        Assert.equal(Secp256k1.decompressKey(pubX, 0).toString(16), pubY.toString(16))
    })

    it('can gen pubkey', () => {
        const pub = Secp256k1.generatePublicKeyFromPrivateKeyData(d)
        Assert.deepStrictEqual(pub, {x: pubX.toString(16), y: pubY.toString(16)})
        // if (Secp256k1Node) {
        //     const pub = Secp256k1Node.publicKeyCreate(B(d), true)
        //     console.log(pub.toString('hex'))
        //     const pubd = Secp256k1Node.publicKeyCreate(B(d), false)
        //     console.log(pubd.toString('hex'))
        // }
    })

    it('test vector', () => {
        const pub = Secp256k1.generatePublicKeyFromPrivateKeyData(Secp256k1.uint256('D30519BCAE8D180DBFCC94FE0B8383DC310185B0BE97B4365083EBCECCD75759',16))
        Assert.deepStrictEqual(pub, {x: "3af1e1efa4d1e1ad5cb9e3967e98e901dafcd37c44cf0bfb6c216997f5ee51df", y: "e4acac3e6f139e0c7db2bd736824f51392bda176965a1c59eb9c3c5ff9e85d7a"})
    })

    it('can sign', () => {
        const sig = Secp256k1.ecsign(d, z)
        Assert.ok(/^[0-9a-f]{64}$/.test(sig.r), 'sig.r is not a hex string')
        Assert.ok(/^[0-9a-f]{64}$/.test(sig.s), 'sig.s is not a hex string')
        Assert.ok(sig.v===0 || sig.v===1, 'sig.v is not a 0 or 1')
        if (Secp256k1Node) {
            const success = Secp256k1Node.verify(B(z), Buffer.concat([B(sig.r), B(sig.s)]), Buffer.concat([Buffer('\04'), B(pubX), B(pubY)]))
            Assert.ok(success, JSON.stringify(sig))
        }
    })

    it('has recovery bit', () => {
        const sig = Secp256k1.ecsign(d, z)
        if (Secp256k1Node) {
            const success = Secp256k1Node.verify(B(z), Buffer.concat([B(sig.r), B(sig.s)]), Buffer.concat([Buffer('\04'), B(pubX), B(pubY)]))
            Assert.ok(success, JSON.stringify(sig))
            const Q = Secp256k1Node.recover(B(z), Buffer.concat([B(sig.r), B(sig.s)]), sig.v, false)
            Assert.deepStrictEqual({x: Q.toString('hex').substr(2,64), y: Q.toString('hex').slice(-64)}, {x: pubX.toString(16), y: pubY.toString(16)})
        }
    })

    it('can verify self', () =>  {
        const sig = Secp256k1.ecsign(d, z)
        Assert.ok(Secp256k1.ecverify(pubX, pubY, Secp256k1.uint256(sig.r,16), Secp256k1.uint256(sig.s,16), z))
    })

    it('can verify fff...', () =>  {
        const z = Secp256k1.uint256("ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff", 16)
        const sig = Secp256k1.ecsign(d, z)
        Assert.ok(Secp256k1.ecverify(pubX, pubY, Secp256k1.uint256(sig.r,16), Secp256k1.uint256(sig.s,16), z))
    })

    it('can verify other sig', () => {
        if (Secp256k1Node) {
            const sig = Secp256k1Node.sign(B(z), B(d))
            r = sig.signature.toString('hex').substr(0,64)
            s = sig.signature.toString('hex').slice(-64)
        }
        Assert.ok(Secp256k1.ecverify(pubX, pubY, Secp256k1.uint256(r,16), Secp256k1.uint256(s,16), z))
    })

    it('can recover other sig', () => {
        if (Secp256k1Node) {
            const sig = Secp256k1Node.sign(B(z), B(d))
            r = sig.signature.toString('hex').substr(0,64)
            s = sig.signature.toString('hex').slice(-64)
            v = sig.recovery
        }
        const Q = Secp256k1.ecrecover(v, Secp256k1.uint256(r,16), Secp256k1.uint256(s,16), z)
        Assert.deepStrictEqual(Q, {x: pubX.toString(16), y: pubY.toString(16)})
    })

    it('can recover self', () =>  {
        const sig = Secp256k1.ecsign(d, z)
        const Q = Secp256k1.ecrecover(sig.v, Secp256k1.uint256(sig.r,16), Secp256k1.uint256(sig.s,16), z)
        Assert.deepStrictEqual(Q, {x: pubX.toString(16), y: pubY.toString(16)})
    })
})
