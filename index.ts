import { X509Certificate, X509CertificateGenerator } from "@peculiar/x509"
import * as crypto from "crypto"

export async function new_keypair() {
    let keys = crypto.generateKeyPairSync("ed25519", {})

    return {
        privateKey: await PrivateKey.from_crypto(keys.privateKey),
        publicKey: await PublicKey.from_crypto(keys.publicKey)
    }
}

export async function new_cert(seconds_to_expiry: number, public_key_permissions: crypto.webcrypto.KeyUsage[], signing_key?: PrivateKey) {
    let { privateKey, publicKey } = await new_keypair()

    if (signing_key === undefined) {
        signing_key = privateKey
    }

    let wc_private = await signing_key.to_webcrypto(true, ["sign"])
    let wc_public = await publicKey.to_webcrypto(true, public_key_permissions)

    let now = new Date()
    let expires = new Date()
    expires.setSeconds(now.getSeconds() + seconds_to_expiry)

    let cert = await X509CertificateGenerator.createSelfSigned({
        keys: {
            privateKey: wc_private,
            publicKey: wc_public
        },
        notBefore: now,
        notAfter: expires,
    })

    return {
        certificate: cert,
        privateKey: privateKey,
        publicKey: publicKey
    }
}

abstract class Key {
    abstract keyObject: crypto.KeyObject

    to_webcrypto(extractable: boolean, key_usages: crypto.webcrypto.KeyUsage[]) {
        let a = this.keyObject.export({ format: "jwk" })

        console.log("to_webcrypto", extractable, key_usages)
        console.log("jwk", a)
        let b = crypto.webcrypto.subtle.importKey("jwk", a, {
            name: "Ed25519"
        },
            extractable,
            key_usages)

        return b
    }
}

export class PrivateKey extends Key {
    keyObject: crypto.KeyObject

    constructor(key: crypto.KeyObject) {
        super()
        this.keyObject = key
    }

    static async from_crypto(key: crypto.KeyObject) {
        return new PrivateKey(key)
    }

    save(passphrase: string): string {
        return this.keyObject.export({ format: "pem", type: "pkcs8", passphrase: passphrase, cipher: "aes-256-cbc" }).toString()
    }

    static unencode(encoded_pkcs8: string, passphrase: string): PrivateKey | undefined {
        try {
            return new PrivateKey(
                crypto.createPrivateKey({ key: encoded_pkcs8, passphrase: passphrase })
            )
        } catch (error) {
            return undefined
        }

    }
}

export class PublicKey extends Key {
    keyObject: crypto.KeyObject

    constructor(key: crypto.KeyObject) {
        super()
        this.keyObject = key
    }

    static async from_crypto(key: crypto.KeyObject) {
        return new PublicKey(key)
    }

    static async from_cert(x509_cert: X509Certificate) {
        let a = crypto.createPublicKey(x509_cert.toString())
        return new PublicKey(a)
    }
}