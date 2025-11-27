import type { X509Certificate } from "@peculiar/x509"
import * as crypto from "crypto"


export class PublicKey {
    keyObject: crypto.KeyObject

    constructor(key: crypto.KeyObject) {
        this.keyObject = key
    }

    static from_crypto(key: crypto.KeyObject) {
        return new PublicKey(key)
    }

    static from_cert(x509_cert: X509Certificate) {
        let a = crypto.createPublicKey(x509_cert.toString())
        return new PublicKey(a)
    }

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