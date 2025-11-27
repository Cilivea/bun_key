import { X509CertificateGenerator } from "@peculiar/x509"
import * as crypto from "crypto"

import { PrivateKey, EncryptedPrivateKey } from "./privateKey"
import { PublicKey } from "./publicKey"
import { Certificate } from "./certificate"

export { PrivateKey, EncryptedPrivateKey, PublicKey, Certificate };

export async function new_keypair() {
    let keys = crypto.generateKeyPairSync("ed25519", {})

    return {
        privateKey: PrivateKey.from_crypto(keys.privateKey),
        publicKey: PublicKey.from_crypto(keys.publicKey)
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
        certificate: new Certificate(cert),
        privateKey: privateKey,
        publicKey: publicKey
    }
}

