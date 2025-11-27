import * as crypto from "crypto"

export class EncryptedPrivateKey {
    pkcs8_string: string

    constructor(encoded_key: string) {
        this.pkcs8_string = encoded_key
    }

    static import_pkcs8(pkcs8_string: string): EncryptedPrivateKey {
        return new EncryptedPrivateKey(pkcs8_string)
    }

    /**
     * 
     * @param passhprase The passphrase to unencrypt the pkcs8 string with
     * 
     * This function throws an error if passphrase is wrong
     */
    unencrypt(passhprase: string): PrivateKey {
        return new PrivateKey(
            crypto.createPrivateKey({
                key: this.pkcs8_string,
                passphrase: passhprase
            })
        )
    }
}

export class PrivateKey {
    keyObject: crypto.KeyObject

    constructor(keyobject: crypto.KeyObject) {
        this.keyObject = keyobject
    }

    static from_crypto(key: crypto.KeyObject) {
        return new PrivateKey(key)
    }

    encrypt(passphrase: string): EncryptedPrivateKey {
        let pkcs8 = this.keyObject.export({ format: "pem", type: "pkcs8", passphrase: passphrase, cipher: "aes-256-cbc" }).toString()
        return new EncryptedPrivateKey(pkcs8)
    }

    to_webcrypto(extractable: boolean, key_usages: crypto.webcrypto.KeyUsage[]) {
        let a = this.keyObject.export({ format: "jwk" })

        let b = crypto.webcrypto.subtle.importKey("jwk", a, {
            name: "Ed25519"
        },
            extractable,
            key_usages)

        return b
    }
}