import * as test from "bun:test"
import { new_cert, new_keypair, PrivateKey } from "."

const PASSPHRASE = "TEST_PASS"
const WRONG_PASS = "WRONG_PASS"


test.test("simple test", async () => {
    let old_certs = await new_cert(300, ["verify"])

    let new_certs = await new_cert(300, ["verify"], old_certs.privateKey)

    // Verify the new certs using the old public key
    let is_valid = await new_certs.certificate.verify({
        date: new Date(),
        publicKey: await old_certs.publicKey.to_webcrypto(true, ["verify"])
    })

    test.expect(is_valid).toBe(true)


    // Verify the new certs with the new public key SHOULD FAIL, as it is equivalent to using wrong key
    is_valid = await new_certs.certificate.verify({
        date: new Date(),
        publicKey: await new_certs.publicKey.to_webcrypto(true, ["verify"])
    })

    test.expect(is_valid).toBe(false)
})

test.test("save and load private key", async () => {
    let keys = await new_keypair()

    let saved_key = keys.privateKey.save(PASSPHRASE)

    let imported_key = PrivateKey.unencode(saved_key, PASSPHRASE)
    if (imported_key !== undefined)
        test.expect(true).toBe(true)
    else
        test.expect(false).toBe(true)


    let wrong_pass = PrivateKey.unencode(saved_key, WRONG_PASS)
    if (wrong_pass === undefined)
        test.expect(true).toBe(true)
    else
        test.expect(false).toBe(true)

})