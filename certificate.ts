import { X509Certificate } from "@peculiar/x509"



export class Certificate {
    raw_cert: X509Certificate

    constructor(cert: X509Certificate) {
        this.raw_cert = cert
    }

    static from_string(str: string) {

        return new Certificate(new X509Certificate(str))
    }
}