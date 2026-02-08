import { AsnConvert } from "@peculiar/asn1-schema";
import { pywidevine_license_protocol } from "./protos/license_protocol.js";
import { RSAPrivateKey, RSAPublicKey } from "@peculiar/asn1-rsa";
import type { PublicKey, PrivateKey } from 'micro-rsa-dsa-dh/rsa.js';
import { bytesToNumberBE } from "@noble/ciphers/utils.js";

export const parseCerificate = (certificate: Uint8Array): pywidevine_license_protocol.DrmCertificate => {
    let signedDrmCertificate;
    try {
        const signedMessage = pywidevine_license_protocol.SignedMessage.deserialize(certificate);
        
        signedDrmCertificate = pywidevine_license_protocol.SignedDrmCertificate.deserialize(signedMessage.msg);
        if(signedDrmCertificate.drm_certificate.length == 0) throw new Error("");
    } catch(e) {
        signedDrmCertificate = pywidevine_license_protocol.SignedDrmCertificate.deserialize(certificate);
    }

    if(!signedDrmCertificate.drm_certificate) throw new Error("Can't decode DRM certificate");

    return pywidevine_license_protocol.DrmCertificate.deserialize(signedDrmCertificate.drm_certificate);
}

export const decodePrivateKey = (bytes: Uint8Array): PrivateKey => {
    const schema = AsnConvert.parse(bytes, RSAPrivateKey);

    return {
        n: bytesToNumberBE(new Uint8Array(schema.modulus)),
        d: bytesToNumberBE(new Uint8Array(schema.privateExponent))
    }
}

export const decodePublicKey = (bytes: Uint8Array): PublicKey => {
    const schema = AsnConvert.parse(bytes, RSAPublicKey);

    return {
        n: bytesToNumberBE(new Uint8Array(schema.modulus)),
        e: bytesToNumberBE(new Uint8Array(schema.publicExponent))
    }
}