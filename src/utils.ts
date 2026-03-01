import { AsnConvert } from "@peculiar/asn1-schema";
import { DrmCertificate, SignedDrmCertificate, SignedMessage } from "@li0ard/widevineproto";
import { RSAPrivateKey, RSAPublicKey } from "@peculiar/asn1-rsa";
import type { PublicKey, PrivateKey } from 'micro-rsa-dsa-dh/rsa.js';
import { bytesToNumberBE } from "@noble/ciphers/utils.js";

export const parseCertificate = (certificate: Uint8Array): DrmCertificate => {
    let signedDrmCertificate;
    try {
        const signedMessage = SignedMessage.deserialize(certificate);
        
        signedDrmCertificate = SignedDrmCertificate.deserialize(signedMessage.msg);
        if(signedDrmCertificate.drm_certificate.length == 0) throw new Error("");
    } catch(e) {
        signedDrmCertificate = SignedDrmCertificate.deserialize(certificate);
    }

    if(!signedDrmCertificate.drm_certificate) throw new Error("Can't decode DRM certificate");

    return DrmCertificate.deserialize(signedDrmCertificate.drm_certificate);
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