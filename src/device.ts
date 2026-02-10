import type { PublicKey, PrivateKey } from 'micro-rsa-dsa-dh/rsa.js';
import { pywidevine_license_protocol } from "./protos/license_protocol.js";
import { decodePrivateKey, decodePublicKey, parseCerificate } from './utils.js';
import type { DeviceType } from './const.js';

/** Device instance for CDM */
export class Device {
    /**
     * Device instance for CDM
     * @param type Device type
     * @param clientId Device client identification
     * @param privateKey Device private key
     */
    constructor(
        public type: DeviceType,
        public clientId: pywidevine_license_protocol.ClientIdentification,
        public privateKey: PrivateKey,
    ) {}

    /** Device public key */
    get publicKey(): PublicKey {
        const certificate = parseCerificate(this.clientId.token);
        if(!certificate.public_key) throw new Error("Missing public key in DRM certificate");

        return decodePublicKey(certificate.public_key);
    }

    /**
     * Get device instance from dump
     * @param type Device type
     * @param clientId Device client identification blob (`client_id.bin`)
     * @param privateKey Device private key blob (ASN.1 encoded)
     */
    static decode(type: DeviceType, clientId: Uint8Array, privateKey: Uint8Array): Device {
        const client_id = pywidevine_license_protocol.ClientIdentification.deserialize(clientId);
        if(!client_id.token) throw new Error("Missing token in Client ID");

        return new Device(type, client_id, decodePrivateKey(privateKey));
    }
}