import type { PublicKey, PrivateKey } from 'micro-rsa-dsa-dh/rsa.js';
import { pywidevine_license_protocol } from "./protos/license_protocol.js";
import { decodePrivateKey, decodePublicKey, parseCerificate } from './utils.js';
import type { DeviceType } from './const.js';

/** Device instance for CDM */
export class Device {
    /**
     * Device instance for CDM
     * @param type Device type
     * @param privateKey Device private key
     * @param client_id Device client identification
     */
    constructor(
        public type: DeviceType,
        public privateKey: PrivateKey,
        public client_id: pywidevine_license_protocol.ClientIdentification,
    ) {}

    /** Device public key */
    get publicKey(): PublicKey {
        const certificate = parseCerificate(this.client_id.token);
        if(!certificate.public_key) throw new Error("Missing public key in DRM certificate");

        return decodePublicKey(certificate.public_key);
    }

    /**
     * Get device instance from dump
     * @param type Device type
     * @param client_id Device client identification blob (`client_id.bin`)
     * @param privateKey Device private key blob (ASN.1 encoded)
     */
    static decode(type: DeviceType, client_id: Uint8Array, privateKey: Uint8Array): Device {
        const clientId = pywidevine_license_protocol.ClientIdentification.deserialize(client_id);
        if(!clientId.token) throw new Error("Missing token in Client ID");

        return new Device(type, decodePrivateKey(privateKey), clientId);
    }
}