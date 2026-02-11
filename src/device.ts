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

    /** Get device instance from `.wvd` file */
    static fromWvd(data: Uint8Array): Device {
        const rdr = new DataView(data.buffer);

        let offset = 0;
        const magic = new TextDecoder().decode(data.subarray(offset, offset += 3));
        if(magic != "WVD") throw new Error("Invalid magic constant, not a WVD file");

        const version = rdr.getUint8(offset);
        offset += 1;
        if(version != 1 && version != 2) throw new Error("Invalid version, not a WVD file");

        const type = rdr.getUint8(offset);
        offset += 1;

        const level = rdr.getUint8(offset);
        offset += 1;
        if(level < 1 || level > 3) throw new Error("Invalid device version, not a WVD file");

        //const flags = rdr.getUint8(offset);
        offset += 1;

        const privateKeyLength = rdr.getUint16(offset);
        offset += 2;

        const privateKey = data.slice(offset, offset += privateKeyLength);
        
        const clientIdLen = rdr.getUint16(offset);
        offset += 2;

        const clientId = pywidevine_license_protocol.ClientIdentification.deserializeBinary(data.slice(offset, offset += clientIdLen));
        if(!clientId.token) throw new Error("Missing token in Client ID, not a WVD file");

        return new Device(type, clientId, decodePrivateKey(privateKey));
    }
}