import { randomBytes } from "@noble/ciphers/utils.js";
import type { pywidevine_license_protocol } from "./protos/license_protocol.js";
import type { Key } from "./key.js";

export class Session {
    public id: Uint8Array;
    public servicCertificate?: pywidevine_license_protocol.SignedDrmCertificate;
    public context = new Map<string, Uint8Array[]>();
    public keys: Key[] = [];
    constructor(public number: number) {
        this.id = randomBytes(16);
    }
}