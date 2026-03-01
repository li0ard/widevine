import { randomBytes } from "@noble/ciphers/utils.js";
import type { SignedDrmCertificate } from "@li0ard/widevineproto";
import type { Key } from "./key.js";

export class Session {
    public id: Uint8Array;
    public serviceCertificate?: SignedDrmCertificate;
    public context = new Map<string, Uint8Array[]>();
    public keys: Key[] = [];
    constructor(public number: number) {
        this.id = randomBytes(16);
    }
}