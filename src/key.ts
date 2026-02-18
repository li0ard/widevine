import { cbc } from "@noble/ciphers/aes.js";
import { pywidevine_license_protocol } from "./protos/license_protocol.js";
import { bytesToNumberBE } from "@noble/ciphers/utils.js";

/** Key control block instance */
export class KeyControlBlock {
    /** Key control block instance */
    constructor(public data: Uint8Array) {
        if (data.length !== 16) throw new Error(`KCB must be exactly 16 bytes`);
    }

    private get magic(): string { return new TextDecoder().decode(this.data.subarray(0,4)); }
    /** API version (0 - `kctl`) */
    get version(): number {
        const match = this.magic.match(/^kc(\d+)$/);
        return match ? parseInt(match[1], 10) : 0;
    }
    /** Key TTL */
    get ttl(): bigint { return bytesToNumberBE(this.data.subarray(4,8)); }
    /** Key control nonce */
    get nonce(): bigint { return bytesToNumberBE(this.data.subarray(8,12)); }
    /** Key permissions bits */
    get permissions(): bigint { return bytesToNumberBE(this.data.subarray(12)); }

    /** Key control block as string */
    toString(): string {
        const ttlStr = (this.ttl === 0n) ? 'unlimited' : `${this.ttl}s`;
        return `KCB<v${this.version}>(ttl = ${ttlStr}, nonce = 0x${this.nonce.toString(16).padStart(8, "0")}, permissions = ${this.permissions.toString(2).padStart(32, "0")})`;
    }
}

/** Key instance */
export class Key {
    /** Key control block */
    public keyControlBlock?: KeyControlBlock;
    /**
     * Key instance
     * @param type Type
     * @param kid ID
     * @param key Key
     */
    constructor(
        public type: pywidevine_license_protocol.License.KeyContainer.KeyType,
        public kid: Uint8Array,
        public key: Uint8Array
    ) {}

    /**
     * Get key from license key container
     * @param container Key container
     * @param encKey Decryption key
     */
    static fromContainer(container: pywidevine_license_protocol.License.KeyContainer, encKey: Uint8Array): Key {
        const decryptedKey = cbc(encKey, container.iv).decrypt(container.key);

        const keyClass = new Key(container.type, container.id, decryptedKey);
        if(container.has_key_control)
            keyClass.keyControlBlock = new KeyControlBlock(cbc(decryptedKey, container.key_control.iv).decrypt(container.key_control.key_control_block));
        return keyClass;
    }
}