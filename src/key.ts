import { cbc } from "@noble/ciphers/aes.js";
import { pywidevine_license_protocol } from "./protos/license_protocol.js";

/** Key instance */
export class Key {
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
     * @param key Key container
     * @param encKey Decryption key
     */
    static fromContainer(key: pywidevine_license_protocol.License.KeyContainer, encKey: Uint8Array): Key {
        return new Key(key.type, key.id, cbc(encKey, key.iv).decrypt(key.key));
    }
}