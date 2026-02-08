import { pywidevine_license_protocol } from "./protos/license_protocol.js";

/** Widevine System ID */
export const WIDEVINE_SID: Readonly<Uint8Array> = new Uint8Array([0xed, 0xef, 0x8b, 0xa9, 0x79, 0xd6, 0x4a, 0xce, 0xa3, 0xc8, 0x27, 0xdc, 0xd5, 0x1d, 0x21, 0xed]);

/** Device type */
export enum DeviceType {
    CHROME = 1,
    ANDROID
}

/** Key type */
export const KeyType = pywidevine_license_protocol.License.KeyContainer.KeyType;