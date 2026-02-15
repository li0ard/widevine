import { pywidevine_license_protocol } from "./protos/license_protocol.js";

/** Device type */
export enum DeviceType {
    CHROME = 1,
    ANDROID
}

/** Key type */
export const KeyType = pywidevine_license_protocol.License.KeyContainer.KeyType;
/** License type */
export const LicenseType = pywidevine_license_protocol.LicenseType;

export const ROOT_CERT_PUBLIC = {
    n: 0xb4fe39c3659003db3c119709e868cdf2c35e9bf2e74d23b110db8765dfdcfb9f35a05703534cf66d357da678dbb336d23f9c40a99526727fb8be66dfc52198781516685d2f460e43cb8a8439abfbb0358022be34238bab535b72ec4bb54869533e475ffd09fda776138f0f92d64cdfae76a9bad92210a99d7145d6d7e11925859c539a97eb84d7cca8888220702620fd7e405027e225936fbc3e72a0fac1bd29b44d825cc1b4cb9c727eb0e98a173e1963fcfd82482bb7b233b97dec4bba891f27b89b884884aa18920e65f5c86c11ff6b36e47434ca8c33b1f9b88eb4e612e0029879525e4533ff11dcebc353ba7c601a113d00fbd2b7aa30fa4f5e48775b17dc75ef6fd2196ddcbe7fb0788fdc82604cbfe429065e698c3913ad1425ed19b2f29f01820d564488c835ec1f11b324e0590d37e4473cea4b7f97311c817c948a4c7d681584ffa508fd18e7e72be447271211b823ec58933cac12d2886d413dc5fe1cdcb9f8d4513e07e5036fa712e812f7b5cea696553f78b4648250d2335f91n,
    e: 65537n
}
/** Challenge to get service certificate */
export const SERVICE_CERTIFICATE_CHALLENGE: Readonly<Uint8Array> = new Uint8Array([8,4]);

export const ENCRYPTION_LABEL: Readonly<Uint8Array> = new Uint8Array([0x45, 0x4e, 0x43, 0x52, 0x59, 0x50, 0x54, 0x49, 0x4f, 0x4e, 0x00]); // ENCRYPTION + \x00
export const ENCRYPTION_SIZE: Readonly<Uint8Array> = new Uint8Array([0,0,0,0x80]); // 128
export const AUTHENTICATION_LABEL: Readonly<Uint8Array> = new Uint8Array([0x41, 0x55, 0x54, 0x48, 0x45, 0x4e, 0x54, 0x49, 0x43, 0x41, 0x54, 0x49, 0x4f, 0x4e, 0x00]); // AUTHENTICATION + \x00
export const AUTHENTICATION_SIZE: Readonly<Uint8Array> = new Uint8Array([0,0,2,0]); // 512