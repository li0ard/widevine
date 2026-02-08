import { bytesToHex, concatBytes, equalBytes, numberToBytesBE, randomBytes } from "@noble/ciphers/utils.js";
import type { Device } from "./device.js";
import type { PSSH } from "./pssh.js";
import { DeviceType } from "./const.js";
import { Session } from "./session.js";
import { PSS, OAEP, mgf1, type Signer, type KEM } from 'micro-rsa-dsa-dh/rsa.js';
import { sha1 } from "@noble/hashes/legacy.js";
import { pywidevine_license_protocol } from "./protos/license_protocol.js";
import { hmac } from "@noble/hashes/hmac.js";
import { sha256 } from "@noble/hashes/sha2.js";
import { cmac } from "@noble/ciphers/aes.js";
import { Key } from "./key.js";

const { LicenseType, LicenseRequest, ProtocolVersion, SignedMessage, License } = pywidevine_license_protocol;
const ENCRYPTION_LABEL = new Uint8Array([0x45, 0x4e, 0x43, 0x52, 0x59, 0x50, 0x54, 0x49, 0x4f, 0x4e, 0x00]); // ENCRYPTION + \x00
const ENCRYPTION_SIZE = new Uint8Array([0,0,0,0x80]); // 128
const AUTHENTICATION_LABEL = new Uint8Array([0x41, 0x55, 0x54, 0x48, 0x45, 0x4e, 0x54, 0x49, 0x43, 0x41, 0x54, 0x49, 0x4f, 0x4e, 0x00]); // AUTHENTICATION + \x00
const AUTHENTICATION_SIZE = new Uint8Array([0,0,2,0]); // 512

/** Widevine Content Decryption Module (CDM) instance */
export class CDM {
    private sessions = new Map<string, Session>();

    private signer: Signer;
    private crypter: KEM;

    /**
     * Widevine Content Decryption Module (CDM) instance
     * @param device Device instance
     */
    constructor(public device: Device) {
        this.signer = PSS(sha1, mgf1(sha1), 20);
        this.crypter = OAEP(sha1, mgf1(sha1));
    }

    /** Open session */
    public open(): string {
        const session = new Session(this.sessions.size + 1);
        const id = bytesToHex(session.id);
        this.sessions.set(id, session);

        return id;
    }

    /**
     * Close session
     * @param sessionId Session ID
     */
    public close(sessionId: string) {
        if(!this.sessions.get(sessionId)) throw new Error("Session identifier is invalid");

        this.sessions.delete(sessionId);
    }

    /**
     * Get license request (challenge)
     * @param sessionId Session ID 
     * @param pssh PSSH object
     * @param license_type License type (default - `STREAMING`)
     */
    public get_license_challenge(sessionId: string, pssh: PSSH, license_type = LicenseType.STREAMING): Uint8Array {
        const session = this.sessions.get(sessionId);
        if(!session) throw new Error("Session identifier is invalid");

        let request_id: Uint8Array;
        if(this.device.type == DeviceType.ANDROID) request_id = new TextEncoder().encode(bytesToHex(concatBytes(
            randomBytes(4),
            new Uint8Array(4),
            numberToBytesBE(session.number, 8).reverse()
        )).toUpperCase());
        else request_id = randomBytes(16);
        
        const wvdPsshData = new LicenseRequest.ContentIdentification.WidevinePsshData();
        wvdPsshData.pssh_data = [pssh.init_data];
        wvdPsshData.license_type = license_type;
        wvdPsshData.request_id = request_id;

        const contentId = new LicenseRequest.ContentIdentification()
        contentId.widevine_pssh_data = wvdPsshData;

        const licenseRequest = new LicenseRequest();
        licenseRequest.client_id = this.device.client_id;
        licenseRequest.content_id = contentId;
        licenseRequest.type = LicenseRequest.RequestType.NEW;
        licenseRequest.request_time = Math.round(Date.now() / 1000);
        licenseRequest.protocol_version = ProtocolVersion.VERSION_2_1;
        licenseRequest.key_control_nonce = Math.floor(Math.random() * 2000000) + 1;

        const licenseRequestSerialized = licenseRequest.serializeBinary();

        const signedLicenseRequest = new SignedMessage();
        signedLicenseRequest.type = SignedMessage.MessageType.LICENSE_REQUEST;
        signedLicenseRequest.msg = licenseRequestSerialized;
        signedLicenseRequest.signature = this.signer.sign(this.device.privateKey, licenseRequestSerialized)

        session.context.set(bytesToHex(request_id), this.derive_context(licenseRequestSerialized))
        return signedLicenseRequest.serializeBinary();
    }

    /**
     * Get keys from license response
     * @param sessionId Session ID
     * @param license_response License response
     */
    public parse_license(sessionId: string, license_response: Uint8Array): Key[] {
        const session = this.sessions.get(sessionId);
        if(!session) throw new Error("Session identifier is invalid");

        const license_message = SignedMessage.deserializeBinary(license_response);
        if(license_message.type != SignedMessage.MessageType.LICENSE) throw new Error("Invalid message type");

        const license = License.deserializeBinary(license_message.msg);
        
        const context = session.context.get(bytesToHex(license.id.request_id));
        if(!context) throw new Error("Cannot parse a license message without first making a license request");

        const [enc_key, mac_key_server, _] = this.derive_keys(
            context[0], context[1],
            this.crypter.decrypt(this.device.privateKey, license_message.session_key)
        );

        const computed_signature = hmac(
            sha256, mac_key_server,
            license_message.oemcrypto_core_message.length != 0
                ? concatBytes(license_message.oemcrypto_core_message, license_message.msg)
                : license_message.msg
        );

        if(!equalBytes(computed_signature, license_message.signature)) throw new Error("Signature mismatch on license message");

        session.keys = license.key.map(i => Key.fromContainer(i, enc_key));
        session.context.delete(bytesToHex(license.id.request_id));

        return session.keys;
    }

    private derive_keys(enc_context: Uint8Array, mac_context: Uint8Array, key: Uint8Array): Uint8Array[] {
        const _derive = (session_key: Uint8Array, context: Uint8Array, counter: number) =>
            cmac(session_key, concatBytes(numberToBytesBE(counter, 1), context));

        const enc_key = _derive(key, enc_context, 1);
        const mac_key_server = concatBytes(_derive(key, mac_context, 1), _derive(key, mac_context, 2));
        const mac_key_client = concatBytes(_derive(key, mac_context, 3), _derive(key, mac_context, 4));

        return [enc_key, mac_key_server, mac_key_client];
    }

    private derive_context(message: Uint8Array): Uint8Array[] {
        return [
            concatBytes(ENCRYPTION_LABEL, message, ENCRYPTION_SIZE),
            concatBytes(AUTHENTICATION_LABEL, message, AUTHENTICATION_SIZE)
        ];
    }
}

export { WIDEVINE_SID, KeyType, DeviceType} from "./const.js";
export { Device } from "./device.js";
export { Key } from "./key.js";
export { PSSH } from "./pssh.js";