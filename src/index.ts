import { DeviceType, ROOT_CERT_PUBLIC, ENCRYPTION_LABEL, ENCRYPTION_SIZE, AUTHENTICATION_LABEL, AUTHENTICATION_SIZE } from "./const.js";
import { pywidevine_license_protocol } from "./protos/license_protocol.js";
import { PSS, OAEP, mgf1 } from 'micro-rsa-dsa-dh/rsa.js';
import { sha1 } from "@noble/hashes/legacy.js";
import { hmac } from "@noble/hashes/hmac.js";
import { sha256 } from "@noble/hashes/sha2.js";
import { cbc, cmac } from "@noble/ciphers/aes.js";
import type { Device } from "./device.js";
import { Key } from "./key.js";
import type { PSSH } from "@li0ard/pssh";
import { Session } from "./session.js";
import { bytesToHex, concatBytes, equalBytes, numberToBytesBE, randomBytes } from "@noble/ciphers/utils.js";
import { decodePublicKey } from "./utils.js";

const signer = PSS(sha1, mgf1(sha1), 20);
const crypter = OAEP(sha1, mgf1(sha1));

/** Widevine Content Decryption Module (CDM) instance */
export class CDM {
    static MAX_SESSIONS = 16;
    private sessions = new Map<string, Session>();

    /**
     * Widevine Content Decryption Module (CDM) instance
     * @param device Device instance
     */
    constructor(public device: Device) {}

    /** Open session */
    public open(): string {
        if(this.sessions.size > CDM.MAX_SESSIONS) throw new Error("Too many sessions");
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
     * @param licenseType License type (default - `STREAMING`)
     * @param privacyMode Encrypt the Client ID using service certificate (If service certificate is set)
     */
    public getLicenseChallenge(sessionId: string, pssh: PSSH, licenseType = pywidevine_license_protocol.LicenseType.STREAMING, privacyMode = true): Uint8Array {
        const session = this.sessions.get(sessionId);
        if(!session) throw new Error("Session identifier is invalid");

        let request_id: Uint8Array;
        if(this.device.type == DeviceType.ANDROID) request_id = new TextEncoder().encode(bytesToHex(concatBytes(
            randomBytes(4),
            new Uint8Array(4),
            numberToBytesBE(session.number, 8).reverse()
        )).toUpperCase());
        else request_id = randomBytes(16);
        
        const wvdPsshData = new pywidevine_license_protocol.LicenseRequest.ContentIdentification.WidevinePsshData();
        wvdPsshData.pssh_data = [pssh.init_data];
        wvdPsshData.license_type = licenseType;
        wvdPsshData.request_id = request_id;

        const contentId = new pywidevine_license_protocol.LicenseRequest.ContentIdentification();
        contentId.widevine_pssh_data = wvdPsshData;

        const licenseRequest = new pywidevine_license_protocol.LicenseRequest();
        if(session.serviceCertificate && privacyMode) licenseRequest.encrypted_client_id = CDM.encryptClientId(this.device.clientId, session.serviceCertificate);
        else licenseRequest.client_id = this.device.clientId;
        licenseRequest.content_id = contentId;
        licenseRequest.type = pywidevine_license_protocol.LicenseRequest.RequestType.NEW;
        licenseRequest.request_time = Math.round(Date.now() / 1000);
        licenseRequest.protocol_version = pywidevine_license_protocol.ProtocolVersion.VERSION_2_1;
        licenseRequest.key_control_nonce = Math.floor(Math.random() * 2000000) + 1;

        const licenseRequestSerialized = licenseRequest.serializeBinary();

        const signedLicenseRequest = new pywidevine_license_protocol.SignedMessage();
        signedLicenseRequest.type = pywidevine_license_protocol.SignedMessage.MessageType.LICENSE_REQUEST;
        signedLicenseRequest.msg = licenseRequestSerialized;
        signedLicenseRequest.signature = signer.sign(this.device.privateKey, licenseRequestSerialized);

        session.context.set(bytesToHex(request_id), CDM.deriveContext(licenseRequestSerialized));
        return signedLicenseRequest.serializeBinary();
    }

    /**
     * Set service certificate for privacy mode
     * @param sessionId Session ID
     * @param certificate Service certificate (If none remove current)
     */
    public setServiceCertificate(sessionId: string, certificate?: Uint8Array): string | null {
        const session = this.sessions.get(sessionId);
        if(!session) throw new Error("Session identifier is invalid");

        let providerId: string | null;
        if(!certificate) {
            if(session.serviceCertificate) {
                const drmCertificate = pywidevine_license_protocol.DrmCertificate.deserializeBinary(session.serviceCertificate.drm_certificate);
                providerId = drmCertificate.provider_id;
            }
            else providerId = null;

            session.serviceCertificate = undefined;

            return providerId;
        }

        let signedDrmCertificate: pywidevine_license_protocol.SignedDrmCertificate;
        try {
            const signedMessage = pywidevine_license_protocol.SignedMessage.deserialize(certificate);
            
            signedDrmCertificate = pywidevine_license_protocol.SignedDrmCertificate.deserialize(signedMessage.msg);
            if(signedDrmCertificate.drm_certificate.length == 0) throw new Error("");
        } catch(e) {
            signedDrmCertificate = pywidevine_license_protocol.SignedDrmCertificate.deserialize(certificate);
        }

        if(!signedDrmCertificate.drm_certificate) throw new Error("Can't decode DRM certificate");
        if(!signer.verify(ROOT_CERT_PUBLIC, signedDrmCertificate.drm_certificate, signedDrmCertificate.signature)) throw new Error("Signature mismatch");

        const drmCertificate = pywidevine_license_protocol.DrmCertificate.deserializeBinary(signedDrmCertificate.drm_certificate);
        session.serviceCertificate = signedDrmCertificate;

        return drmCertificate.provider_id;
    }

    /**
     * Get service certificate of session
     * @param sessionId Session ID
     */
    public getServiceCertificate(sessionId: string): pywidevine_license_protocol.SignedDrmCertificate | null {
        const session = this.sessions.get(sessionId);
        if(!session) throw new Error("Session identifier is invalid");

        return session.serviceCertificate ?? null;
    }

    /**
     * Get keys from license response
     * @param sessionId Session ID
     * @param licenseResponse License response
     */
    public parseLicense(sessionId: string, licenseResponse: Uint8Array): Key[] {
        const session = this.sessions.get(sessionId);
        if(!session) throw new Error("Session identifier is invalid");

        const license_message = pywidevine_license_protocol.SignedMessage.deserializeBinary(licenseResponse);
        if(license_message.type != pywidevine_license_protocol.SignedMessage.MessageType.LICENSE) throw new Error("Invalid message type");

        const license = pywidevine_license_protocol.License.deserializeBinary(license_message.msg);
        
        const context = session.context.get(bytesToHex(license.id.request_id));
        if(!context) throw new Error("Cannot parse a license message without first making a license request");

        const [enc_key, mac_key_server] = CDM.deriveKeys(
            context[0], context[1],
            crypter.decrypt(this.device.privateKey, license_message.session_key)
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

    /** Encrypt Client ID with Service certificate */
    static encryptClientId(
        clientId: pywidevine_license_protocol.ClientIdentification,
        serviceCertificate: pywidevine_license_protocol.SignedDrmCertificate,
        key?: Uint8Array,
        iv?: Uint8Array
    ): pywidevine_license_protocol.EncryptedClientIdentification {
        const privacy_key = key ?? randomBytes(16), privacy_iv = iv ?? randomBytes(16);

        const drmCertificate = pywidevine_license_protocol.DrmCertificate.deserializeBinary(serviceCertificate.drm_certificate);
        const encryptClientIdentification = new pywidevine_license_protocol.EncryptedClientIdentification();

        encryptClientIdentification.provider_id = drmCertificate.provider_id;
        encryptClientIdentification.service_certificate_serial_number = drmCertificate.serial_number;
        encryptClientIdentification.encrypted_client_id = cbc(privacy_key, privacy_iv).encrypt(clientId.serializeBinary());
        encryptClientIdentification.encrypted_client_id_iv = privacy_iv;
        encryptClientIdentification.encrypted_privacy_key = crypter.encrypt(decodePublicKey(drmCertificate.public_key), privacy_key);

        return encryptClientIdentification;
    }

    /** Compute keys from context and key  */
    static deriveKeys(encContext: Uint8Array, macContext: Uint8Array, key: Uint8Array): Uint8Array[] {
        const _derive = (session_key: Uint8Array, context: Uint8Array, counter: number) =>
            cmac(session_key, concatBytes(numberToBytesBE(counter, 1), context));

        const enc_key = _derive(key, encContext, 1);
        const mac_key_server = concatBytes(_derive(key, macContext, 1), _derive(key, macContext, 2));
        const mac_key_client = concatBytes(_derive(key, macContext, 3), _derive(key, macContext, 4));

        return [enc_key, mac_key_server, mac_key_client];
    }

    /** Compute context for AES and HMAC keys */
    static deriveContext(message: Uint8Array): Uint8Array[] {
        return [
            concatBytes(ENCRYPTION_LABEL, message, ENCRYPTION_SIZE),
            concatBytes(AUTHENTICATION_LABEL, message, AUTHENTICATION_SIZE)
        ];
    }
}

export { KeyType, DeviceType, LicenseType, SERVICE_CERTIFICATE_CHALLENGE } from "./const.js";
export { Device } from "./device.js";
export { Key } from "./key.js";
export { PSSH } from "@li0ard/pssh";