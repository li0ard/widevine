import { equalBytes } from "@noble/ciphers/utils.js";
import { pywidevine_license_protocol } from "./protos/license_protocol.js";
import { WIDEVINE_SID } from "./const.js";

/** Protection System Specific Header (PSSH) object */
export class PSSH {
    /** Protection System Specific Header (PSSH) */
    constructor(public version: number, public flags: number, public system_id: Uint8Array, public kids: Uint8Array[] = [], public init_data: Uint8Array) {}

    /** Get decoded payload (Widevine only) */
    get decoded(): pywidevine_license_protocol.WidevinePsshData | null {
        return equalBytes(this.system_id, WIDEVINE_SID) ? pywidevine_license_protocol.WidevinePsshData.deserialize(this.init_data) : null;
    }

    /** Get PSSH object from bytes */
    static decode(pssh: Uint8Array): PSSH {
        const rdr = new DataView(pssh.buffer, pssh.byteOffset);

        // const size = rdr.getUint32(offset); offset += 4;

        let offset = 4;
        const box_header = new TextDecoder().decode(pssh.subarray(offset, offset + 4));
        offset += 4;
        if(box_header !== "pssh") throw new Error("Expecting BMFF header");

        const version_and_flags = rdr.getUint32(offset);
        offset += 4;

        const version = (version_and_flags >> 24) & 0xff;
        if(version > 1) throw new Error("Unknown PSSH version " + version);

        const system_id = pssh.slice(offset, offset + 16);
        offset += 16;

        const kids: Uint8Array[] = [];
        if(version == 1) {
            let kid_count = rdr.getUint32(offset);
            offset += 4;
            while (kid_count > 0) {
                const kid = pssh.slice(offset, offset + 16);
                offset += 16;
                kids.push(kid);
                kid_count -= 1;
            }
        }

        //const pssh_data_len = rdr.getUint32(offset);
        offset += 4;

        return new PSSH(version, version_and_flags & 0xF, system_id, kids, pssh.slice(offset));
    }
}