import { bytesToNumberBE, equalBytes, hexToBytes } from "@noble/ciphers/utils.js";
import { pywidevine_license_protocol } from "./protos/license_protocol.js";

/** System IDs */
export const SystemID: Record<"WIDEVINE" | "PLAYREADY", Readonly<Uint8Array>> = {
    WIDEVINE: hexToBytes("edef8ba979d64acea3c827dcd51d21ed"),
    PLAYREADY: hexToBytes("9a04f07998404286ab92e65be0885f95")
}

export interface PlayReadyRecord {
    type: number;
    value: string;
}

const bytesToNumberLE = (bytes: Uint8Array): bigint => bytesToNumberBE(new Uint8Array(bytes).reverse());

/** Protection System Specific Header (PSSH) object */
export class PSSH {
    /** Protection System Specific Header (PSSH) */
    constructor(public version: number, public flags: number, public systemId: Uint8Array, public kids: Uint8Array[] = [], public initData: Uint8Array) {}

    /** Get decoded payload (Widevine and PlayReady only) */
    get decoded(): pywidevine_license_protocol.WidevinePsshData | PlayReadyRecord[] | null {
        if(equalBytes(this.systemId, SystemID.WIDEVINE)) return pywidevine_license_protocol.WidevinePsshData.deserialize(this.initData);
        else if(equalBytes(this.systemId, SystemID.PLAYREADY)) {
            let offset = 0;

            const proLength = bytesToNumberLE(this.initData.slice(offset, offset += 4));
            if(proLength != BigInt(this.initData.length)) return null;

            const proRecordCount = bytesToNumberLE(this.initData.slice(offset, offset += 2));

            const records: PlayReadyRecord[] = [];
            for(let _ = 0n; _ < proRecordCount; _++) {
                const type = Number(bytesToNumberLE(this.initData.slice(offset, offset += 2)));
                const length = Number(bytesToNumberLE(this.initData.slice(offset, offset += 2)));
                if(type == 1) records.push({
                    type,
                    value: new TextDecoder("utf-16le").decode(this.initData.slice(offset, offset += length))
                });
            }

            return records;
        }
        else return null;
    }

    /** Get PSSH object from bytes */
    static decode(pssh: Uint8Array): PSSH {
        const rdr = new DataView(pssh.buffer, pssh.byteOffset);

        let offset = 4;
        // const size = rdr.getUint32(offset); offset += 4;
        
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