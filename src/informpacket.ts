import { subtle, webcrypto } from 'crypto';
import { uncompress as unSnappy } from 'snappyjs';
import { inflateSync as inflateZlib } from 'zlib';


export const enum InformPacketDataType {
    Binary, JSON
}

export type InformPacketFlag = 
    "Encrypted" | "EncryptedGCM" | 
    "Compressed" | "CompressedSnappy" | `Unk_${number}`;

export interface InformPacketHeader {
    rawPacket: Buffer;
    rawHeader: Buffer;
    fields: {
        version: number;
        mac: string;
        encryptionMethod: "none" | "AES-GCM" | "AES-CBC";
        compressionMethod: "none" | "zlib" | "Snappy";
        iv: Uint8Array;
        dataType: InformPacketDataType;
        flags: InformPacketFlag[];
        payloadLength: number;
    }
    payload: Uint8Array;
}


// Default key for UBNT devices - literally just `md5("ubnt")`
const UBNT_DEFAULT_KEY = "ba86f2bbe107c7c57eb5f2690775c712";

function readInformHeader(packet: Buffer) {
    var header = packet.subarray(0,40)
    // check magic is 'TNBU' (trivia: UBNT backwards!)
    if (header.readUint32BE(0) !== 1414414933) 
       throw new Error("expected TNBU (1414414933), got " + [...packet.subarray(0,4)].map(a => String.fromCharCode(a)).join("") + " (" + header.readUint32BE(0) + ")");
    
    let payloadLength = header.readUint32BE(36)
    if (payloadLength > packet.length - 40) throw new Error("Payload is too short, expected " + payloadLength + " got " + (packet.length - 40) + " bytes.")
    let payload = packet.subarray(40, payloadLength + 40)

    let flags = header
        .readUint16BE(14)
        .toString(2)
        .split('')
        .reverse()
        .map((v,x) => 
            (v == "1" ? (
                x == 0 ? "Encrypted" :
                x == 1 ? "Compressed" :
                x == 2 ? "CompressedSnappy" : 
                x == 3 ? "EncryptedGCM" :
                "Unk_" + v
            ) : false)
        ).filter((a) => !!a) as InformPacketFlag[];
    if (flags.find((a) => a.startsWith("Unk_"))) console.warn("Unknown flags found, decryption/decompresssion may fail! " + flags)

    const pHeader: InformPacketHeader = {
        rawPacket: packet,
        rawHeader: header,
        payload,
        fields: {
            version: header.readUint32BE(4),
            mac: [...packet.subarray(8,14)].map((a) => a.toString(16).padStart(2,'0')).join(":"),
            encryptionMethod:
                flags.includes("EncryptedGCM") ? "AES-GCM" :
                flags.includes("Encrypted") ? "AES-CBC" :
                "none",
            compressionMethod: 
                flags.includes("CompressedSnappy") ? "Snappy" :
                flags.includes("Compressed") ? "zlib" :
                "none",
            iv: packet.subarray(16,32),
            dataType: header.readUint32BE(32),
            flags,
            payloadLength,
        }
    };
    // check version is 0
    if (pHeader.fields.version !== 0) console.warn("Version was expected to be '0', was " +  pHeader.fields.version)
        
    
    return pHeader;
}

async function decryptPacket(header: InformPacketHeader, key: webcrypto.BufferSource) {
    let { encryptionMethod, iv } = header.fields; 
    if (encryptionMethod == "none") return new Uint8Array(header.payload.buffer);

    var ck =  await subtle.importKey('raw', key, encryptionMethod, true, ['decrypt'])
    return new Uint8Array(await crypto.subtle.decrypt({name: encryptionMethod, iv, additionalData: header.rawHeader}, ck, header.payload))
}


function decompressPacket(method: InformPacketHeader['fields']['compressionMethod'], compressed: Uint8Array) {
    if (method == "zlib") return inflateZlib(compressed)
    else if (method == "Snappy") return unSnappy(compressed)
    else if (method == "none") return compressed;
    else throw new Error("Unknown compression method " + method)
}
  
export async function parseInformPacket(packet: Buffer,keyProvider: (mac: string) => Promise<string | undefined> | (string | undefined)) {
    let head: InformPacketHeader['fields'];
    let keyUsed: string;
    let data, error;
    try {
        let header = readInformHeader(packet);
        head = header.fields;
        
        let key = await keyProvider(head.mac) || UBNT_DEFAULT_KEY;
        keyUsed = key;
        if (key == UBNT_DEFAULT_KEY) keyUsed = "(default)";

        let decrypted = await decryptPacket(header, Buffer.from(key, "hex"));
        let decompressed = Buffer.from(decompressPacket(head.compressionMethod,decrypted))
        data = JSON.parse(decompressed.toString())
    } catch(e) {
        error = e
    }
    return { head, data, error, keyUsed }
}
