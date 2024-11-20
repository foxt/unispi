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