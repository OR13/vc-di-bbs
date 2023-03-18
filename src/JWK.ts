import crypto from "crypto";
import { BBS } from "@or13/bbs-node-reference";

import {base64url} from 'jose';

const bbs = new BBS();

export const generate = (seed = crypto.randomBytes(32))=>{
    const SK = bbs.KeyGen(seed);
    const PK = bbs.SkToPk(SK);
    return {
        "kty": "OKP",
        "crv": "Bls12381G2",
        "x": base64url.encode(PK),  // probably wrong.
        "d": base64url.encode(seed) // probably wrong.
    }
}

export const sign = async (msg: any[], privateKey:any) => {
    const SK = bbs.KeyGen(base64url.decode(privateKey.d));
    const PK = bbs.SkToPk(SK)
    const length = msg.length;
    const generators = await bbs.create_generators(length);
    const messagesAsScalarHashes = msg.map(v => bbs.MapMessageToScalarAsHash(v));
    const header = Buffer.from("HEADER", "utf-8");
    const signature = bbs.Sign(SK, PK, header, messagesAsScalarHashes, generators);
    return base64url.encode(signature);
}

export const verify = async (msg: any[], signature: string, publicKey:any) => {
    try {
        const PK = base64url.decode(publicKey.x)
        const length = msg.length;
        const generators = await bbs.create_generators(length);
        const messagesAsScalarHashes = msg.map(v => bbs.MapMessageToScalarAsHash(v));
        const header = Buffer.from("HEADER", "utf-8");
        bbs.Verify(PK, Uint8Array.from(base64url.decode(signature)), header, messagesAsScalarHashes, generators);
        return true
    } catch(e){
        console.log(e)
        return false;
    }
}


    
