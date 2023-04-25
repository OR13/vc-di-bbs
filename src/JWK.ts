import crypto from "crypto";
import { BBS } from "@or13/bbs-node-reference";

import {base64url} from 'jose';

const bbs = new BBS();

const signatureHeader = Buffer.from("HEADER", "utf-8");
const proofHeader = Buffer.from("PRESENTATION HEADER", "utf-8");

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
    const generators = await bbs.create_generators(msg.length);
    const messagesAsScalarHashes = msg.map(v => bbs.MapMessageToScalarAsHash(v));
    const signature = bbs.Sign(SK, PK, signatureHeader, messagesAsScalarHashes, generators);
    return `u` + base64url.encode(signature);
}

export const verify = async (msg: any[], signature: string, publicKey:any) => {
    try {
        const signatureBase64 = signature.replace(/^./, ""); // remove u
        const PK = base64url.decode(publicKey.x)
        const generators = await bbs.create_generators(msg.length);
        const messagesAsScalarHashes = msg.map(v => bbs.MapMessageToScalarAsHash(v));
        bbs.Verify(PK, Uint8Array.from(base64url.decode(signatureBase64)), signatureHeader, messagesAsScalarHashes, generators);
        return true
    } catch(e){
        console.error(e)
        return false;
    }
}

export const deriveProof = async(msg: any[], signature: string, disclosed: number[], publicKey:any) => {
    const PK = base64url.decode(publicKey.x)
    const signatureBase64 = signature.replace(/^./, ""); // remove u
    const generators = await bbs.create_generators(msg.length);
    const messagesAsScalarHashes = msg.map(v => bbs.MapMessageToScalarAsHash(v));
    const proof = bbs.ProofGen(PK, Uint8Array.from(base64url.decode(signatureBase64)), signatureHeader, proofHeader, messagesAsScalarHashes, generators, disclosed);
    return {
        disclosed,
        generators: msg.length,
        proofValue: `u` + base64url.encode(proof)
    }
}   

export const verifyProof = async(originalMessagesLength: number, disclosedMessages: any[], proof: string, disclosed: number[], publicKey:any) => {
    try {
        const proofBase64 = proof.replace(/^./, ""); // remove u
        const PK = base64url.decode(publicKey.x)
        const generators = await bbs.create_generators(originalMessagesLength);
        const disclosedMessagesAsScalarHashes = disclosedMessages.map(v => bbs.MapMessageToScalarAsHash(v));
        bbs.ProofVerify(PK, Uint8Array.from(base64url.decode(proofBase64)), signatureHeader, proofHeader, disclosedMessagesAsScalarHashes, generators, disclosed);
        return true
    } catch(e){
        console.error(e)
        return false;
    }
}   

