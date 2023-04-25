import jsonld from "jsonld";

import * as JWK from "./JWK";

export class DataIntegrity {
  public privateKey: any;

  constructor({ privateKey }: { privateKey: any }) {
    this.privateKey = privateKey;
  }

  async canonize(document: any, documentLoader: any) {
    return jsonld.canonize(document, {
      algorithm: "URDNA2015",
      format: "application/n-quads",
      documentLoader,
    });
  }

  messages(canonicalized: string) {
    const lines = canonicalized
      .split("\n")
      .filter((line: string) => !!line)
      .map((line: string) => {
        // idempotency
        if (line.includes("<urn:bnid:")) {
          return line;
        } else {
          return line.replace(/(_:c14n[0-9]+)/g, "<urn:bnid:$1>");
        }
      })
      .map(Buffer.from);
    return lines;
  }

  async removeBlankNodes(document: any, documentLoader:any){
    const clone = JSON.parse(JSON.stringify(document));
    const documentWithoutBlankNodes = await jsonld.compact(
      await jsonld.fromRDF(
        this.messages(await this.canonize(document, documentLoader)).join("\n")
      ),
      clone["@context"]
    );
    return documentWithoutBlankNodes;
  }

  async disclosedDocument(fullDocument: any, proof: string, frame: any, documentLoader:any){
    const disclosedDocument = await jsonld.frame(fullDocument, frame, {
      documentLoader,
    });
    const revealedMessages = this.messages(
      await this.canonize(disclosedDocument, documentLoader)
    );
    const allMessages = this.messages(
      await this.canonize(fullDocument, documentLoader)
    );
    const disclosed = this.disclosed(allMessages, revealedMessages);
    const proofComponents = await JWK.deriveProof(
      allMessages,
      proof,
      disclosed,
      this.privateKey
    );
    disclosedDocument.proof = {
      type: "DataIntegrityProof",
      cryptosuite: 'bbs-proof-2023',
      ...proofComponents,
    };
    return disclosedDocument
  }

  disclosed(allMessages: Buffer[], revealedMessages: Buffer[]) {
    const disclosure: number[] = [];
    const full = allMessages.map((m) => m.toString("utf8"));
    const partial = revealedMessages.map((m) => m.toString("utf8"));
    full.forEach((message: string, index: number) => {
      if (partial.includes(message)) {
        disclosure.push(index + 1);
      }
    });
    return disclosure;
  }

  async sign(document: any, documentLoader: any) {
    const clone = JSON.parse(JSON.stringify(document));
    const canonicalized = await this.canonize(clone, documentLoader);
    const lines = this.messages(canonicalized);
    const signature = await JWK.sign(lines, this.privateKey);
    const proof = {
      "type": "DataIntegrityProof",
      "cryptosuite": "bbs-signature-2023",
      proofValue: signature,
    };
    clone.proof = proof;
    return clone;
  }

  async verify(document: any, documentLoader: any) {
    const clone = JSON.parse(JSON.stringify(document));
    const { type, cryptosuite } = clone.proof;
    if (type === "DataIntegrityProof" && cryptosuite === 'bbs-signature-2023') {
      const { proofValue } = clone.proof;
      delete clone.proof;
      const canonicalized = await this.canonize(clone, documentLoader);
      const lines = this.messages(canonicalized);
      const verified = await JWK.verify(lines, proofValue, this.privateKey);
      return verified;
    } else if (type === "DataIntegrityProof" && cryptosuite === 'bbs-proof-2023') {
      const { generators, disclosed, proofValue } = clone.proof;
      delete clone.proof;
      const revealedMessages = this.messages(
        await this.canonize(clone, documentLoader)
      );
      const verified = await JWK.verifyProof(
        generators,
        revealedMessages,
        proofValue,
        disclosed,
        this.privateKey
      );
      return verified;
    }

    return false;
  }

  async derive(document: any, frame: any, documentLoader: any) {
    const clone = JSON.parse(JSON.stringify(document));
    const { type, cryptosuite, proofValue } = clone.proof;
    if (type !== "DataIntegrityProof" || cryptosuite !== 'bbs-signature-2023') {
      throw new Error(
        "Expected FullDisclosureProof, encountered unsupported type: " + type
      );
    }
    delete clone.proof;
    const fullDocument = await this.removeBlankNodes(clone, documentLoader)
    // all messages
    return this.disclosedDocument(fullDocument, proofValue, frame, documentLoader)
  }
}
