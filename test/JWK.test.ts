
import crypto from 'crypto'

import {JWK} from '../src'

const seed = '4940c419a458c92bd6e232b04da8bf2861516f27646a4b65cd336f17a025462c';
const privateKey = {
  "kty": "OKP",
  "crv": "Bls12381G2",
  "x": "qBpTVEN37H4iE6G7N9pq_44dH9dyb-vCc4GM3f_cpAj3OOAZcxDkfbEWi_IzctHCAFpptIu0mWLYujroDccDYZp_cIxEWKZ2bAtxvmifuT0YwAI9lV0qavteDOVgnqSZ",
  "d": "SUDEGaRYySvW4jKwTai_KGFRbydkaktlzTNvF6AlRiw"
}

it("can generate JWK from seed", async () => {
  const privateKey = JWK.generate(Buffer.from(seed, 'hex'));
  expect(privateKey).toBe(privateKey)
});

it("can sign with private key", async () => {
  const msg = Array(5).fill(null).map(() => crypto.randomBytes(20));
  const signature = await JWK.sign(msg, privateKey)
  const verified1 = await JWK.verify(msg, signature, privateKey)
  expect(verified1).toBe(true)
  const proof = await JWK.deriveProof(msg, signature, [ 2, 3, 5 ], privateKey)
  const disclosedMessages = msg.filter((v, i, a) => {return proof.disclosed.includes(i+1)});
  const verified2 = await JWK.verifyProof(proof.generators, disclosedMessages, proof.proofValue, proof.disclosed, privateKey)
  expect(verified2).toBe(true)
});
