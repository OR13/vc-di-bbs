import { DataIntegrity } from '../src'

import { documentLoader } from './documentLoader';

const privateKey = {
  "kty": "OKP",
  "crv": "Bls12381G2",
  "x": "qBpTVEN37H4iE6G7N9pq_44dH9dyb-vCc4GM3f_cpAj3OOAZcxDkfbEWi_IzctHCAFpptIu0mWLYujroDccDYZp_cIxEWKZ2bAtxvmifuT0YwAI9lV0qavteDOVgnqSZ",
  "d": "SUDEGaRYySvW4jKwTai_KGFRbydkaktlzTNvF6AlRiw"
}

const suite = new DataIntegrity({ privateKey })

const document = {
  "@context": [{"@vocab":"https://www.w3.org/ns/did/controller-dependent#"}],
  "💀": "🔥",
  "🌱": "🐋",
  "🌈": "🚀"
}

const frame = {
  "@context": [{"@vocab":"https://www.w3.org/ns/did/controller-dependent#"}],
  "@explicit": true,
  "🌱": {}
}

it("canonize", async () => {
  const canonicalized = await suite.canonize(document, documentLoader);
  const lines = canonicalized.split("\n").filter((line: string)=> !!line)
  expect(lines.length).toBe(3)
});

it("sign / verify - derive / verify", async () => {
  const signed = await suite.sign(document, documentLoader);
  // console.log(JSON.stringify(signed, null, 2))
  const verified1 = await suite.verify(signed, documentLoader);
  expect(verified1).toBe(true);
  const derived = await suite.derive(signed, frame, documentLoader);
  // console.log(JSON.stringify(derived, null, 2))
  const verified2 = await suite.verify(derived, documentLoader);
  expect(verified2).toBe(true);
});

afterAll((done)=>{
  setTimeout(done, 1)
})