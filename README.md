# vc-di-bbs

[![CI](https://github.com/or13/vc-di-bbs/actions/workflows/ci.yml/badge.svg)](https://github.com/or13/vc-di-bbs/actions/workflows/ci.yml)
![Branches](./badges/coverage-branches.svg)
![Functions](./badges/coverage-functions.svg)
![Lines](./badges/coverage-lines.svg)
![Statements](./badges/coverage-statements.svg)
![Jest coverage](./badges/coverage-jest%20coverage.svg)

<!-- [![NPM](https://nodei.co/npm/@or13/vc-di-bbs.png?mini=true)](https://npmjs.org/package/@or13/vc-di-bbs) -->

Experimental implementation of bbs data integrity proofs.

Built on: [microsoft/bbs-node-reference](https://github.com/microsoft/bbs-node-reference)


## Usage

```sh
npm i @or13/vc-di-bbs --save
```

```ts
import { DataIntegrity } from '@or13/vc-di-bbs'

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

// Full disclosure
const signed = await suite.sign(document, documentLoader);
const verified1 = await suite.verify(signed, documentLoader);

// Selective disclosure
const derived = await suite.derive(signed, frame, documentLoader);
const verified2 = await suite.verify(derived, documentLoader);

```

## Develop

```bash
npm i
npm t
npm run lint
npm run build
```