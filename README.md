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

#### Full Disclosure 

Example:

```json
{
  "@context": [
    {
      "@vocab": "https://www.w3.org/ns/did/controller-dependent#"
    }
  ],
  "💀": "🔥",
  "🌱": "🐋",
  "🌈": "🚀",
  "proof": {
    "type": "FullDisclosureProof",
    "value": "oQLBFeiZfpNcHqWcTckM05G7hyOgSgedUoeDnrqGcYQKHnuuok9gRx-1AeVKaTNYMLY9gaTNTnyyZjfDfjcBLL6VV2iXa5PbfR_xk63ca8wPUTt-DSMJ8CknEb9bxbFVG_ccpP4Gnp-3pkmLZgCNjg"
  }
}
```

#### Selective Disclosure 

Example:

```json
{
  "@context": {
    "@vocab": "https://www.w3.org/ns/did/controller-dependent#"
  },
  "@id": "urn:bnid:_:c14n0",
  "🌱": "🐋",
  "proof": {
    "type": "PartialDisclosureProof",
    "disclosed": [
      2
    ],
    "generators": 3,
    "value": "iDeWr8yHII0fcvpCkh1bTh14PM00uv6TnqGmTETABljkbc1B4HhqtLs3D83_60D9qPoj-oNd7iX5xdWHzxOx4aVt_JIZxdvxCbBrfE2U5PDlI2VlxBu6qc73Kk3o3a1qkkvK748KToQvT2pQ9eWQId-88L_jyVPGizjRRmh0A-QT_G84_M2IfOc4whBBwX3SahhrNDYNXNqfeCnRAxZGPoG5JZASBmHKbWuAwXNhzwUkObg4VifTvIdHqVvAG83RaAYhT7AzGW6kppDqa4KF9TtVQp9uM7e2PWjEGSGsuznN_E-BDhBtiDlhiwFrQWs0LL39X1eLd_PpXHqsV_4BYJmB9KvlkH0yVFEoQO3TmakDYk6_udbXiQkssFNAb1zuwpJjgmc9nl9YFL82J2W_wiOOQZj_DrrSfqsnAUs97mIGz1DBMBN8CWBRVprxXOOVIC1hH8Bp0wmcgt5WMImB6uA51TX9gSMYoZ3mv-bbqWc"
  }
}
```

## Develop

```bash
npm i
npm t
npm run lint
npm run build
```