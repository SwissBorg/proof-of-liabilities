# SwissBorg Proof-of-Liabilities

https://swissborg.com/blog/proof-of-liabilities

## Previous audits

| Date                    | Audit ID      | Merkle Root Hash                                                   |
| -                       | -             | -                                                                  |
| 2023-08-01 20:59:59 UTC | SBPOL20230801 | `9beb400935a7ecb1783fd50df5e08c7d6f29d7013d1dfe50302f7e4fdcf8c55d` |
| 2023-07-01 20:59:59 UTC | SBPOL20230701 | `b22b844610b0b04b3447c15bc96b679f6e45ae9e6df888922c0d155c8242447d` |
| 2023-06-01 20:59:59 UTC | SBPOL20230601 | `b27a0b7633a5fe8337170032ef8a27d9ffe975f6f9e5540ff53616362a26880d` |
| 2023-05-01 20:59:59 UTC | SBPOL20230501 | `59a9aeef522f954aac4b3933ec60e534f7e10d846fad5be7a8e36d952654d476` |
| 2023-04-12 20:59:59 UTC | SBPOL20230412 | `420e493b403cee3b1ce538827e54cb9e2a3f04af0f28b1cb1400de6027ed77c9` |

This data is also available via the SwissBorg API. You can reproduce this by running the command (requires [`jq`](https://jqlang.github.io/jq/))
```bash
curl "https://api.swissborg.io/v1/solvency/audit?limit=5&offset=0" | jq '.audits[] | [.time, .id, .commitment.digest]'
```

## Self Verification

### Requirements
* nodejs v18+
* yarn

### Installation

```bash
yarn
```

### Self Verification

```bash
export AUDIT_CREDENTIAL=<Your audit credential>
export AUDIT_ID=SBPOL20230801
yarn run self_verification $AUDIT_CREDENTIAL $AUDIT_ID
```
