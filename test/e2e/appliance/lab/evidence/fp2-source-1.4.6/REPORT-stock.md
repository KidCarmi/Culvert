# F-P2 isolated reproduction — attribution summary

| variant | requests | EICAR replies | clean replies | wrong clean (EICAR → bare OK) | with NO earlier fault in its cycle |
|---|---|---|---|---|---|
| stock-control | 80 | {'FOUND': 40} | {'OK': 40} | 0 | 0 |
| stock-edge | 120 | {'OK': 60} | {'OK': 60} | 60 | 60 |
| stock-full | 40 | {'ERROR+OK': 20} | {'ERROR+OK': 20} | 0 | 0 |

## Every wrong clean

| variant | seq | cycle | wire bytes | wire sha256 | dur ms | tmp free before | prior faults in cycle | s since last fault | in flight |
|---|---|---|---|---|---|---|---|---|---|
| stock-edge | 1 | 1 | 142 | `58826c6440278d08…` | 1.59 | 4096 | 0 | None | 0 |
| stock-edge | 3 | 1 | 142 | `05c62ffdccf6e7b6…` | 1.21 | 4096 | 0 | None | 0 |
| stock-edge | 5 | 1 | 142 | `c70f3aa425bf326e…` | 1.2 | 4096 | 0 | None | 0 |
| stock-edge | 7 | 1 | 142 | `140bb8532c4d57b6…` | 1.34 | 4096 | 0 | None | 0 |
| stock-edge | 9 | 1 | 142 | `1616aedc35e942d5…` | 1.13 | 4096 | 0 | None | 0 |
| stock-edge | 11 | 1 | 142 | `b8e0459b24556c0d…` | 1.12 | 4096 | 0 | None | 0 |
| stock-edge | 13 | 1 | 142 | `10f68e577f5e37e2…` | 1.13 | 4096 | 0 | None | 0 |
| stock-edge | 15 | 1 | 142 | `a4c38afed64082e7…` | 1.21 | 4096 | 0 | None | 0 |
| stock-edge | 17 | 1 | 142 | `b32edd037c248d2f…` | 1.12 | 4096 | 0 | None | 0 |
| stock-edge | 19 | 1 | 142 | `957394777db1ac73…` | 1.15 | 4096 | 0 | None | 0 |
| stock-edge | 21 | 2 | 142 | `052368e18dc7d7a6…` | 0.34 | 4096 | 0 | None | 0 |
| stock-edge | 23 | 2 | 142 | `b27fb875a7da831c…` | 1.27 | 4096 | 0 | None | 0 |
| stock-edge | 25 | 2 | 142 | `f3d4aaf70ef36e16…` | 1.11 | 4096 | 0 | None | 0 |
| stock-edge | 27 | 2 | 142 | `8e1cfc28854cbb50…` | 1.15 | 4096 | 0 | None | 0 |
| stock-edge | 29 | 2 | 142 | `75dee24e823f580d…` | 1.1 | 4096 | 0 | None | 0 |
| stock-edge | 31 | 2 | 142 | `a72fe2bc24f90750…` | 1.24 | 4096 | 0 | None | 0 |
| stock-edge | 33 | 2 | 142 | `e576a0448f6d1d50…` | 1.07 | 4096 | 0 | None | 0 |
| stock-edge | 35 | 2 | 142 | `07db9a19c8364962…` | 1.3 | 4096 | 0 | None | 0 |
| stock-edge | 37 | 2 | 142 | `133e0cf3ba3be76f…` | 1.09 | 4096 | 0 | None | 0 |
| stock-edge | 39 | 2 | 142 | `bd4785ca58438f74…` | 1.14 | 4096 | 0 | None | 0 |
| stock-edge | 41 | 3 | 142 | `8da8ea884422be26…` | 0.36 | 4096 | 0 | None | 0 |
| stock-edge | 43 | 3 | 142 | `31010ea572e050f0…` | 1.56 | 4096 | 0 | None | 0 |
| stock-edge | 45 | 3 | 142 | `692011b7c1ef3a2a…` | 1.47 | 4096 | 0 | None | 0 |
| stock-edge | 47 | 3 | 142 | `ac867ecd71b86fdb…` | 1.21 | 4096 | 0 | None | 0 |
| stock-edge | 49 | 3 | 142 | `6afc26f7c19b9cdd…` | 1.27 | 4096 | 0 | None | 0 |
| stock-edge | 51 | 3 | 142 | `5e8f924ac0dfe55d…` | 1.19 | 4096 | 0 | None | 0 |
| stock-edge | 53 | 3 | 142 | `584f6e0ab69e08f6…` | 1.13 | 4096 | 0 | None | 0 |
| stock-edge | 55 | 3 | 142 | `1be8c873da574214…` | 1.45 | 4096 | 0 | None | 0 |
| stock-edge | 57 | 3 | 142 | `41b7a7f75cdf1e4c…` | 1.21 | 4096 | 0 | None | 0 |
| stock-edge | 59 | 3 | 142 | `f16c92fbbe6fd80e…` | 1.22 | 4096 | 0 | None | 0 |
| stock-edge | 61 | 4 | 142 | `d7a7aa2041f8cf0b…` | 0.37 | 4096 | 0 | None | 0 |
| stock-edge | 63 | 4 | 142 | `597afcaa6dc37ed8…` | 1.15 | 4096 | 0 | None | 0 |
| stock-edge | 65 | 4 | 142 | `5376de2a3707a23c…` | 1.14 | 4096 | 0 | None | 0 |
| stock-edge | 67 | 4 | 142 | `0acc25ddf91803bb…` | 1.11 | 4096 | 0 | None | 0 |
| stock-edge | 69 | 4 | 142 | `33d0c3a221213495…` | 1.12 | 4096 | 0 | None | 0 |
| stock-edge | 71 | 4 | 142 | `a7b66904c7ed0d8e…` | 1.16 | 4096 | 0 | None | 0 |
| stock-edge | 73 | 4 | 142 | `fc6d7cabbac05c89…` | 1.16 | 4096 | 0 | None | 0 |
| stock-edge | 75 | 4 | 142 | `ab0f730a20d67f65…` | 1.18 | 4096 | 0 | None | 0 |
| stock-edge | 77 | 4 | 142 | `97f2b510134e59af…` | 1.13 | 4096 | 0 | None | 0 |
| stock-edge | 79 | 4 | 142 | `1882b51f500799af…` | 1.04 | 4096 | 0 | None | 0 |
| stock-edge | 81 | 5 | 142 | `b10b580713eeba80…` | 0.37 | 4096 | 0 | None | 0 |
| stock-edge | 83 | 5 | 142 | `ede714569618f5a5…` | 1.3 | 4096 | 0 | None | 0 |
| stock-edge | 85 | 5 | 142 | `f0cc5fa7b162c045…` | 1.16 | 4096 | 0 | None | 0 |
| stock-edge | 87 | 5 | 142 | `4def2726c064a442…` | 1.19 | 4096 | 0 | None | 0 |
| stock-edge | 89 | 5 | 142 | `ee501631ec760bba…` | 1.28 | 4096 | 0 | None | 0 |
| stock-edge | 91 | 5 | 142 | `5359c892804c0a95…` | 1.27 | 4096 | 0 | None | 0 |
| stock-edge | 93 | 5 | 142 | `a5a345fecc5965ff…` | 1.37 | 4096 | 0 | None | 0 |
| stock-edge | 95 | 5 | 142 | `55188b01b7084537…` | 1.21 | 4096 | 0 | None | 0 |
| stock-edge | 97 | 5 | 142 | `641888bcbff9f782…` | 1.13 | 4096 | 0 | None | 0 |
| stock-edge | 99 | 5 | 142 | `e73cdffc6033b6e4…` | 1.15 | 4096 | 0 | None | 0 |
| stock-edge | 101 | 6 | 142 | `903166d3d4eaabe2…` | 0.35 | 4096 | 0 | None | 0 |
| stock-edge | 103 | 6 | 142 | `6083e442bda6a3f1…` | 1.01 | 4096 | 0 | None | 0 |
| stock-edge | 105 | 6 | 142 | `b58b124ec9ea033a…` | 1.04 | 4096 | 0 | None | 0 |
| stock-edge | 107 | 6 | 142 | `54a1d223bbeeb7f7…` | 1.09 | 4096 | 0 | None | 0 |
| stock-edge | 109 | 6 | 142 | `1c4a958f40da62b7…` | 1.01 | 4096 | 0 | None | 0 |
| stock-edge | 111 | 6 | 142 | `0c75f8fb89781efe…` | 1.12 | 4096 | 0 | None | 0 |
| stock-edge | 113 | 6 | 142 | `a6f91f76c2ba59f1…` | 1.09 | 4096 | 0 | None | 0 |
| stock-edge | 115 | 6 | 142 | `c3039847033b11ca…` | 1.02 | 4096 | 0 | None | 0 |
| stock-edge | 117 | 6 | 142 | `4daa04a8e1ca2314…` | 1.03 | 4096 | 0 | None | 0 |
| stock-edge | 119 | 6 | 142 | `ebcf344ca7ffcd2c…` | 1.15 | 4096 | 0 | None | 0 |

## Fill events

- stock-control cycle 1: headroom target -1, temp free after fill 57311232
- stock-edge cycle 1: headroom target 4096, temp free after fill 4096
- stock-edge cycle 2: headroom target 4096, temp free after fill 4096
- stock-edge cycle 3: headroom target 4096, temp free after fill 4096
- stock-edge cycle 4: headroom target 4096, temp free after fill 4096
- stock-edge cycle 5: headroom target 4096, temp free after fill 4096
- stock-edge cycle 6: headroom target 4096, temp free after fill 4096
- stock-full cycle 1: headroom target 0, temp free after fill 0
- stock-full cycle 2: headroom target 0, temp free after fill 0
