# F-P2 isolated reproduction — attribution summary

| variant | requests | EICAR replies | clean replies | wrong clean (EICAR → bare OK) | with NO earlier fault in its cycle |
|---|---|---|---|---|---|
| control | 200 | {'FOUND': 100} | {'OK': 100} | 0 | 0 |
| serial-full | 280 | {'ERROR+OK': 140} | {'ERROR+OK': 140} | 0 | 0 |
| serial-sweep | 560 | {'ERROR+OK': 40, 'FOUND': 200, 'OK': 40} | {'ERROR+OK': 40, 'OK': 240} | 40 | 40 |
| conc8 | 280 | {'ERROR+OK': 49, 'FOUND': 75, 'OK': 16} | {'ERROR': 4, 'ERROR+OK': 42, 'OK': 94} | 16 | 10 |
| conc8-full | 280 | {'ERROR+OK': 140} | {'ERROR+OK': 140} | 0 | 0 |

## Every wrong clean

| variant | seq | cycle | wire bytes | wire sha256 | dur ms | tmp free before | prior faults in cycle | s since last fault | in flight |
|---|---|---|---|---|---|---|---|---|---|
| serial-sweep | 21 | 2 | 142 | `cc47991cd99e818d…` | 0.67 | 4096 | 0 | None | 0 |
| serial-sweep | 23 | 2 | 142 | `55c3f56864b8ba60…` | 0.6 | 4096 | 0 | None | 0 |
| serial-sweep | 25 | 2 | 142 | `eba859457a038493…` | 0.62 | 4096 | 0 | None | 0 |
| serial-sweep | 27 | 2 | 142 | `d7cfd6dd7b6481b5…` | 0.58 | 4096 | 0 | None | 0 |
| serial-sweep | 29 | 2 | 142 | `715fa618cd7a632b…` | 0.63 | 4096 | 0 | None | 0 |
| serial-sweep | 31 | 2 | 142 | `30b7f0287c92f8eb…` | 0.61 | 4096 | 0 | None | 0 |
| serial-sweep | 33 | 2 | 142 | `d2144229dff7fa51…` | 0.58 | 4096 | 0 | None | 0 |
| serial-sweep | 35 | 2 | 142 | `fcd2737e51cf1cce…` | 0.63 | 4096 | 0 | None | 0 |
| serial-sweep | 37 | 2 | 142 | `2ed74d9dae69f292…` | 0.59 | 4096 | 0 | None | 0 |
| serial-sweep | 39 | 2 | 142 | `6269ff573f3f6f50…` | 0.62 | 4096 | 0 | None | 0 |
| serial-sweep | 161 | 9 | 142 | `791cc7e75ac0f705…` | 0.67 | 4096 | 0 | None | 0 |
| serial-sweep | 163 | 9 | 142 | `57ab262db0daa499…` | 0.65 | 4096 | 0 | None | 0 |
| serial-sweep | 165 | 9 | 142 | `1d3c972934bc18ec…` | 0.6 | 4096 | 0 | None | 0 |
| serial-sweep | 167 | 9 | 142 | `d8aa2491bb7804ae…` | 0.62 | 4096 | 0 | None | 0 |
| serial-sweep | 169 | 9 | 142 | `965d543de7a0449d…` | 0.57 | 4096 | 0 | None | 0 |
| serial-sweep | 171 | 9 | 142 | `15ef950b94b2e786…` | 0.61 | 4096 | 0 | None | 0 |
| serial-sweep | 173 | 9 | 142 | `03ad6775a5660361…` | 0.64 | 4096 | 0 | None | 0 |
| serial-sweep | 175 | 9 | 142 | `5bf002bc93b477b9…` | 0.62 | 4096 | 0 | None | 0 |
| serial-sweep | 177 | 9 | 142 | `9526078a13670d0f…` | 0.65 | 4096 | 0 | None | 0 |
| serial-sweep | 179 | 9 | 142 | `f2fe58e14302cc5f…` | 0.59 | 4096 | 0 | None | 0 |
| serial-sweep | 301 | 16 | 142 | `466388fc18cc056e…` | 0.69 | 4096 | 0 | None | 0 |
| serial-sweep | 303 | 16 | 142 | `46ac99e05dc24bf7…` | 0.64 | 4096 | 0 | None | 0 |
| serial-sweep | 305 | 16 | 142 | `327e424e5555cf71…` | 0.59 | 4096 | 0 | None | 0 |
| serial-sweep | 307 | 16 | 142 | `2ac1bfc11ca5fbcb…` | 0.62 | 4096 | 0 | None | 0 |
| serial-sweep | 309 | 16 | 142 | `2256e218f2ede653…` | 0.58 | 4096 | 0 | None | 0 |
| serial-sweep | 311 | 16 | 142 | `6d5e77b4398dbcee…` | 0.63 | 4096 | 0 | None | 0 |
| serial-sweep | 313 | 16 | 142 | `c30a160ae1a227ea…` | 0.64 | 4096 | 0 | None | 0 |
| serial-sweep | 315 | 16 | 142 | `23e40cc5f0ea9822…` | 0.61 | 4096 | 0 | None | 0 |
| serial-sweep | 317 | 16 | 142 | `fd2858fd4561f619…` | 0.65 | 4096 | 0 | None | 0 |
| serial-sweep | 319 | 16 | 142 | `147338254c9131b9…` | 0.59 | 4096 | 0 | None | 0 |
| serial-sweep | 441 | 23 | 142 | `dd4898656f4f28a0…` | 0.74 | 4096 | 0 | None | 0 |
| serial-sweep | 443 | 23 | 142 | `e11f116431e2501f…` | 0.63 | 4096 | 0 | None | 0 |
| serial-sweep | 445 | 23 | 142 | `eb02ed02a126c6a5…` | 0.62 | 4096 | 0 | None | 0 |
| serial-sweep | 447 | 23 | 142 | `c4b1e8d5cccb1cb8…` | 0.67 | 4096 | 0 | None | 0 |
| serial-sweep | 449 | 23 | 142 | `9739aa4f6187085b…` | 0.59 | 4096 | 0 | None | 0 |
| serial-sweep | 451 | 23 | 142 | `7c281aa665156253…` | 0.6 | 4096 | 0 | None | 0 |
| serial-sweep | 453 | 23 | 142 | `2ac644af95ec79f2…` | 0.64 | 4096 | 0 | None | 0 |
| serial-sweep | 455 | 23 | 142 | `f6c5e3e59007fbc6…` | 0.59 | 4096 | 0 | None | 0 |
| serial-sweep | 457 | 23 | 142 | `ce9e17020443fa1e…` | 0.58 | 4096 | 0 | None | 0 |
| serial-sweep | 459 | 23 | 142 | `44fe5ff84479377d…` | 0.64 | 4096 | 0 | None | 0 |
| conc8 | 21 | 2 | 142 | `57bf79b947a9c0a6…` | 1.79 | 4096 | 0 | None | 4 |
| conc8 | 25 | 2 | 142 | `f2726ca1e63f464a…` | 4.17 | 4096 | 1 | 0.0 | 11 |
| conc8 | 27 | 2 | 142 | `eecc0edf4eae124d…` | 3.24 | 4096 | 1 | 0.001 | 12 |
| conc8 | 31 | 2 | 142 | `f7e9e1365b418737…` | 2.69 | 4096 | 2 | 0.0 | 11 |
| conc8 | 59 | 3 | 142 | `c76a2262179f1bfb…` | 5.52 | 0 | 12 | 0.0 | 6 |
| conc8 | 71 | 4 | 142 | `f8f6287d4dba00b6…` | 4.08 | 4096 | 0 | None | 7 |
| conc8 | 181 | 10 | 142 | `017db339826cd739…` | 2.3 | 12288 | 0 | None | 6 |
| conc8 | 183 | 10 | 142 | `eb068cc9fe1a1311…` | 2.33 | 12288 | 0 | None | 6 |
| conc8 | 187 | 10 | 142 | `e68268d7e0e97aa7…` | 2.88 | 4096 | 0 | None | 10 |
| conc8 | 193 | 10 | 142 | `185589d89a397162…` | 1.91 | 0 | 2 | 0.0 | 11 |
| conc8 | 197 | 10 | 142 | `de0fa201facef6b2…` | 4.35 | 0 | 5 | 0.0 | 9 |
| conc8 | 207 | 11 | 142 | `a1e90f9642398691…` | 5.31 | 45056 | 0 | None | 7 |
| conc8 | 209 | 11 | 142 | `5c20e36bda3253cc…` | 1.57 | 4096 | 0 | None | 7 |
| conc8 | 211 | 11 | 142 | `bcf94e56e7503372…` | 2.02 | 4096 | 0 | None | 7 |
| conc8 | 215 | 11 | 142 | `23ea2140e81d6cf1…` | 10.83 | 16384 | 0 | None | 8 |
| conc8 | 217 | 11 | 142 | `fed6c50de600d708…` | 4.47 | 8192 | 0 | None | 8 |

## Fill events

- control cycle 1: headroom target -1, temp free after fill 229203968
- control cycle 2: headroom target -1, temp free after fill 229203968
- serial-full cycle 1: headroom target 0, temp free after fill 0
- serial-full cycle 2: headroom target 0, temp free after fill 0
- serial-full cycle 3: headroom target 0, temp free after fill 0
- serial-full cycle 4: headroom target 0, temp free after fill 0
- serial-full cycle 5: headroom target 0, temp free after fill 0
- serial-full cycle 6: headroom target 0, temp free after fill 0
- serial-full cycle 7: headroom target 0, temp free after fill 0
- serial-full cycle 8: headroom target 0, temp free after fill 0
- serial-full cycle 9: headroom target 0, temp free after fill 0
- serial-full cycle 10: headroom target 0, temp free after fill 0
- serial-full cycle 11: headroom target 0, temp free after fill 0
- serial-full cycle 12: headroom target 0, temp free after fill 0
- serial-full cycle 13: headroom target 0, temp free after fill 0
- serial-full cycle 14: headroom target 0, temp free after fill 0
- serial-sweep cycle 1: headroom target 0, temp free after fill 0
- serial-sweep cycle 2: headroom target 4096, temp free after fill 4096
- serial-sweep cycle 3: headroom target 16384, temp free after fill 16384
- serial-sweep cycle 4: headroom target 65536, temp free after fill 65536
- serial-sweep cycle 5: headroom target 262144, temp free after fill 262144
- serial-sweep cycle 6: headroom target 1048576, temp free after fill 1048576
- serial-sweep cycle 7: headroom target 4194304, temp free after fill 4194304
- serial-sweep cycle 8: headroom target 0, temp free after fill 0
- serial-sweep cycle 9: headroom target 4096, temp free after fill 4096
- serial-sweep cycle 10: headroom target 16384, temp free after fill 16384
- serial-sweep cycle 11: headroom target 65536, temp free after fill 65536
- serial-sweep cycle 12: headroom target 262144, temp free after fill 262144
- serial-sweep cycle 13: headroom target 1048576, temp free after fill 1048576
- serial-sweep cycle 14: headroom target 4194304, temp free after fill 4194304
- serial-sweep cycle 15: headroom target 0, temp free after fill 0
- serial-sweep cycle 16: headroom target 4096, temp free after fill 4096
- serial-sweep cycle 17: headroom target 16384, temp free after fill 16384
- serial-sweep cycle 18: headroom target 65536, temp free after fill 65536
- serial-sweep cycle 19: headroom target 262144, temp free after fill 262144
- serial-sweep cycle 20: headroom target 1048576, temp free after fill 1048576
- serial-sweep cycle 21: headroom target 4194304, temp free after fill 4194304
- serial-sweep cycle 22: headroom target 0, temp free after fill 0
- serial-sweep cycle 23: headroom target 4096, temp free after fill 4096
- serial-sweep cycle 24: headroom target 16384, temp free after fill 16384
- serial-sweep cycle 25: headroom target 65536, temp free after fill 65536
- serial-sweep cycle 26: headroom target 262144, temp free after fill 262144
- serial-sweep cycle 27: headroom target 1048576, temp free after fill 1048576
- serial-sweep cycle 28: headroom target 4194304, temp free after fill 4194304
- conc8 cycle 1: headroom target 0, temp free after fill 0
- conc8 cycle 2: headroom target 4096, temp free after fill 4096
- conc8 cycle 3: headroom target 16384, temp free after fill 16384
- conc8 cycle 4: headroom target 65536, temp free after fill 65536
- conc8 cycle 5: headroom target 262144, temp free after fill 258048
- conc8 cycle 6: headroom target 1048576, temp free after fill 1044480
- conc8 cycle 7: headroom target 4194304, temp free after fill 4190208
- conc8 cycle 8: headroom target 0, temp free after fill 0
- conc8 cycle 9: headroom target 4096, temp free after fill 0
- conc8 cycle 10: headroom target 16384, temp free after fill 12288
- conc8 cycle 11: headroom target 65536, temp free after fill 61440
- conc8 cycle 12: headroom target 262144, temp free after fill 258048
- conc8 cycle 13: headroom target 1048576, temp free after fill 1044480
- conc8 cycle 14: headroom target 4194304, temp free after fill 4190208
- conc8-full cycle 1: headroom target 0, temp free after fill 0
- conc8-full cycle 2: headroom target 0, temp free after fill 0
- conc8-full cycle 3: headroom target 0, temp free after fill 0
- conc8-full cycle 4: headroom target 0, temp free after fill 0
- conc8-full cycle 5: headroom target 0, temp free after fill 0
- conc8-full cycle 6: headroom target 0, temp free after fill 0
- conc8-full cycle 7: headroom target 0, temp free after fill 0
- conc8-full cycle 8: headroom target 0, temp free after fill 0
- conc8-full cycle 9: headroom target 0, temp free after fill 0
- conc8-full cycle 10: headroom target 0, temp free after fill 0
- conc8-full cycle 11: headroom target 0, temp free after fill 0
- conc8-full cycle 12: headroom target 0, temp free after fill 0
- conc8-full cycle 13: headroom target 0, temp free after fill 0
- conc8-full cycle 14: headroom target 0, temp free after fill 0
