# F-P2 isolated reproduction — attribution summary

| variant | requests | EICAR replies | clean replies | wrong clean (EICAR → bare OK) | with NO earlier fault in its cycle |
|---|---|---|---|---|---|
| control | 200 | {'FOUND': 100} | {'OK': 100} | 0 | 0 |
| serial-full | 280 | {'ERROR+OK': 140} | {'ERROR+OK': 140} | 0 | 0 |
| serial-sweep | 560 | {'ERROR+OK': 40, 'FOUND': 200, 'OK': 40} | {'ERROR+OK': 40, 'OK': 240} | 40 | 40 |
| conc8 | 280 | {'ERROR+OK': 39, 'FOUND': 78, 'OK': 23} | {'ERROR': 4, 'ERROR+OK': 45, 'OK': 91} | 23 | 6 |
| conc8-full | 280 | {'ERROR+OK': 140} | {'ERROR+OK': 140} | 0 | 0 |

## Every wrong clean

| variant | seq | cycle | wire bytes | wire sha256 | dur ms | tmp free before | prior faults in cycle | s since last fault | in flight |
|---|---|---|---|---|---|---|---|---|---|
| serial-sweep | 21 | 2 | 142 | `cc47991cd99e818d…` | 0.59 | 4096 | 0 | None | 0 |
| serial-sweep | 23 | 2 | 142 | `55c3f56864b8ba60…` | 0.39 | 4096 | 0 | None | 0 |
| serial-sweep | 25 | 2 | 142 | `eba859457a038493…` | 0.4 | 4096 | 0 | None | 0 |
| serial-sweep | 27 | 2 | 142 | `d7cfd6dd7b6481b5…` | 0.45 | 4096 | 0 | None | 0 |
| serial-sweep | 29 | 2 | 142 | `715fa618cd7a632b…` | 0.44 | 4096 | 0 | None | 0 |
| serial-sweep | 31 | 2 | 142 | `30b7f0287c92f8eb…` | 0.43 | 4096 | 0 | None | 0 |
| serial-sweep | 33 | 2 | 142 | `d2144229dff7fa51…` | 0.41 | 4096 | 0 | None | 0 |
| serial-sweep | 35 | 2 | 142 | `fcd2737e51cf1cce…` | 0.36 | 4096 | 0 | None | 0 |
| serial-sweep | 37 | 2 | 142 | `2ed74d9dae69f292…` | 0.38 | 4096 | 0 | None | 0 |
| serial-sweep | 39 | 2 | 142 | `6269ff573f3f6f50…` | 0.42 | 4096 | 0 | None | 0 |
| serial-sweep | 161 | 9 | 142 | `791cc7e75ac0f705…` | 0.53 | 4096 | 0 | None | 0 |
| serial-sweep | 163 | 9 | 142 | `57ab262db0daa499…` | 0.39 | 4096 | 0 | None | 0 |
| serial-sweep | 165 | 9 | 142 | `1d3c972934bc18ec…` | 0.33 | 4096 | 0 | None | 0 |
| serial-sweep | 167 | 9 | 142 | `d8aa2491bb7804ae…` | 0.36 | 4096 | 0 | None | 0 |
| serial-sweep | 169 | 9 | 142 | `965d543de7a0449d…` | 0.41 | 4096 | 0 | None | 0 |
| serial-sweep | 171 | 9 | 142 | `15ef950b94b2e786…` | 0.42 | 4096 | 0 | None | 0 |
| serial-sweep | 173 | 9 | 142 | `03ad6775a5660361…` | 0.37 | 4096 | 0 | None | 0 |
| serial-sweep | 175 | 9 | 142 | `5bf002bc93b477b9…` | 0.35 | 4096 | 0 | None | 0 |
| serial-sweep | 177 | 9 | 142 | `9526078a13670d0f…` | 0.35 | 4096 | 0 | None | 0 |
| serial-sweep | 179 | 9 | 142 | `f2fe58e14302cc5f…` | 0.41 | 4096 | 0 | None | 0 |
| serial-sweep | 301 | 16 | 142 | `466388fc18cc056e…` | 0.46 | 4096 | 0 | None | 0 |
| serial-sweep | 303 | 16 | 142 | `46ac99e05dc24bf7…` | 0.36 | 4096 | 0 | None | 0 |
| serial-sweep | 305 | 16 | 142 | `327e424e5555cf71…` | 0.35 | 4096 | 0 | None | 0 |
| serial-sweep | 307 | 16 | 142 | `2ac1bfc11ca5fbcb…` | 0.33 | 4096 | 0 | None | 0 |
| serial-sweep | 309 | 16 | 142 | `2256e218f2ede653…` | 0.38 | 4096 | 0 | None | 0 |
| serial-sweep | 311 | 16 | 142 | `6d5e77b4398dbcee…` | 0.37 | 4096 | 0 | None | 0 |
| serial-sweep | 313 | 16 | 142 | `c30a160ae1a227ea…` | 0.4 | 4096 | 0 | None | 0 |
| serial-sweep | 315 | 16 | 142 | `23e40cc5f0ea9822…` | 0.42 | 4096 | 0 | None | 0 |
| serial-sweep | 317 | 16 | 142 | `fd2858fd4561f619…` | 0.42 | 4096 | 0 | None | 0 |
| serial-sweep | 319 | 16 | 142 | `147338254c9131b9…` | 0.35 | 4096 | 0 | None | 0 |
| serial-sweep | 441 | 23 | 142 | `dd4898656f4f28a0…` | 0.44 | 4096 | 0 | None | 0 |
| serial-sweep | 443 | 23 | 142 | `e11f116431e2501f…` | 0.39 | 4096 | 0 | None | 0 |
| serial-sweep | 445 | 23 | 142 | `eb02ed02a126c6a5…` | 0.43 | 4096 | 0 | None | 0 |
| serial-sweep | 447 | 23 | 142 | `c4b1e8d5cccb1cb8…` | 0.38 | 4096 | 0 | None | 0 |
| serial-sweep | 449 | 23 | 142 | `9739aa4f6187085b…` | 0.41 | 4096 | 0 | None | 0 |
| serial-sweep | 451 | 23 | 142 | `7c281aa665156253…` | 0.4 | 4096 | 0 | None | 0 |
| serial-sweep | 453 | 23 | 142 | `2ac644af95ec79f2…` | 0.37 | 4096 | 0 | None | 0 |
| serial-sweep | 455 | 23 | 142 | `f6c5e3e59007fbc6…` | 0.38 | 4096 | 0 | None | 0 |
| serial-sweep | 457 | 23 | 142 | `ce9e17020443fa1e…` | 0.43 | 4096 | 0 | None | 0 |
| serial-sweep | 459 | 23 | 142 | `44fe5ff84479377d…` | 0.38 | 4096 | 0 | None | 0 |
| conc8 | 21 | 2 | 142 | `57bf79b947a9c0a6…` | 2.16 | 4096 | 0 | None | 7 |
| conc8 | 25 | 2 | 142 | `f2726ca1e63f464a…` | 1.44 | 0 | 0 | None | 7 |
| conc8 | 27 | 2 | 142 | `eecc0edf4eae124d…` | 1.36 | 4096 | 1 | 0.0 | 6 |
| conc8 | 29 | 2 | 142 | `de1a7bcbb7b583c0…` | 1.03 | 0 | 1 | 0.001 | 5 |
| conc8 | 33 | 2 | 142 | `654fb1fc95b01d87…` | 1.12 | 4096 | 1 | 0.002 | 7 |
| conc8 | 31 | 2 | 142 | `f7e9e1365b418737…` | 1.86 | 4096 | 1 | 0.002 | 11 |
| conc8 | 36 | 2 | 142 | `a0b09d5e075e5ff9…` | 0.99 | 0 | 2 | 0.0 | 6 |
| conc8 | 35 | 2 | 142 | `518d110e02194172…` | 1.55 | 4096 | 1 | 0.003 | 10 |
| conc8 | 38 | 2 | 142 | `74acb262a1a3a567…` | 1.14 | 4096 | 2 | 0.001 | 6 |
| conc8 | 75 | 4 | 142 | `d5d1b33ac24d821c…` | 1.56 | 8192 | 3 | 0.0 | 7 |
| conc8 | 77 | 4 | 142 | `28c28c7a9f61178f…` | 1.58 | 4096 | 3 | 0.002 | 7 |
| conc8 | 79 | 4 | 142 | `84a4835a0f4cbe58…` | 3.12 | 12288 | 4 | 0.0 | 8 |
| conc8 | 163 | 9 | 142 | `e345cb832ce888f4…` | 1.06 | 0 | 0 | None | 5 |
| conc8 | 161 | 9 | 142 | `f93a3f63df8ff14f…` | 1.94 | 4096 | 0 | None | 6 |
| conc8 | 165 | 9 | 142 | `30a650567002691a…` | 1.9 | 0 | 0 | None | 9 |
| conc8 | 167 | 9 | 142 | `f017a87180308508…` | 1.48 | 4096 | 1 | 0.0 | 7 |
| conc8 | 169 | 9 | 142 | `148ac7dafd6f37a4…` | 1.67 | 4096 | 1 | 0.001 | 7 |
| conc8 | 171 | 9 | 142 | `3c0551813b6a15b2…` | 0.76 | 4096 | 1 | 0.002 | 5 |
| conc8 | 173 | 9 | 142 | `faaddd39e7d98350…` | 0.52 | 0 | 1 | 0.003 | 3 |
| conc8 | 174 | 9 | 142 | `1ef75a7cbd7eaff0…` | 1.14 | 0 | 1 | 0.003 | 5 |
| conc8 | 180 | 9 | 142 | `29522e5c131a0001…` | 0.78 | 4096 | 2 | 0.001 | 5 |
| conc8 | 179 | 9 | 142 | `9a135e33efefc6b0…` | 1.01 | 4096 | 2 | 0.002 | 4 |
| conc8 | 211 | 11 | 142 | `bcf94e56e7503372…` | 5.26 | 16384 | 0 | None | 9 |

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
- conc8 cycle 5: headroom target 262144, temp free after fill 262144
- conc8 cycle 6: headroom target 1048576, temp free after fill 1048576
- conc8 cycle 7: headroom target 4194304, temp free after fill 4194304
- conc8 cycle 8: headroom target 0, temp free after fill 0
- conc8 cycle 9: headroom target 4096, temp free after fill 4096
- conc8 cycle 10: headroom target 16384, temp free after fill 16384
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
