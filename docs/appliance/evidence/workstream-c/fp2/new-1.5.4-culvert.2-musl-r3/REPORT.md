# F-P2 isolated reproduction — attribution summary

| variant | requests | EICAR replies | clean replies | wrong clean (EICAR → bare OK) | with NO earlier fault in its cycle |
|---|---|---|---|---|---|
| control | 200 | {'FOUND': 100} | {'OK': 100} | 0 | 0 |
| serial-full | 280 | {'ERROR+OK': 140} | {'ERROR+OK': 140} | 0 | 0 |
| serial-sweep | 560 | {'ERROR+OK': 40, 'FOUND': 240} | {'ERROR': 40, 'ERROR+OK': 40, 'OK': 200} | 0 | 0 |
| conc8 | 280 | {'ERROR+OK': 43, 'FOUND': 97} | {'ERROR': 14, 'ERROR+OK': 41, 'OK': 85} | 0 | 0 |
| conc8-full | 280 | {'ERROR+OK': 140} | {'ERROR+OK': 140} | 0 | 0 |

## Every wrong clean

None observed. Absence over these samples is not proof the defect cannot occur.

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
- conc8 cycle 11: headroom target 65536, temp free after fill 65536
- conc8 cycle 12: headroom target 262144, temp free after fill 262144
- conc8 cycle 13: headroom target 1048576, temp free after fill 1048576
- conc8 cycle 14: headroom target 4194304, temp free after fill 4194304
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
