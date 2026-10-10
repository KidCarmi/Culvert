# F-P2 isolated reproduction — attribution summary

| variant | requests | EICAR replies | clean replies | wrong clean (EICAR → bare OK) | with NO earlier fault in its cycle |
|---|---|---|---|---|---|
| patched-control | 80 | {'FOUND': 40} | {'OK': 40} | 0 | 0 |
| patched-edge | 120 | {'ERROR': 60} | {'ERROR': 60} | 0 | 0 |
| patched-full | 40 | {'ERROR+OK': 20} | {'ERROR+OK': 20} | 0 | 0 |

## Every wrong clean

None observed. Absence over these samples is not proof the defect cannot occur.

## Fill events

- patched-control cycle 1: headroom target -1, temp free after fill 57311232
- patched-edge cycle 1: headroom target 4096, temp free after fill 4096
- patched-edge cycle 2: headroom target 4096, temp free after fill 4096
- patched-edge cycle 3: headroom target 4096, temp free after fill 4096
- patched-edge cycle 4: headroom target 4096, temp free after fill 4096
- patched-edge cycle 5: headroom target 4096, temp free after fill 4096
- patched-edge cycle 6: headroom target 4096, temp free after fill 4096
- patched-full cycle 1: headroom target 0, temp free after fill 0
- patched-full cycle 2: headroom target 0, temp free after fill 0
