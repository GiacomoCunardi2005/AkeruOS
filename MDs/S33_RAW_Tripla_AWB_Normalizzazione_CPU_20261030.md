# S33 — esplorazione del ramo della tripla con valore centrale diverso da 128

Il 30 ottobre 2026 il banco GNU ARC ha eseguito la funzione originale `0x10BF64`, sostituendo in copie da laboratorio il fornitore a `0xFBE68` con due coefficienti scelti e il setter `0xE5408` con un registratore. Questi coefficienti non sono misure della fotocamera. I risultati numerici sono esplorativi: manca un oracolo indipendente per la formula.

| Tripla in ingresso | Coefficienti sintetici | Tripla al setter |
|---|---|---|
| 100, 64, 200 | 1, 1 | 3, 128, 6 |
| 100, 256, 200 | 1, 1 | 3, 128, 6 |
| 100, 64, 200 | 2, 1 | 6, 128, 6 |
| 100, 64, 200 | 1, 0,5 | 3, 128, 3 |
| 162, 127, 113 | 1, 1 | 5, 128, 4 |
| 255, 256, 100 | 1, 1 | 8, 128, 3 |
| 128, 128, 128 | 1, 1 | 128, 128, 128 |

Nei casi provati il valore centrale diverso da 128 è sostituito da 128; variando separatamente i coefficienti sintetici variano separatamente i valori esterni. Con centrale 128, il fornitore non viene chiamato e la tripla è inoltrata invariata. Non è dimostrato che la stessa tripla sia stata scritta nel file durante lo scatto, né il significato dei canali o la scala reale.

Evidenze: `Risultati/Mono_RAW/cfa_awb_normalize_cpu_20261030T162739Z/`, script `Python_Trace_Scripts/s33_verify_cfa_awb_triplet_caller_cpu.py`. Controllo precedente con centrale 128: 3 casi PASS in `Risultati/Mono_RAW/cfa_awb_caller_cpu_20261030T162739Z/`. ISO, tempo e diaframma non sono stati identificati. Nessuna modifica alla fotocamera o agli originali.
