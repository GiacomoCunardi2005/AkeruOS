# ISO software: confronto e scrittura nel consumatore — 5 novembre 2026

Nel campione V1.1 il banco GNU ARC700 estende la [prova aritmetica](S33_GUI_ISO_Correzione_Aritmetica_CPU_20261104.md): esegue setter e convertitore ISO originali, poi **chiama esplicitamente** il frammento `0xD8D0A..0xD8DE6` e la funzione originale `0x18C90C..0x18C958`. I servizi intermedi sono stub; i byte originali delle finestre vengono confrontati dopo il link. Il banco interrompe il chiamante subito dopo il ritorno da `0x18C90C`.

Il banco impone soglia ISO software 125, correttivo signed −7, ingressi aritmetici fissi e una word di lavoro `r17=4075`: valori **sintetici**, scelti per attraversare il confronto originale `r2 >= 4000` in `0x18C92E`. Non rappresentano una soglia ISO o un'unità fotografica misurata.

| ISO software / condizione | Somma scritta nel frame | `r14`, passato come `r2` | Halfword iniziale → finale |
|---|---:|---:|---:|
| 125, tabella abilitata, guardia 0 | 78 | 3997 | 8 → 8 |
| 140 o 1600, tabella abilitata, guardia 0 | 71 | 4004 | 8 → 42 |
| 1600, tabella disabilitata oppure guardia 1 | 78 | 3997 | 8 → 8 |

Con ISO software 1600 e correttivo attivo, il banco varia separatamente gli altri ingressi della funzione originale: il byte passato in `r1=1` lascia 8; con `r1=21`, flag `r3=1` scrive 19, `r3=4` scrive 42 e `r3=0` lascia 8. Tutti gli altri ingressi della riga corrispondente restano fissi. I valori 8, 19 e 42 sono codici software: il loro significato fisico non è stabilito. Sono verificati la halfword a `fp−4`, la word a `fp−328`, il risultato `r14`, ISO convertito, numero di chiamate e punti di traccia. **9/9 casi PASS**: [evidenze e finestre](../Risultati/GUI_S33/iso_threshold_apply_cpu_20261105T102705346343Z/verified_evidence.json). Regressione del precedente banco aritmetico [7/7](../Risultati/GUI_S33/iso_threshold_slice_cpu_20261105T102711090141Z/verified_evidence.json).

Una [prova intermedia](../Risultati/GUI_S33/iso_threshold_call_cpu_20261105T102608119335Z/verified_evidence.json) ha verificato la chiamata con destinatario intercettato; la prova principale esegue invece `0x18C90C` originale. La prima matrice del banco esteso è stata correttamente marcata FAIL perché il controllo di traccia richiedeva il confronto `0x18C92E` anche quando `r1=1` causa un'uscita precedente; il controllo è stato corretto per riflettere i due rami e la matrice è stata rieseguita interamente.

Riproduzione: `python3 Python_Trace_Scripts/s33_verify_iso_threshold_consumer_cpu.py`. Snapshot dei sorgenti nella cartella evidenze: [scenario](../Risultati/GUI_S33/iso_threshold_apply_cpu_20261105T102705346343Z/verifier_snapshot.py), [banco condiviso](../Risultati/GUI_S33/iso_threshold_apply_cpu_20261105T102705346343Z/fanout_snapshot.py).

Questo prova una propagazione **condizionata in RAM emulata**, non che la GUI attivi quella sequenza in camera. Tabella, soglia, stato, frame, sequenza e servizi restano fixture: fra questi `0x1AA2B0` restituisce 40, `0xE0F94/0xE0FB8` restituiscono zero e `0x18C634` restituisce 36. Non sono accertati identità o durata della struttura reale, il seguito del chiamante, AE, tempi, guadagno o sensore. Non sono state eseguite operazioni su fotocamera o supporti. **NON_INSTALLARE**.
