# S33 V1.1 — propagazione del correttivo ISO in CPU emulata

Il 4 novembre 2026 il banco estende la precedente prova del confronto ISO fino all'aritmetica originale `0xD8D7C`. Dopo setter e convertitore originali, il banco entra esplicitamente a `0xD8D0A`; tabella, contesti, frame, registri e ordine sono sintetici. Il servizio `0x1AA2B0` è uno stub che restituisce 40. Il pool e la finestra di istruzioni originali sono confrontati byte per byte con i payload dopo il link.

La soglia **125** e il correttivo **−7** sono scelti dal banco, non letti da una configurazione della fotocamera. Con gli altri ingressi fissati, la somma a 16 bit signed vale 78 quando il correttivo è zero e 71 quando è −7; il risultato successivo `r14` vale rispettivamente 22 e 29. La tabella mostra i sette casi:

| ISO software | Flag tabella | Guardia contesto | Correttivo | Somma | `r14` |
|---:|---:|---:|---:|---:|---:|
| 50 | 1 | 0 | 0 | 78 | 22 |
| 125 | 1 | 0 | 0 | 78 | 22 |
| 140 | 1 | 0 | −7 | 71 | 29 |
| 1600 | 1 | 0 | −7 | 71 | 29 |
| 3200 | 1 | 0 | −7 | 71 | 29 |
| 1600 | 0 | 0 | 0 | 78 | 22 |
| 1600 | 1 | 1 | 0 | 78 | 22 |

Il banco controlla i risultati, la chiamata allo stub e il passaggio sui punti aritmetici originali: [evidenze 7/7](../Risultati/GUI_S33/iso_threshold_slice_cpu_20261104T161110432982Z/verified_evidence.json). Riproduzione: `python3 Python_Trace_Scripts/s33_verify_iso_threshold_arithmetic_cpu.py`. Regressione della prova precedente: [8/8](../Risultati/GUI_S33/iso_threshold_slice_cpu_20261104T161119064312Z/verified_evidence.json).

Questo mostra una dipendenza nell'aritmetica emulata per gli ingressi imposti; non dimostra che il percorso avvenga dopo la selezione nella fotocamera. La chiamata a `0x1AA2B0` è simulata e la prova termina prima della successiva scrittura nel buffer. Tabelle, unità, tempi, AE, guadagno analogico/digitale, ISO base e risultati fotografici restano sconosciuti. Nessun hardware o supporto toccato. **NON_INSTALLARE**.
