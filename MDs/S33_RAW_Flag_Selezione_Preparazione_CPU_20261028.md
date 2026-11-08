# S33 V1.1 — flag RAW e selezione della preparazione

28 ottobre 2026. Quattro casi GNU ARC700 con DSP sperimentale eseguono il frammento originale `0x1BAA28` e, quando selezionato, il preparatore originale `0x17D62C`. **NON_INSTALLARE**.

| Flag RAW | Selettore | Percorso osservato |
|---:|---:|---|
| 0 | 3 | `0x17D458` sostituito dalla fixture |
| 1 | 3 | `0x17D62C` originale |
| 1 | 0 | `0x17D458` sostituito dalla fixture |
| 2 | 3 | `0x17D458` sostituito dalla fixture |

Nel caso 1/3 il helper originale scrive la word `0x3000` nella struttura sintetica e copia nei campi `+588` e `+590` valori forniti dalla fixture che sostituisce `0xDF47C`. Non sono stati attribuiti a questi campi un significato fisico, un formato sensore o una garanzia di capacità. L'altro helper `0x17D458` non è eseguito: una fixture ne registra la scelta. Il banco entra direttamente nel frammento, con frame e flag sintetici, e si arresta prima della continuazione; non dimostra che lo scatto reale raggiunga il ramo.

Il risultato mostra che il valore **2 non equivale a 1**, anche se entrambi sono nonzero per il writer: in questo sito il confronto esatto a 1 cambia la preparazione. Perciò usare 2 allo scopo di saltare il marcatore non costituisce una correzione dimostrata. Nel candidato forzato il getter restituisce invece 1 e il selettore 3, qualunque siano i valori RAM; il banco qui esegue i getter originali, non il candidato. Il [censimento statico](S33_RAW_Consumer_Flag_Censimento_Statico_20261028.md) descrive altri siti con condizioni analoghe, non eseguiti qui.

Riproduzione: `python3 Python_Trace_Scripts/s33_verify_raw_prepare_selection_cpu.py`. [Casi](../Risultati/HiddenMenu_RAW/prepare_selection_cpu_20261028T145305Z/cases.json), [fixture](../Risultati/HiddenMenu_RAW/prepare_selection_cpu_20261028T145305Z/fixture_patches.json), [script](../Python_Trace_Scripts/s33_verify_raw_prepare_selection_cpu.py). I byte dei frammenti sono confrontati al dump e la traccia controlla gli ingressi; nessun dato immagine, scatto, file o hardware è eseguito. La prima invocazione non ha avviato il banco per un errore di sintassi, corretto nel verificatore.
