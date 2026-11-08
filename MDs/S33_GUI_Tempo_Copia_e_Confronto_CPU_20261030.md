# GUI — copia e confronto del valore del tempo

Il 30 ottobre 2026 ho proseguito la [prova precedente](S33_GUI_Tempo_Calcolo_Chiamata_Successiva_CPU_20261030.md) eseguendo anche `0x18C99C` originale. Questa funzione, quando il secondo argomento non è nullo, scrive il primo come word all'indirizzo indicato. Nel percorso eseguito viene chiamata due volte: copia il tempo trasformato e un secondo valore sintetico in due celle locali; il codice originale confronta le due word e scrive un risultato 0/1. Una fixture a `0xFDFA6` legge le celle e interrompe la prova dopo il confronto.

| Tempo trasformato nella cella | Seconda word | Risultato del confronto |
|---:|---:|---:|
| 42.000 | 1 | 1 |
| 84.000 | 1 | 1 |
| 20.000 | 1 | 1 |
| 44.941 | 1 | 1 |
| 42.000 | 42.000 | 0 |
| 42.000 | 50.000 | 0 |

I primi quattro casi ripetono le variazioni singole di tempo, limite e campo `+0x0E` rispetto al banco base; gli ultimi due cambiano solo la seconda word sintetica per verificare uguaglianza e ordine inverso. In ciascun caso la traccia verifica due scritture dell'originale `0x18C99C`, oltre ai passaggi `0xFDA28 → 0xFDE08 → 0xFDF82`. Il confronto è osservato solo per questi valori non negativi; non attribuiamo alle due word un significato fisico preciso né al risultato un'azione di scatto.

Restano fixture la copia byte a `0x128C20`, la callback indiretta, `0x18C634` e il registratore a `0xFDFA6`. Contesto, seconda word, soglia e tabella sono sintetici; simulatore DSP sperimentale. I setter, la copia del contesto, la trasformazione e le due chiamate a `0x18C99C` sono codice originale. Il banco verifica che i valori correnti siano stati cambiati dopo lo snapshot e che il valore osservato provenga dal percorso della copia.

[Verificatore](../Python_Trace_Scripts/s33_probe_gui_exposure_store_compare_cpu.py), casi 0–5: [0](../Risultati/GUI_S33/exposure_calc_store_compare_probe_0_20261030T101803Z/verified_evidence.json), [1](../Risultati/GUI_S33/exposure_calc_store_compare_probe_1_20261030T101803Z/verified_evidence.json), [2](../Risultati/GUI_S33/exposure_calc_store_compare_probe_2_20261030T101803Z/verified_evidence.json), [3](../Risultati/GUI_S33/exposure_calc_store_compare_probe_3_20261030T101803Z/verified_evidence.json), [uguaglianza](../Risultati/GUI_S33/exposure_calc_store_compare_probe_4_20261030T101803Z/verified_evidence.json), [ordine inverso](../Risultati/GUI_S33/exposure_calc_store_compare_probe_5_20261030T101803Z/verified_evidence.json).

Il percorso successivo al confronto, le condizioni reali della tabella, AE, unità fisiche, GUI, tasti e scatto non sono provati. Firmware e fotocamera invariati; **NON_INSTALLARE**.
