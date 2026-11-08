# Menu tempo, registrazione e CapMgrTask — 6 novembre 2026

**6/6 CPU emulata PASS; NON_INSTALLARE.** Dopo la conferma del tempo nel percorso CaptureMenu → Akeru sintetico → pagina Nikon, il banco entra nel frammento originale `0x14A0E4`. Il codice carica `0xDB138` dal letterale originale e chiama `0x14A714`; con guardia sintetica libera, quest'ultima lo registra nel contesto `0x366FA0+0x10`. Il banco verifica il puntatore memorizzato, impone lo stato 5 a `+0x2C` e chiama l'entry originale di **CapMgrTask** `0x14A4C4`.

La traccia verifica l'attesa modellata, la lettura dello stato e il salto tramite la tabella originale `0x14A522`: stato 5 → `0x14A586`. Il task legge il puntatore registrato e lo chiama indirettamente a `0x14A590 → 0xDB138`; il prologo originale e `0xDB33C → 0xD8CA4 → 0xF6F54 → 0xFDA28` seguono nel medesimo processo emulato. Il banco controlla valore, ISO, flag, stato 5, risultato del ramo e ripristino dello stack.

| Tempo confermato | Limite sintetico | Risultato software | Caso | Cartella `Risultati/GUI_S33/…` |
|---:|---:|---:|---|---|
| 121 | 1000000 | 121000 | guardia occupata | `snapshot_capture_focus_original_cpu_20261106T090036374423Z_245190` |
| 119 | 1000000 | 119000 | discesa | `snapshot_capture_focus_original_cpu_20261106T090036332656Z_245191` |
| 121 | 20000 | 20000 | limite | `snapshot_capture_focus_original_cpu_20261106T090036385490Z_245194` |
| 119 | 20000 | 20000 | discesa e limite | `snapshot_capture_focus_original_cpu_20261106T090036337453Z_245193` |
| 121 | 1000000 | 121000 | ritorno contestuale libero | `snapshot_capture_focus_original_cpu_20261106T090036374423Z_245192` |
| 121 | 1000000 | 121000 | ritorno con retry iniettato | `snapshot_capture_focus_original_cpu_20261106T090036385490Z_245195` |

ISO 125 e flag 1 sono sintetici. Regressioni PASS: ingresso diretto nel ramo del task `snapshot_capture_focus_original_cpu_20261106T090036391572Z_245196`; ingresso diretto `DB138` `snapshot_capture_focus_original_cpu_20261106T090036393096Z_245197`. [Verificatore](../Python_Trace_Scripts/s33_verify_snapshot_capture_focus_original_cpu.py); [precedente ingresso DB138](S33_GUI_Tempo_Ingresso_DB138_CPU_20261105.md); [analisi preesistente del task](S33_Ingresso_Acquisizione.md).

Il banco impone l'ordine delle operazioni, richiama direttamente il frammento di registrazione e poi il task, imposta stato 5 e usa fixture per sincronizzazione, invio/attesa eventi e numerosi servizi. Il ritorno del calcolo e quello del task sono intercettati a `0xDB340` e `0x14A594`: non si eseguono le continuazioni originali né la notifica finale. Il valore ritornato dal ramo deriva dal percorso interrotto e non caratterizza il ritorno della funzione completa. RAM, MMIO e DSP sono modellati/sperimentali; non sono stabiliti scatto fisico, schedulazione concorrente, persistenza, AE, unità o sensore. Nessun hardware o supporto modificato.

Il primo test del task è stato rifiutato dall'assert sulla posizione del frame: mancava la dimensione di 20 byte del prologo del task. Dopo correzione l'intera matrice è stata ripetuta; la cartella fallita resta tra le evidenze e non viene conteggiata.
