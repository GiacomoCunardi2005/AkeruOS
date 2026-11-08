# Tempo del menu e contesti del chiamante — 5 novembre 2026

**6/6 CPU emulata PASS; NON_INSTALLARE.** Dopo CaptureMenu → Akeru sintetico → pagina del tempo → conferma, il banco entra in `0xDB1DE` con frame sintetico. Il codice originale legge il byte da `0x37FD76` e la halfword da `0x380A28`, scrive `fp−12` e `fp−16` e, attraverso il percorso selezionato da fixture, prosegue fino alla chiamata originale `0xDB33C → 0xD8CA4 → 0xF6F54 → 0xFDA28`. All'inizio i locali hanno sentinelle diverse; nel test si controllano i valori finali 1 e 4 e le letture nelle tracce. I contesti sono inizializzati dal banco: non ne è dimostrata l'origine reale.

| Tempo confermato | Limite sintetico | Risultato software | Condizione | Cartella `Risultati/GUI_S33/…` |
|---:|---:|---:|---|---|
| 121 | 1000000 | 121000 | guardia occupata | `snapshot_capture_focus_original_cpu_20261105T192443130916Z_216725` |
| 119 | 1000000 | 119000 | discesa | `snapshot_capture_focus_original_cpu_20261105T192443131128Z_216726` |
| 121 | 20000 | 20000 | guardia occupata | `snapshot_capture_focus_original_cpu_20261105T192443131491Z_216727` |
| 119 | 20000 | 20000 | discesa | `snapshot_capture_focus_original_cpu_20261105T192443090956Z_216728` |
| 121 | 1000000 | 121000 | ritorno contestuale libero | `snapshot_capture_focus_original_cpu_20261105T192443141126Z_216731` |
| 121 | 1000000 | 121000 | ritorno con retry iniettato | `snapshot_capture_focus_original_cpu_20261105T192443140840Z_216729` |

ISO sintetico 125, flag 1, risultato e copia finale sono controllati come nel [banco precedente](S33_GUI_Tempo_Chiamante_DB33C_CPU_20261105.md); lo stack è conservato. La regressione con ingresso a `0xDB31C` passa in `snapshot_capture_focus_original_cpu_20261105T192443091370Z_216730`. [Verificatore](../Python_Trace_Scripts/s33_verify_snapshot_capture_focus_original_cpu.py). La precedente verifica REA dei byte del sito chiamante è nel rapporto collegato.

Il frame è costruito dal banco; sono fixture `0xDEF20`, `0xE1284`, `0x11A0F8`, `0xE12C4`, `0x17866C`, `0x1785FC`, `0x149548`, `0xDB088`, `0xE3FF0` e il ritorno a `0xDB340`, oltre a copia byte, dispatch e registratore/ramo del calcolo già descritti. Le fixture che restituiscono 1 selezionano i rami osservati. Non si entra dal prologo `0xDB138`; né il percorso da un tasto reale né AE, unità fisiche, concorrenza o sensore sono dimostrati. DSP GNU sperimentale, RAM e MMIO modellati. Nessuna prova hardware o scrittura su dispositivi.

Una prima matrice intermedia è stata rifiutata dall'assert sulle tracce: il formato del simulatore scrive `cr16` per la seconda lettura, non `cr`. L'assert è stato corretto e la matrice intera ripetuta; le cartelle fallite sono conservate e non conteggiate come PASS.
