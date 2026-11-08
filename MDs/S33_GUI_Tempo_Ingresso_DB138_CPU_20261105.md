# Tempo del menu e ingresso DB138 — 5 novembre 2026

**6/6 CPU emulata PASS; NON_INSTALLARE.** Dopo CaptureMenu → Akeru sintetico → pagina Nikon e conferma, il banco chiama esplicitamente `0xDB138`. Il prologo originale salva registri e crea il frame; il codice originale carica i valori dai contesti sintetici, percorre i rami selezionati dalle fixture e chiama `0xDB33C → 0xD8CA4 → 0xF6F54 → 0xFDA28`. Alla fine del calcolo la fixture a `0xDB340` osserva i locali effettivi (`fp−16=4`, `fp−12=1`), ripristina il frame e usa il millicode originale per recuperare registri e indirizzo di ritorno. Lo stack coincide con quello iniziale. **Non viene eseguita la continuazione originale dopo DB340.**

| Tempo confermato | Limite sintetico | Risultato | Scenario | Cartella `Risultati/GUI_S33/…` |
|---:|---:|---:|---|---|
| 121 | 1000000 | 121000 | guardia occupata | `snapshot_capture_focus_original_cpu_20261105T192643166115Z_220426` |
| 119 | 1000000 | 119000 | discesa | `snapshot_capture_focus_original_cpu_20261105T192643122410Z_220429` |
| 121 | 20000 | 20000 | guardia occupata | `snapshot_capture_focus_original_cpu_20261105T192643167456Z_220427` |
| 119 | 20000 | 20000 | discesa | `snapshot_capture_focus_original_cpu_20261105T192643162377Z_220428` |
| 121 | 1000000 | 121000 | ritorno contestuale libero | `snapshot_capture_focus_original_cpu_20261105T192643166113Z_220432` |
| 121 | 1000000 | 121000 | ritorno con retry iniettato | `snapshot_capture_focus_original_cpu_20261105T192643132773Z_220431` |

ISO software 125 e flag 1 sono sintetici; il risultato è controllato sia dopo il primo calcolo sia nella copia finale. La regressione con ingresso `0xDB1DE` passa in `snapshot_capture_focus_original_cpu_20261105T192643170141Z_220430`. [Verificatore](../Python_Trace_Scripts/s33_verify_snapshot_capture_focus_original_cpu.py), [prova precedente](S33_GUI_Tempo_Chiamante_Contesti_CPU_20261105.md).

## Riferimento statico a DB138

Il letterale V1.1 a `0x14A1A0` contiene `0xDB138`; l'istruzione `0x14A0E6` lo carica in `r2` e `0x14A0FA` chiama `0x14A714`. Il codice di quest'ultima conserva l'argomento e, se la guardia restituisce zero, lo scrive a offset 16 di una struttura. [Verificatore statico](../Python_Trace_Scripts/s33_verify_exposure_caller_registration_static.py), [evidenze](../Risultati/GUI_S33/exposure_caller_registration_static_20261105T192729660430Z/evidence.json). È una relazione statica condizionata, non dimostra registrazione effettiva, esecuzione pianificata o legame con il tasto di scatto.

Il banco impone RAM, MMIO, valori, ordine e chiamata iniziale. Oltre alle fixture precedenti aggiunge servizi per `0x145D1C`, `0x109A30`, `0x12CAD4`, `0xDB0E8`, `0x18C6F4`, `0xDD24C`, `0xDD20C`, `0xAD90C` e `0x109A88`. Il DSP GNU è sperimentale. Primo tentativo non eseguito: errore di assemblaggio `j_s [r10]`, corretto in `j [r10]`; evidenze fallite conservate. Non sono provati la continuazione effettiva, scatto fisico, AE, unità, sensore, concorrenza o persistenza. Nessuna operazione su camera o supporti.
