# Tempo dal menu Akeru al calcolo — 5 novembre 2026

**Esito: 6/6 CPU emulata PASS; NON_INSTALLARE.** Il verificatore integrato percorre CaptureMenu → Akeru sintetico → pagina Nikon del tempo, scanner e dispatcher, modifica e conferma. Dopo la copia di stato descritta in [Tempo e snapshot](S33_GUI_Tempo_Menu_Snapshot_CPU_20261105.md), il banco inizializza il contesto sintetico e chiama esplicitamente il chiamante originale `0xD8CA4`. La traccia attraversa `0xF6F54` e una chiamata a `0xFDA28`; un registratore osserva il primo risultato a `0xD8E22`, e il banco confronta tempo, ISO e flag anche nella copia finale a `0x380844`.

| Tempo mostrato confermato | Limite sintetico | Risultato software | Scenario | Cartella evidenze `Risultati/GUI_S33/…` |
|---:|---:|---:|---|---|
| 121 | 1000000 | 121000 | guardia occupata | `snapshot_capture_focus_original_cpu_20261105T191807166733Z_207487` |
| 121 | 20000 | 20000 | guardia occupata | `snapshot_capture_focus_original_cpu_20261105T191828761938Z_207970` |
| 119 | 1000000 | 119000 | discesa | `snapshot_capture_focus_original_cpu_20261105T191828761939Z_207971` |
| 119 | 20000 | 20000 | discesa | `snapshot_capture_focus_original_cpu_20261105T191828763125Z_207969` |
| 121 | 1000000 | 121000 | ritorno contestuale libero | `snapshot_capture_focus_original_cpu_20261105T191828762689Z_207972` |
| 121 | 1000000 | 121000 | ritorno con retry iniettato | `snapshot_capture_focus_original_cpu_20261105T191828724467Z_207973` |

In tutti i casi l'ISO è 125 e il flag 1, imposti dal contesto sintetico; lo stack è preservato. Le regressioni snapshot normale e zero passano rispettivamente nelle cartelle `snapshot_capture_focus_original_cpu_20261105T191828774868Z_207975` e `snapshot_capture_focus_original_cpu_20261105T191828773353Z_207974`. [Verificatore](../Python_Trace_Scripts/s33_verify_snapshot_capture_focus_original_cpu.py); [prova precedente del calcolo con callback diagnosticamente iniettato](S33_GUI_Conferme_ISO_Tempo_Calcolo_CPU_20261030.md).

Il banco impone sequenza, contesto, ISO, limiti, guardie e chiamata di calcolo; usa RAM e MMIO modellati, callback/dispatch/copia byte fixture e DSP GNU sperimentale. Il registratore sostituisce il confronto/ramo a `0xD8E22` e riproduce il ramo scelto; il ritorno contestuale usa un reindirizzamento di laboratorio. La copia finale usa una routine fixture. Non è dimostrato che il vero scatto chiami il percorso in questo stato, né che zero significhi AE funzionante, né l'unità fisica o il comportamento del sensore. Non sono verificate concorrenza, persistenza o sovrascritture successive. Nessuna prova hardware o scrittura su dispositivi.

REA ARC/Ghidra ha letto cinque finestre di 64 byte a `0xD8CA4`, `0xD8E22`, `0xF6F54`, `0xFDA28` e `0x128C20`, tutte coincidenti con il payload originale V1.1: [evidenza statica](../Risultati/GUI_S33/rea_time_calc_bytes_20261105T191916Z/evidence.json). La lettura REA verifica i byte, non la semantica o l’esecuzione.
