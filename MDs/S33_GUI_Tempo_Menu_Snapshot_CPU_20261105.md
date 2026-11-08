# Tempo dal menu Akeru alla copia di stato — 5 novembre 2026

**Esito: 8/8 casi CPU emulata PASS; NON_INSTALLARE.** Il banco esistente percorre CaptureMenu → menu Akeru sintetico → pagina Nikon del tempo, con eventi scanner e dispatcher esplicitamente azionati. Dopo modifica e conferma oppure annullamento, il banco richiama esplicitamente la routine originale `0xF6F54` e confronta la sua copia a 64 byte con una copia di riferimento del contenuto vivo di `0x37FBD0`. La copia byte sottostante `0x128C20` è una fixture; i due canarini adiacenti alla destinazione restano invariati. L'ISO a `+0x22` è impostato dal banco a 125 immediatamente prima della copia: non è una selezione ISO effettuata dal menu.

| Caso | Campo tempo a `+0x24` copiato | Evidenza |
|---|---:|---|
| 120 → 121, conferma, guardia occupata | 121000 | `snapshot_capture_focus_original_cpu_20261105T191600698446Z_204534` |
| 120 → 119, conferma | 119000 | `snapshot_capture_focus_original_cpu_20261105T191607364412Z_204873` |
| 3999 → 0, conferma | 0 | `snapshot_capture_focus_original_cpu_20261105T191607410454Z_204874` |
| 1 → 0, conferma | 0 | `snapshot_capture_focus_original_cpu_20261105T191607423713Z_204879` |
| 120 → 121, annulla | `0x12345678` precedente sintetico | `snapshot_capture_focus_original_cpu_20261105T191607410895Z_204878` |
| Conferma, ritorno contestuale libero | 121000 | `snapshot_capture_focus_original_cpu_20261105T191607418784Z_204880` |
| Conferma con guardia occupata, retry iniettato | 121000 | `snapshot_capture_focus_original_cpu_20261105T191607411327Z_204875` |
| Annulla, ritorno contestuale libero | `0x12345678` precedente sintetico | `snapshot_capture_focus_original_cpu_20261105T191607370240Z_204876` |

Le cartelle si trovano in `Risultati/GUI_S33/` e contengono tracce, manifest, fixture e copia del verificatore. Regressione senza nuova opzione: `snapshot_capture_focus_original_cpu_20261105T191607412681Z_204877` PASS. [Verificatore](../Python_Trace_Scripts/s33_verify_snapshot_capture_focus_original_cpu.py); [precedente prova separata fino al calcolo](S33_GUI_Conferme_ISO_Tempo_Calcolo_CPU_20261030.md).

Il ritorno contestuale usa un reindirizzamento di laboratorio; guardie, RAM, selezione, MMIO e gestione eventi sono modellati. Il retry è inserito a mano. La copia è invocata direttamente dal banco: questa prova non dimostra che la sequenza reale di scatto la invochi, né attraversa `D8CA4/FDA28` nello stesso scenario. Zero e moltiplicazione per 1000 sono valori software; unità fisiche, esposizione automatica, persistenza, concorrenza e comportamento del sensore non sono verificati. Nessuna prova hardware o operazione su fotocamera/SD.
