# Quattro eventi sulle liste originali di CaptureMenu — 2026-11-01

## Risultato

Otto casi GNU ARC700 V1.1 collegano i tasti logici `11`, `14`, `67`, `78` al generatore e alla coda originali, quindi al dispatcher e agli handler originali della classe `0x15`. Rispetto alla [prova precedente con destinazioni sostituite](S33_GUI_Dispatch_Coda_Ricaduta_CaptureMenu_CPU_20261028.md), qui il controllo attivo è predisposto su una delle due risorse **originali**, con i rispettivi record originali, confrontati con il dump. Pagina zero, guardie e servizi sono predisposti dal banco; la richiesta di apertura è intercettata da una fixture.

| Evento logico | Slot | Lista `0x4800`: richiesta registrata | Lista `0x4801`: richiesta registrata |
| --- | ---: | --- | --- |
| `0x0580` | 0 | `0x87`, argomento 0 | `0x87`, argomento 0 |
| `0x0700` | 1 | `0x9D`, argomento 2 | `0x07`, argomento 0 |
| `0x2180` | 2 | `0x9D`, argomento 3 | `0x0A`, argomento 0 |
| `0x2700` | 3 | Nessuna richiesta nel caso provato: lista di 3 record | `0xBB`, argomento 0 |

I nomi staticamente associati agli ID includono AutoSceneLiveView (`0x87`), LiveViewHotKeyMenu (`0x9D`), ShootingMode (`0x07`), FrameSelect (`0x0A`) e ChangeColorMenu (`0xBB`); sono nomi dei descrittori, non prova di schermate effettivamente visualizzate. Per lo slot 3 della lista `0x4800` il dispatcher ritorna 1 e la fixture non registra né selezione né richiesta: ciò riguarda il solo contesto predisposto e non garantisce l'assenza di ricadute in altri stati. ChangeColorMenu originale non è una prova di Mono RAW Luminance.

Gli otto test controllano richiesta, argomento, indice selezionato, conservazione dello stack e record di pressione e rilascio in coda. Il banco consegna al dispatcher solo la pressione; il rilascio viene generato ed estratto, non consegnato. Il codice usa il simulatore GNU DSP sperimentale per `MULUDW`.

## Riproduzione e limiti

- `python3 Python_Trace_Scripts/s33_verify_gui_key_queue_capture_original_items_cpu.py`: 8 PASS, `Risultati/GUI_S33/key_queue_capture_original_items_cpu_20261101T100331010633Z/`.
- Regressioni: `s33_verify_gui_key_queue_manager_dispatch_cpu.py` 8 PASS, `key_queue_manager_dispatch_cpu_20261101T100334Z/`; `s33_verify_snapshot_capture_classes_cpu.py` 4 PASS, `snapshot_capture_classes_cpu_20261101T100334078741Z/`.

La selezione del controllo attivo e la consegna dell'evento sono imposte; apertura, attributi, selezione e sincronizzazione sono fixture. Questa prova non integra l'apertura iniziale nella stessa sequenza, non prova la mappa dei tasti fisici, il rendering, i valori delle impostazioni né la persistenza. Nessun accesso alla fotocamera. **NON_INSTALLARE**.
