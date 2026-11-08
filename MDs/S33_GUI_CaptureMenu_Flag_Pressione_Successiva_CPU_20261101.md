# CaptureMenu: pressioni successive all'aggiornamento flag — 2026-11-01

## Risultato

La prova GNU ARC700 V1.1 collega nello stesso caso l'apertura della lista originale `0x4801`, l'aggiornamento originale dei suoi flag e una successiva pressione logica. Nelle condizioni del banco, entrambi gli slot con destinazioni `0x0A` e `0xBB` leggono flag `2`, ritornano `1` e non chiamano né la selezione `0x631E00` né il servizio di apertura `0x1453E4` dopo la pressione. Il descrittore corrente osservato resta `CaptureMenu` (`0x9802AC`).

| Apertura e stato | Pressione successiva | Handler originale | Osservazione |
| --- | --- | --- | --- |
| Evento `0x2180`, ID 2 argomento 5; flag `08,00,02,02` | Tasto logico 67 → `0x2180` | `0x631A38`, record `0x980230`, destinazione `0x0A` | Flag `2`, nessuna nuova richiesta |
| Come sopra | Tasto logico 78 → `0x2700` | `0x631B14`, record `0x98024C`, destinazione `0xBB` | Flag `2`, nessuna nuova richiesta |
| Guardia manager attiva | Nessuna pressione successiva inviata | — | L'apertura iniziale resta bloccata |

La prima pressione e il rilascio percorrono snapshot sintetico, normalizzatore, coda e dispatcher originali, con estrazione e consegna esplicite; il codice `0x7CB1B4` aggiorna i record. Dopo il rilascio il banco **imposta esplicitamente il controllo attivo** al descrittore originale `0x980268`, inietta il tasto logico successivo, estrae l'evento dalla coda e lo consegna al dispatcher originale. Il secondo rilascio non è generato. La traccia controlla entrata negli handler, lettura del flag, assenza di chiamate ulteriori all'apertura e stack; le quattro chiamate osservate a `0x1453E4` sono le richieste iniziali a ID 2, comprese quelle bloccate dal manager.

`0xCAD30` restituisce `0x46` e `0xCA310` 0 tramite fixture. Il bit 1 iniziale è seminato artificialmente nei record prima dell'aggiornamento. Il confronto con la [prova diretta](S33_GUI_CaptureMenu_Aggiornamento_Record_e_Slot_CPU_20261027.md) mostra che altre risposte sintetiche agli helper possono dare esiti diversi, ma non stabilisce quali stati si presentino sulla fotocamera. La fixture indipendente `0x1286BC` è stata provata con 0 e `0x23`.

## Riproduzione e limiti

- `python3 Python_Trace_Scripts/s33_verify_snapshot_capture_followup_key_cpu.py`: 4 casi PASS, `Risultati/GUI_S33/snapshot_capture_followup_key_cpu_20261101T100557346989Z/`.
- Stesso comando con `--ui-mode-23`: 4 PASS, `Risultati/GUI_S33/snapshot_capture_followup_key_cpu_20261101T100600883965Z/`.
- Regressioni: `s33_verify_gui_capture_init_slot_cpu.py` 6 PASS, `capture_init_slot_cpu_20261101T100600Z/`; `s33_verify_snapshot_capture_record_init_cpu.py` 4 PASS, `snapshot_capture_record_init_cpu_20261101T100600857651Z/`.

MMIO, stato iniziale, lifecycle AutoScene, recupero della risorsa, controllo attivo, scheduler e servizi sono in parte imposti o sintetici; il simulatore DSP è sperimentale. Non sono dimostrati tasti fisici, rendering, valori delle impostazioni, persistenza o hardware. **NON_INSTALLARE**.
