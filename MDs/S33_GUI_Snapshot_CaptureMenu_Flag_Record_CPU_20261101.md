# Snapshot e aggiornamento dei flag di CaptureMenu — 2026-11-01

## Risultato

Il banco GNU ARC700 V1.1 esegue, nella stessa sequenza, snapshot MMIO sintetico → normalizzazione e coda originali → dispatch imposto → AutoScene → manager → CaptureMenu originale. Durante l'ingresso viene ora eseguito anche l'aggiornamento originale `0x7CB1B4` → `0x631E98`, usando i due controlli e i sette record originali nella copia di laboratorio. Il recupero controllo rimane una fixture che restituisce gli indirizzi originali; anche il servizio che restituisce l'ID corrente è una fixture che legge l'ID dal controllo selezionato.

Prima di ogni caso il banco imposta artificialmente il bit 1 di tutti e sette i flag a `record+24`. La traccia controlla che le prime letture del codice originale vedano effettivamente `0A, 02, 02` e `0A, 02, 02, 02`, rispettivamente. Con ritorno sintetico `0xCAD30=0x46` e `0xCA310=0`:

| Sequenza | Flag `0x4800` dopo | Flag `0x4801` dopo |
| --- | --- | --- |
| `0x700` → apertura ID 2 argomento 4 | `08, 00, 00` | `0A, 02, 02, 02` |
| `0x2180` → apertura ID 2 argomento 5 | `0A, 02, 02` | `08, 00, 02, 02` |
| Entrambe, con guardia manager attiva | `0A, 02, 02` | `0A, 02, 02, 02` |

La lista selezionata viene aggiornata, mentre i valori iniziali sintetici dell'altra lista rimangono invariati. Per `0x4801` il bit 1 dei record con destinazioni `0x0A` e `0xBB` risulta impostato nel caso eseguito. Nella [prova separata di selezione](S33_GUI_CaptureMenu_Aggiornamento_Record_e_Slot_CPU_20261027.md) questo bit bloccava le rispettive richieste: quindi le richieste `0x0A` e `0xBB` ottenute nel [banco precedente](S33_GUI_Quattro_Eventi_Record_CaptureMenu_CPU_20261101.md), dove l'aggiornamento non era eseguito, non dimostrano che tali voci siano disponibili dopo questa inizializzazione. Qui non è stata ancora eseguita una pressione successiva nella stessa sequenza.

La prova è ripetuta con la fixture indipendente `0x1286BC` pari a 0 e a `0x23`: entrambe danno gli stessi flag elencati. Non si attribuisce un significato fisico a questi valori. Il modello DSP sperimentale è usato per le istruzioni richieste dai cicli.

## Riproduzione e limiti

- `python3 Python_Trace_Scripts/s33_verify_snapshot_capture_record_init_cpu.py`: 4 PASS, `Risultati/GUI_S33/snapshot_capture_record_init_cpu_20261101T100447765904Z/`.
- Stesso comando con `--ui-mode-23`: 4 PASS, `Risultati/GUI_S33/snapshot_capture_record_init_cpu_20261101T100451892499Z/`.
- Regressioni: `s33_verify_gui_capture_init_slot_cpu.py` 6 PASS, `capture_init_slot_cpu_20261101T100451Z/`; `s33_verify_gui_key_queue_capture_original_items_cpu.py` 8 PASS, `key_queue_capture_original_items_cpu_20261101T100451870456Z/`.

MMIO, ordine, consegna degli eventi, lifecycle AutoScene, recupero controllo e servizi sono in parte sintetici. Il seed non è lo stato iniziale osservato sulla fotocamera. Non sono verificati tasti fisici, rendering, valori reali delle impostazioni, persistenza o hardware; nessuna installazione. **NON_INSTALLARE**.
