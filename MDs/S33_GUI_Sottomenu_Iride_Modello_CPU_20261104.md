# Sottomenu iride sperimentale — 2026-11-04

Il modello C AkeruOS ora apre una schermata di scelta quando, dalla pagina esposizione, riceve l'evento logico `0x2180`. Le voci sono intenzionalmente **stato software 1** e **stato software 9**: la corrispondenza con i valori f/ e con la posizione fisica del filtro ND non è dimostrata.

| Schermata iride | Evento logico | Comportamento modello |
|---|---|---|
| indietro | `0x580` | ritorna a esposizione, richiede ridisegno |
| stato 1 | `0x700` | emette `AKERU_IRIS_STATE_1` |
| stato 9 | `0x2180` | emette `AKERU_IRIS_STATE_9` |
| quarta voce | `0x2700` | nessuna azione |

I rilasci non ripetono l'azione. La selezione resta nella schermata iride; il modello emette una richiesta e non dichiara che il filtro si sia spostato. `AKERU_OPEN_APERTURE` resta nell'enumerazione come valore storico, ma il percorso normale di esposizione ora produce ridisegno e apre la nuova schermata. I banchi storici che si aspettano immediatamente quell'azione descrivono il modello precedente e non sono automaticamente regressioni valide di questa versione.

## Verifica

- [Menu host UBSan e GNU ARC700](../Risultati/GUI_S33/akeru_menu_model_20261104T160513Z/verified_evidence.json): sei schermate, quattro eventi, rilasci, annullo, errori, azioni differite e sequenza della coda per entrambe le scelte.
- [Snapshot → menu → setter iride 14/14](../Risultati/GUI_S33/key_snapshot_menu_iris_cpu_20261104T160611376353Z/verified_evidence.json): dopo l'apertura, una **seconda pressione generata dallo scanner** seleziona stato 1 o 9 nel modello; il banco preleva l'azione e la traduce in chiamata al setter originale `0x18B85C`. Accettazione, acquisizione/guardia/richiesta rifiutate, scelta già corrente e controllo ISO sono provati con due ordini. La richiesta e gli altri servizi ottici sono stub: non provano attuazione.
- [Scanner → callback → modello 57/57](../Risultati/GUI_S33/key_scanner_menu_bridge_cpu_20261104T160513921654Z/verified_evidence.json), compresa la nuova schermata; [ritorno ISO 8/8](../Risultati/GUI_S33/key_scanner_menu_iso_return_cpu_20261104T160513921038Z/verified_evidence.json), ora seguito dall'apertura del sottomenu; [tempo 4/4](../Risultati/GUI_S33/key_scanner_menu_time_cpu_20261104T160513911116Z/verified_evidence.json); pipeline colore host/GNU PASS.

Il banco impone descrittore iniziale, snapshot, gate e ordine delle callback; estrae/dispatcha i record e traduce l'azione in setter. Non sono realizzati visualizzazione, stato ottico confermato, recupero/retry UI sul rifiuto, concorrenza AE, integrazione automatica o mapping fisico dei tasti. Gli indici non equivalgono a f/ fisici; non è stato toccato alcun dispositivo o firmware. **NON_INSTALLARE**.

Riproduzione: `make -C AkeruOS menu-model-verify`; `python3 Python_Trace_Scripts/s33_verify_snapshot_menu_iris_setter_cpu.py`; `python3 Python_Trace_Scripts/s33_verify_key_scanner_menu_bridge_cpu.py`.
