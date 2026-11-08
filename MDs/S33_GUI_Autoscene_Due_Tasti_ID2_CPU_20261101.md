# S33 V1.1 — due eventi AutoScene e menu ID 2

**Data:** 2026-11-01. Prove GNU ARC700 con manager e handler originali, contesto e servizi sintetici.

Il [banco AutoScene](S33_GUI_Autoscene_Tasto_Rientro_Coda_CPU_20261101.md) ora esercita separatamente due eventi, con modalità `0x46` e guardie simulate. Entrambi passano per `0x6593A0` → `0x65C46C` → `0x65C5F8`; il codice originale richiede al manager lo stesso ID con argomenti differenti:

| Evento logico AutoScene | Richiesta osservata |
| --- | --- |
| `0x700` | ID `2`, argomento `4` |
| `0x2180` | ID `2`, argomento `5` |

La tabella `0x783B08`, i siti di codice e la voce ID 2 sono confrontati con il dump V1.1; la trace verifica gli argomenti effettivi. Per ciascun evento il banco ripete la richiesta con guardia manager attiva e inattiva: il dispatcher restituisce 1 in entrambi i casi, ma il descrittore rimane AutoScene quando la guardia blocca l'apertura. Quando la guardia è rimossa, nella **copia di laboratorio** ID 2 risolve il descrittore AkeruOS sintetico; il banco verifica la destinazione, resetta la coda alla pagina principale e usa un successivo `0x700` per raggiungere la pagina colore del modello.

Questo conferma un limite concreto della sostituzione globale sperimentale di ID 2: nei casi provati coinvolge entrambi gli eventi, non solo `0x700`. Il reset imposto a `AKERU_MAIN` ignora la differenza 4/5; non è dimostrato quale pagina o comportamento quelle due quantità producano nel CaptureMenu reale. Non trasferire l'ordine degli slot o la mappa fisica da una schermata all'altra.

Il wrapper del callback AutoScene inoltra al codice originale solo `0x700` e `0x2180`, simulando il lifecycle. Tabella ID 2 modificata soltanto nella copia laboratorio, modalità/guardie/tasti simulati, controllo attivo nullo e reset della coda imposto. Non sono provati tasti fisici, rendering, concorrenza, altre modalità o Mono RAW in camera. L'esperimento non è una modifica firmware pronta: **NON_INSTALLARE**.

Riproduzione: `python3 Python_Trace_Scripts/s33_verify_gui_autoscene_key_reenter_cpu.py` e stessa riga con `--event-2180`. Evidenze: [0x700](../Risultati/GUI_S33/autoscene_key_reenter_cpu_20261101T095157Z/reentry.json), [0x2180](../Risultati/GUI_S33/autoscene_key2180_reenter_cpu_20261101T095149Z/reentry.json); nove scenari PASS per variante, trace e fixture nelle rispettive cartelle. Modello menu host/GNU PASS `akeru_menu_model_20261101T095157Z/`. Nessuna operazione sulla fotocamera o SD.
