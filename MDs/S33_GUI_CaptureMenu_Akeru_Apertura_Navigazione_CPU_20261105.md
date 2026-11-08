# CaptureMenu → pagina AkeruOS → navigazione, CPU V1.1

Data 2026-11-05. In CPU emulata lo snapshot MMIO sintetico passa dal lettore/scanner, coda, dispatcher e AutoScene al CaptureMenu originale, che inizializza le proprie risorse e seleziona il focus. La successiva classe logica 67 genera `0x2180`: il callback originale di CaptureMenu chiede al manager originale ID `0x3e`. In questo esperimento l'ID punta a un **descrittore AkeruOS sintetico**: il manager lo rende corrente e raggiunge il suo callback, che chiama il modello C AkeruOS compilato per ARC700.

Il cambio avviene soltanto nelle immagini di laboratorio e in RAM emulata: record destinazione in `0x980244`, voce di tabella a `0x3f59f8`, descrittore e stato a `0x20c0000`, codice sperimentale a `0x20b0000`. Gli indirizzi sintetici non indicano RAM fisica utilizzabile. Il descrittore deriva dai 28 byte originali di CaptureMenu ma controllo, conteggio e callback sono sostituiti; callback per eventi lifecycle ritorna zero, senza attuare un ciclo di vita completo. L'identità dei byte di firmware e delle voci originali è verificata contro `DUMPS/MainCode.dmp`; il firmware originale non viene scritto.

## Navigazione: 6/6 PASS

Tre sequenze, ciascuna con UI fixture 0 e 0x23. Dopo l'apertura, il banco impone classi e stati al generatore originale `0x16f72c`, estrae dalla coda originale e consegna esplicitamente ogni evento al dispatcher originale `0x169e1c`; dopo ogni evento preleva l'azione pendente chiamando `akeru_menu_take_action`. Il verificatore controlla i record di coda, la pagina risultante, l'azione pendente, l'azione prelevata, le trace dei due metodi C e lo stack. I rilasci non producono azioni.

| Eventi premuti/rilasciati | Esito del modello |
| --- | --- |
| `580/581`, `2700/2701`, `700/701` | principale → esposizione → esposizione successiva → richiesta `AKERU_OPEN_SHUTTER` (4) |
| `700/701`, `2180/2181` | principale → colore → richiesta `AKERU_REQUEST_MONO` (6) |
| `580/581`, `480/481` | principale → esposizione → principale |

Le richieste sono **prelevate come valori**, non eseguite: non attestano modifica dell'otturatore, del sensore o di un'immagine. Il ritorno provato è interno al modello di pagina, non un ritorno alla live view Nikon. Nessuna associazione a tasti fisici è dimostrata.

## Riproduzione e prove

`python3 Python_Trace_Scripts/s33_verify_snapshot_capture_focus_original_cpu.py --boot-2c --custom-targets --open-targets --akeru-menu`, con `--akeru-color` o `--akeru-back` per le altre sequenze e `--ui-mode-23` per la seconda fixture. Rispettivamente:

- UI 0: `Risultati/GUI_S33/snapshot_capture_focus_original_cpu_20261105T105803618069Z`, `...105805236503Z`, `...105806798565Z`.
- UI 0x23: `...105808279025Z`, `...105809634785Z`, `...105811063133Z`.
- Regressioni: destinazione Nikon originaria `...105812492040Z` PASS; 4 casi precedenti con richieste intercettate `...105813745375Z` PASS.

Ogni cartella contiene trace, codice compilato, snapshot del verificatore, fixture e risultati. Il primo tentativo con generatore, `...105746183858Z`, ha fallito un'asserzione sul quarto campo del buffer: era il valore di ritorno dell'estrazione, che il banco non aveva registrato. Il test corretto lo salva e lo verifica; il fallimento è conservato.

## Limiti

MMIO, modo `0x2c`, guardie, RAM, servizi e consegna sono fixture; dopo l'apertura le classi sono iniettate nel generatore, non nello scanner completo. Il rilascio dell'evento che apre la pagina e l'uscita finale dal descrittore non sono stati eseguiti. Nessun rendering, scheduler, persistenza, controllo fisico, otturatore o hardware è verificato. Il simulatore DSP è sperimentale; REA aveva rifiutato l'ELF ARC come architettura non supportata. Sorgenti/build GNU invariati; non è stato individuato un miglioramento dell'emulatore in questa prova. **NON_INSTALLARE**.
