> Correzione 2026-11-05: la prova originale impostava sia guardia busy sia conteggio tabella zero; il solo effetto della guardia è stato isolato successivamente con conteggio 197. Vedi [ritorno contestuale](S33_GUI_Akeru_Tempo_Ritorno_Contestuale_CPU_20261105.md).

# CaptureMenu → AkeruOS → tempo diagnostico → conferma, CPU V1.1

Data 2026-11-05. Un processo ARC emulato esegue snapshot MMIO sintetici → lettore/scanner/coda/dispatcher originali → AutoScene e CaptureMenu originali → manager originale → descrittore e callback AkeruOS sintetici → sequenza di navigazione del modello C → richiesta `AKERU_OPEN_SHUTTER` (4). Il banco preleva la richiesta e, solo se è 4, la traduce esplicitamente in `0x1453e4(0x3e,0)`. Il manager originale apre la schermata diagnostica Nikon `0x989cd8`, raggiungendo il callback originale `0x7d22f0`.

Per mantenere originale ID `0x3e` nella seconda apertura, la prima apertura AkeruOS usa ID **sperimentale** `0x3d`, con record CaptureMenu e voce della tabella modificati esclusivamente nella copia emulata. La voce originale della tabella è verificata rispetto al payload; non si afferma che ID 0x3d sia disponibile o utilizzabile sulla camera. In questa prova non viene implementato un ponte di produzione: il prelievo e la traduzione dell'azione sono operazioni del banco.

## Risultati: 8/8 PASS

Due fixture UI (0 e 0x23), quattro scenari ciascuna:

- Apertura: guardia libera, il manager restituisce 1 e passa al descrittore tempo `0x989cd8`.
- Guardia occupata impostata dopo l'azione: il manager restituisce 0 e conserva il descrittore AkeruOS `0x20c0000`. L'azione è già stata prelevata; non è dimostrato il retry.
- Modifica più: il banco inizializza il valore di lavoro `0x899ad0` a 120; pressione/rilascio `0x380/381` → 121. Prima della conferma i due campi software `0x365788` e `0x37fbf4` mantengono `0x12345678`; `0x580/581` li porta entrambi a 121000.
- Modifica meno: `0x400/401` → 119; conferma → entrambi 119000, con le stesse sentinelle intatte prima della conferma.

Per le modifiche, il banco inietta lo stato nello scanner originale `0x16f86c`, estrae e consegna i record al dispatcher; non usa lo snapshot MMIO per i quattro eventi della schermata tempo. I callback direzionali e quello di conferma, i setter `0x0d03e0` e `0x0de7b4`, e le relative finestre verificate contro il dump, sono originali. Controllo attivo, valore iniziale, indirizzo di stato, guardie e servizi di testo/formattazione sono fixture. Prima della conferma il banco imposta la guardia busy: la conferma tenta il manager, ma resta sulla schermata tempo. Ritorno e persistenza non sono dimostrati. Non è stabilito che i valori o il fattore 1000 corrispondano a secondi fisici o a un'esposizione del sensore.

## Riproduzione e prove

Base `python3 Python_Trace_Scripts/s33_verify_snapshot_capture_focus_original_cpu.py --boot-2c --custom-targets --open-targets --akeru-menu --akeru-time-open`; aggiungere `--akeru-time-busy`, oppure `--akeru-time-edit`, oppure `--akeru-time-edit --akeru-time-down`. Ripetere con `--ui-mode-23`.

- UI 0, nell'ordine apertura, busy, più, meno: `Risultati/GUI_S33/snapshot_capture_focus_original_cpu_20261105T110419528661Z`, `...110420334106Z`, `...110421155706Z`, `...110422038115Z`.
- UI 0x23: `...110422889895Z`, `...110423686333Z`, `...110424476817Z`, `...110425473025Z`.
- Regressioni: terza voce AkeruOS vuota `...110426333396Z`; apertura destinazione Nikon originale `...110427122854Z`, entrambe PASS.

I risultati includono trace, snapshot del verificatore, fixture, ELF e buffer. Le tracce verificano i callback delle due direzioni, il callback di conferma e i due setter; sono confrontati snapshot iniziali/finali, record, ritorni del dispatcher e stack.

## Limiti

Modalità, MMIO, RAM, lifecycle Akeru, timer/servizi e consegna eventi sono sintetici; il DSP del simulatore è sperimentale. Nessun rendering, ritorno reale, persistenza, associazione a tasti fisici, movimento dell'otturatore, cattura o hardware verificato. Gli indirizzi di laboratorio non dimostrano RAM fisica disponibile. REA aveva rifiutato l'ELF ARC; non sono state modificate sorgenti/build GNU, né scoperto qui un miglioramento dell'emulatore da pubblicare. **NON_INSTALLARE**.
