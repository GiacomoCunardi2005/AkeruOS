# Ritorno dal tempo ad AkeruOS — CPU V1.1, 2026-11-05

## Correzione della prova precedente

Nel banco `S33_GUI_CaptureMenu_Akeru_Tempo_Conferma_CPU_20261105.md` la guardia del manager era impostata, ma anche il conteggio della tabella finestre `0x366ea0` era azzerato. Il mancato ritorno osservato non isolava quindi l'effetto della guardia. Ripristinando il conteggio fixture a 197 e confrontando guardia libera/occupata, otto casi CPU confermano: con guardia libera la conferma originale richiede ID `0x36`, apre il menu diagnostico Nikon `0x987af8` e raggiunge `0x7cfb94`; con guardia occupata resta nella finestra tempo `0x989cd8`. In entrambi i casi la conferma ha già scritto i campi software. Il valore sopravvive anche alla consegna del rilascio successivo nel perimetro del banco; non è prova di persistenza.

## Ritorno sperimentale contestuale: 10/10 PASS

Si estende il percorso CPU snapshot → CaptureMenu e manager originali → AkeruOS sintetico → richiesta tempo prelevata e tradotta dal banco → finestra tempo originale. Nella copia emulata un trampolino sostituisce la chiamata originale al sito `0x7d23b8` della **sola conferma**. Il banco imposta un flag sintetico soltanto quando l'apertura del tempo restituisce 1 e il descrittore corrente è `0x989cd8`.

- Flag 1, guardia libera: il trampolino chiama il manager originale con il descrittore AkeruOS sintetico `0x20c0000`; quando ritorno e descrittore indicano successo azzera il flag. Il rilascio `0x581` arriva al modello riaperto; un nuovo snapshot `0x580/581` porta il modello dalla pagina esposizione successiva alla pagina esposizione. I campi software restano 121000 o 119000 e lo stack è conservato.
- Flag 1, guardia occupata: il manager rifiuta, il descrittore rimane `0x989cd8` e il flag rimane 1. I campi sono già stati scritti; retry e idempotenza non sono dimostrati.
- Flag forzato a 0, guardia libera: il trampolino ripete la chiamata originale all'ID `0x36`, il menu diagnostico Nikon diventa corrente e il callback originale viene raggiunto. Questo è un controllo con flag imposto, non una dimostrazione del caso d'uso originale sulla camera.

La matrice copre più/meno × guardia libera/occupata × UI fixture 0/0x23 (8) e flag forzato 0 × due fixture UI (2). Con flag 1, si controllano destinazione, stato del flag, campi, record di input, azione del modello e stack dopo la navigazione. Con flag 0 si controlla il ritorno al menu diagnostico. La modifica e conferma tempo usano scanner originale con stati imposti; gli input di navigazione Akeru usano snapshot MMIO sintetici. Codice, descrittore, tabella, flag e RAM del laboratorio non sono una patch installabile.

## Riproduzione e prove

Base `python3 Python_Trace_Scripts/s33_verify_snapshot_capture_focus_original_cpu.py --boot-2c --custom-targets --open-targets --akeru-menu --akeru-time-open --akeru-time-edit --akeru-time-return-context`. Aggiungere `--akeru-time-return-free` per guardia libera, `--akeru-time-down` per la direzione meno, `--ui-mode-23` per la seconda fixture; per il controllo flag 0 aggiungere `--akeru-context-off --akeru-time-return-free`.

- UI 0: più busy `Risultati/GUI_S33/snapshot_capture_focus_original_cpu_20261105T111002260853Z`, più libero `...111003125732Z`, meno busy `...111004039982Z`, meno libero `...111004924425Z`, flag 0 `...111005820679Z`.
- UI 0x23: più busy `...111006733743Z`, più libero `...111007604749Z`, meno busy `...111008467971Z`, meno libero `...111009388973Z`, flag 0 `...111010447537Z`.
- Controlli senza trampolino: `...110729636395Z`–`...110735649755Z`, otto casi, con conteggio 197; `...111011499804Z` ripete libero. Verifica finale con metadata aggiornati `...111024113825Z`; voce vuota Akeru `...111012456191Z` PASS.
- Esplorazione conservata: `...110609304136Z` fallisce l'attesa di ritorno con conteggio zero; `...110633378392Z` con conteggio 197 raggiunge il callback diagnostico ma richiede RAM sintetica `0x47c000` e termina con fault finché la fixture non è mappata. Non sono prove hardware.

## Limiti

Il trampolino e la produzione del flag sono nel banco, non in una integrazione pronta all'uso. Non sono provati annullo, retry, rollback, gestione concorrente, scheduler, rendering, memoria fisica, mapping dei tasti, unità fisiche, esposizione reale o hardware. Mode, guardie, input, servizi e lifecycle Akeru sono fixture; il DSP è sperimentale. REA aveva rifiutato l'ELF ARC; nessuna modifica a firmware, sorgenti o build GNU. **NON_INSTALLARE**.
