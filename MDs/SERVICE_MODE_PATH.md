# HiddenMenu e Service Mode: percorso dimostrato e limiti

**Continuazione differenziale, 19 ottobre 2026.** Il [nuovo rapporto](MENU_DIFFERENTIAL.md) esegue24scenari con esiti FS simulati esplicitamente: main e callback ingresso root raggiunte in entrambi i casi positivi, ma fallback diverso se HiddenMenu fallisce e il marcatore NAND è disponibile (CMP3→4A, CMP1 nessuna apertura). Verificato anche un tratto del loop con record già estratto. Non sono provate UI visibile, inizializzazione/chiusura complete, equivalenza globale o sicurezza flash; NO-GO invariato.

Verifica documentale locale del 19 ottobre 2026 sul campione Nikon S33 **V1.1** (29.602.084 byte; SHA-256 `1d34e990a8f99019ffa53ca5de785399df863e942739a667ceb314ec6ce62a39`). Gli indirizzi sono CPU della mappa candidata dei payload, non offset del contenitore. Le istruzioni e i risultati qui citati sono evidenze statiche **pregresse lette in questa sessione**, non una nuova esecuzione del firmware né una verifica hardware. Nessun trasferimento degli indirizzi alla macchina V1.0 è dimostrato.

**È dimostrata una UI chiamata HIDDEN MENU; l'equivalenza con un distinto “Service Mode” non è dimostrata.** Nessuna sequenza di tasti fisici è ricavabile con affidabilità dai soli eventi UI. La ricerca locale dei termini `service mode` / `service menu` nei rapporti `S33_*.md` della radice e nei file HiddenMenu selezionati non ha trovato una definizione tecnica aggiuntiva; è una ricerca testuale limitata, non prova di assenza nel firmware.

## Entrata studiata

1. `0x1353F2` chiama il getter `0x129920`, che legge `0x366880`. Il payload contiene 1; `0xC5DE8` passa 1 al setter `0x129904`. È inizializzazione statica, non stato RAM osservato dopo boot; altri writer non sono esclusi.
2. A CPU `0x1353F6`, offset firmware `0xCFEAE`, l'originale `83 E0` è `cmp_s r0,3`; il patchato `81 E0` confronta 1. Il ramo `bne_s` a `0x1353F8` va a `0x135410`. La patch sostituisce la condizione 3 con 1. Per la riconferma corrente dei byte e dell'integrità vedere [PATCH_COMPATIBILITY.md](PATCH_COMPATIBILITY.md).
3. Solo se uguale, la call `.d` a `0x1353FA` usa nel delay slot il pool `0x1355D4 → 0x38FF2F`, stringa `B:\HiddenMenu`. `0xCDA24 → 0x12BBB8 → 0x18B45C → 0x26E6BC` verifica lookup riuscito e bit attributo `0x10`. Non basta una stringa incorporata, né un file di attributi qualsiasi.
4. Esito vero: `0x135404` prepara `r0=0x20`, `0x135406` prepara `r1=0`, `0x135408` chiama `0x1453E4`, resolver/apertura oggetto. Il manager può rifiutare l'apertura; non è una prova di visualizzazione.

Fonti: [GNU originale](../S33-sections/analysis_codex/evidence/00135384_activation_valid.txt), [lookup](../S33-sections/analysis_codex/evidence/000cda24_path_check.txt), [mappa e limiti dei modelli](HIDDENMENU_MAP.md), [sweep precedente sui 16 payload](../S33-sections/analysis_codex/evidence/activation_reference_sweep.json). Il modello precedente di 1.024 combinazioni assume stato stabile fra letture e sonde sostituite da esiti; non esegue il boot.

Il percorso B: non è stato identificato fisicamente come SD. Non si propone quindi di creare marker su una scheda della fotocamera. Anche le funzioni precedenti a `0x1353F2` e il ciclo vita UI appartengono al requisito di assenza di persistenza ancora da chiudere.

## ENABLE_NAND_TOOL è un ingresso alternativo

Se il primo ramo non apre la radice, `0x135410` rilegge lo stato; `cmp_s r0,2` e `blo_s` a `0x135414/16` richiedono stato almeno 2. `0x135418` verifica `B:\ENABLE_NAND_TOOL`, pool `0x1355D8 → 0x38FF3D`, poi può aprire direttamente ID `0x4A` (`0x135422`). Non è una condizione aggiuntiva del primo ingresso a `0x20`. Dalla radice la callback `0x7CC94C` apre `0x4A` senza ripetere questa sonda. Questo dimostra che la sonda è evitabile nel percorso statico della radice, non che una sessione reale abbia i prerequisiti soddisfatti. Fonti: [slice](../S33-sections/analysis_codex/evidence/00135384_activation_valid.txt), [callback root→NAND](../S33-sections/analysis_codex/evidence/007cc94c_handler_20_5005.txt).

## Dopo l'apertura

La radice ha descrittore `0x9827DC`, main `0x7CC6DC`, titolo HIDDEN MENU `0x982860`, sette voci: INFO, ERROR CODE, CALIBRATION, IQDEBUG, DEBUG MODE, NAND TOOL e SKY TOOL. Eventi `0x5000..0x5006` aprono `0x21/25/26/35/36/4A/4B`. Questo è un albero diagnostico con operazioni persistenti selezionabili; nessuna delle etichette dimostra un passaggio ulteriore a “Service Mode”. Fonte: [catalogo](../S33-sections/analysis_codex/evidence/ui_catalog.json), [mappa](HIDDENMENU_MAP.md).

L'evento root `0x0480` apre `0x84` ResetCameraConfirmMenu tramite `0x7CC88C`, non un ritorno innocuo. L'evento `0x2180` di `0x84` chiama `0xC9D84(1,1)`, `0xCBDF8`, `0x177030`, poi `0x78`. L'evento `0x2700` controlla un percorso con suffisso `\HiddenMenu`, chiama `0x12BBB8` e `0x16F920(8)`, poi apre `0x20` o `0x78`. Effetti di reset e mapping pulsanti restano aperti. Fonte: [eventi reset riancorati](../S33-sections/analysis_codex/evidence/00806c40_reset_confirm_events.txt).

## Risposte operative

| Domanda | Esito attuale |
|---|---|
| HiddenMenu equivale a Service Mode? | Non dimostrato; nome del menu e funzioni diagnostiche sono verificati. |
| Serve un evento ulteriore? | Per aprire la radice il ramo studiato chiama direttamente ID 0x20; un distinto ingresso Service Mode resta non identificato. |
| Serve ENABLE_NAND_TOOL? | Non nel primo ramo di apertura della radice; è una sonda del ramo alternativo verso 0x4A. |
| È dimostrato un ingresso senza scritture persistenti? | No. Nel piccolo slice di confronto/lookup non compare un writer diretto; ciclo vita, hook e dipendenze transitive non sono chiusi. |
| Posso limitarmi a guardare? | Non è ancora certificato: ingresso/uscita, default e reset hanno dipendenze aperte. Selezioni storage sono chiaramente rischiose. |

Per ridurre l'incertezza sul menu occorre verificare in isolamento manager `0x366E94`, hook `0x367808/0x367810`, risorse e callback di inizializzazione/chiusura, mantenendo le operazioni storage intercettate. Questo non sostituisce compatibilità updater e recupero R4 necessari prima di raccomandare il flash.
