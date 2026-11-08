# NAND dal PC: verdetto dal nuovo export MainCode — la flash non ha mai ricevuto i candidati successivi

21 ottobre 2026 — R0/R3/R4. **Passo decisivo del ramo eseguito**: l'utente ha rifatto l'export MainCode (HiddenMenu → NAND TOOL → C1 Dump, SD collegata). Il nuovo `MainCode.dmp` è **byte-identico all'export del 20 ottobre**: SHA-256 `00551af5f4a948f83c3f549a6c5ed3261990143724a3b12de33228c6b4db06b5`, 19.267.584 byte. L'[analizzatore](S33_NAND_PC_Analizzatore_Export_MainCode.md) dà **`GENERAZIONE_SD_CANDIDATE`**.

## Fatti misurati

|Grandezza|Valore|Interpretazione|
|---|---|---|
|slot `0x9A3460`|`0x820B2C`|gestore FF originale (noop): **l'handler RAW non è in flash**|
|byte MSDC `0xC5EEA`|`0x02` (originale)|**la patch MSDC-default `af65ab0e` non è in flash**|
|coda record17|assente (solo FF)|**il candidato NAND/PC `0bb25fd6` non è in flash**|
|identità TBM|coincide integralmente col candidato SD `ce504526`|la flash contiene la generazione installata la **mattina del 20 ottobre**|

Il nuovo export è conservato come [DUMPS/MainCode_20261021_nuovo_export.dmp](../DUMPS/MainCode_20261021_nuovo_export.dmp) (l'export originale del 20 ottobre resta intatto in `DUMPS/MainCode.dmp`); analisi salvata in [maincode_export_analysis_20261021T175816Z](../Risultati/USB_SCSI/Accesso_NAND_PC/maincode_export_analysis_20261021T175816Z/analysis.json).

## Conseguenza per il ramo

Tutti i «messaggi di aggiornamento completato» riferiti dall'utente per i BIN successivi (MSDC-default `af65ab0e` la sera del 20 ottobre, NAND/PC `0bb25fd6` il 21 ottobre, e il re-install del candidato SD di stasera — quest'ultimo ovviamente coerente con sé stesso) **non hanno lasciato traccia nella partizione MainCode**. Il comportamento noop della sonda RAW del 21 ottobre è ora pienamente spiegato: l'immagine avviata non ha mai avuto l'handler RAW perché non è mai stata scritta. Anche l'apparizione di MSDC su USB si spiega senza la patch: resta attribuibile all'**impostazione MSDC del menu DEBUG** (byte RAM `366B9D`, già osservata «MSDC Card:ON»), non al firmware `af65ab0e`.

**Il problema del ramo è l'installazione, non la sintassi né il client.** Il goal «accesso al resto NAND dal PC» resta aperto e ora ha un bersaglio preciso: capire perché l'updater non scrive (o non vede) i BIN successivi.

## Ipotesi da verificare al prossimo tentativo

1. **Posizione del file**: la convenzione Nikon vuole `firmware.bin` nella **radice della SD**; i tentativi documentati usavano la sottocartella `firmware/`. La prima installazione riuscita (20 ottobre mattina) aveva probabilmente un layout diverso. Il candidato NAND/PC è stato ora copiato **sia in radice sia in `firmware/`**.
2. **Rifiuto silenzioso dell'updater**: il candidato NAND/PC ha 18 record (record17 aggiunto) e 29.606.692 byte contro 29.602.084 dell'originale; la validazione dell'updater potrebbe respingerlo senza messaggio utile. Il candidato MSDC (5 byte, dimensione originale) sarebbe un buon **test di controllo**: se anche quello non persiste, il problema non è la struttura del contenitore.
3. **Percorso di commit**: l'updater ha boot/commit/copia di riserva; un commit non concluso può lasciare la Main precedente. I verificatori offline del dispatch hanno già mostrato contatori e percorsi condizionali, non il comportamento fisico.

Prossimo protocollo (operazioni utente): installare il candidato messo in SD, poi **senza toccare altro** rifare C1 Dump → analizzatore: se il verdetto cambia la flash ha ricevuto l'immagine; se resta `GENERAZIONE_SD_CANDIDATE` l'installazione è fallita di nuovo e il ramo si sposta sull'updater.

## Limiti

- L'export mostra la partizione MainCode della flash al momento del dump, non la copia avviata; qui le due letture (export + sonda RAW noop) concordano.
- Metodo del dump: fornito dall'utente (C1 della NAND TOOL); l'agente ha solo letto il file dalla SD.
- I tre BIN sperimentali restano NON_INSTALLARE come etichetta di verifica pre-install; le installazioni sulla macchina sono decisioni dell'utente con i limiti di recupero documentati (R4 aperto).

Candidato `0bb25fd6…` invariato nei byte; circa 10% invariato; goal aperto.
