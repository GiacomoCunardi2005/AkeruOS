# NAND dal PC: analizzatore pronto per il nuovo export MainCode

21 ottobre 2026 — R0/R3/R4, strumento per il **passo decisivo del ramo** indicato da tutti i checkpoint recenti: quando l'utente eseguirà un nuovo Dump2File da HiddenMenu, `s33_analyze_maincode_export.py` classifica immediatamente la generazione dell'immagine nella flash MainCode. Nessun esito preferito è codificato: lo strumento misura e classifica.

## Uso

```bash
# sul nuovo export (dopo il Dump2File dell'utente):
python3 Python_Trace_Scripts/s33_analyze_maincode_export.py --export DUMPS/MainCode.dmp --save
# oppure su qualunque percorso del file esportato
```

L'analisi viene salvata in `Risultati/USB_SCSI/Accesso_NAND_PC/maincode_export_analysis_<ts>/analysis.json` con snapshot dell'analizzatore e indice `maincode_export_analysis_latest.json`.

## Cosa misura

Per l'export fornito (verificato per SHA-256 e lunghezza):

- **slot FF `0x9A3460`**: `820B2C` (gestori originali/noop attuale) oppure `35BD40` (handler RAW del candidato) — offset calcolato dal manifesto dei payload;
- **byte MSDC a RAM `0xC5EEA`** (patch di default MSDC);
- **hook 8 byte a RAM `0x820C88`** (aggancio del candidato);
- **coda record17** oltre i 17.615.360 byte del TBM originale (4.608 byte, 4.597 non-FF nel candidato);
- **identità integrale** del TBM esportato contro le quattro immagini note (originale V1.1, candidato SD `ce504526…`, MSDC-default `af65ab0e…`, candidato NAND/PC `0bb25fd6…`), con conteggio e indirizzi dei run di differenza.

Verdetto: `GENERAZIONE_CANDIDATO_NAND_PC` (slot RAW + record17 presenti) / `GENERAZIONE_<IMMAGINE>` (identità integrale con una nota) / `GENERAZIONE_ORIGINALE_SCONOSCIUTA` / `GENERAZIONE_SCONOSCIUTA`.

## Collaudi eseguiti

|Prova|Esito|
|---|---|
|export attuale `DUMPS/MainCode.dmp` (19.267.584 B, SHA `00551af5…`)|`GENERAZIONE_SD_CANDIDATE`: identità integrale col candidato SD, slot `820B2C` — coincide col [checkpoint generazioni](S33_NAND_PC_Generazioni_MainCode_Slot_FF_e_Assenza_Scrittori.md); [analisi salvata](../Risultati/USB_SCSI/Accesso_NAND_PC/maincode_export_analysis_20261021T164247Z/analysis.json)|
|export sintetico costruito dal TBM del candidato NAND/PC|`GENERAZIONE_CANDIDATO_NAND_PC`: slot `35BD40`, coda record17 4.597 byte non-FF, byte MSDC e hook presenti|

## Come leggere il verdetto

- L'export mostra il **contenuto della flash MainCode al momento del Dump2File**: non prova da solo quale copia sia avviata (le finestre di boot e le copie precedenti restano distinte, come già documentato).
- Un verdetto `GENERAZIONE_CANDIDATO_NAND_PC` indicherebbe che la flash contiene il candidato e renderebbe il dispatch RAW possibile: il passo successivo sarebbe la lettura RAW dal PC.
- Un verdetto di generazione precedente indicherebbe che l'installazione non è avvenuta nella flash MainCode: il problema sarebbe l'installazione, non la sintassi dei comandi.

## Limiti

- La classificazione dipende dalle quattro immagini note; varianti non note restano `SCONOSCIUTE` con i run di differenza disponibili per ispezione.
- Nessuna scrittura, nessun comando alla fotocamera, nessun flash: il candidato resta NON_INSTALLARE e nessuna installazione è qui proposta.
- Il metodo di acquisizione dell'export resta quello dell'utente (Dump2File da HiddenMenu).

## Continuazione

In attesa del nuovo export: continuare le verifiche offline residue (altri servizi di scrittura del vicinato, DMA/cache/alias) oppure l'analisi del dispatch calcolato del tratto `0x333968` (nessun chiamante statico né letterale: il cluster di helper `0x333924..0x333A80` è raggiunto solo via indirizzi calcolati — limite onesto registrato).
