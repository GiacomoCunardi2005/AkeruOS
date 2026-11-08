# Verifica della patch HiddenMenu offline

Verifica statica locale del 19 ottobre 2026. Campione **Nikon S33 V1.1**: 29.602.084 byte, SHA-256 `1d34e990a8f99019ffa53ca5de785399df863e942739a667ceb314ec6ce62a39`. Indirizzi CPU della mappa candidata dei payload, salvo esplicita indicazione «offset file». Nessun risultato è una prova di esecuzione sulla S33 V1.0 dei log hardware.

Fonti riproducibili: [catalogo strutture](../S33-sections/analysis_codex/evidence/ui_catalog.json), [traccia e modelli locali](../S33-sections/analysis_codex/evidence/hiddenmenu_trace.json), [audit integrità](../S33-sections/analysis_codex/evidence/patch_audit.json). Esecuzione complessiva dalla radice: `python3 S33-sections/analysis_codex/run_analysis.py`, senza `-O`. GNU `-m arc:ARC700 -EL`, payload verificati e conversioni ELF temporanee ricontrollate byte per byte. Le finestre di contesto possono includere pool/tabelle: le righe che li interpretano come istruzioni non costituiscono flusso eseguibile; per i salti di selezione usare le finestre `case_…` riancorate.

## Confronto integrale dei file

Campione patchato ricevuto dall'utente, mai modificato durante questa analisi: `S33-sections/firmware_HIDDENMENU_RHIR_KHIR_OFFLINE_NOT_FLASH.bin`.

| File | Dimensione byte | SHA-256 |
|---|---|---|
| original | 29602084 | 1d34e990a8f99019ffa53ca5de785399df863e942739a667ceb314ec6ce62a39 |
| patched | 29602084 | 932281f89b840a45dc1b050dac52d5250f040ea6576b94696b55f3b93e123f1c |

| Offset file | Originale | Patchato | Interpretazione |
|---|---|---|---|
| 0x480d6 | 0x37 | 0x35 | Somma del payload00 nel record RHIR |
| 0x482ae | 0xdd | 0xdb | Somma KHIR del solo header RHIR |
| 0x482b2 | 0x22 | 0x24 | Complemento della somma KHIR |
| 0xcfeae | 0x83 | 0x81 | Immediato cmp_s: stato3→1 |

Il confronto ha esaminato tutti i29.602.084 byte con dimensione uguale: **esattamente quattro differenze**, nessun'altra. L'offset codice `0xCFEAE` corrisponde alla VA `0x1353F6` usando la base del blocco00 `0xAD800` e il payload a file `0x482B8`. I byte di istruzione non sono parole dati LE: a `0x1353F6` `83 E0 →81 E0`, GNU `cmp_s r0,3 →cmp_s r0,1`. Il salto successivo resta uguale.

## Integrità matematica verificata adesso

TBM inizia a **offset file0x480B8**, header descrittivo “TBM_SK501.BIN” a4806C, lunghezza TBM `0x10CCA00`. Il magic **RHIR è a480B8**, quattro byte dopo480B4 del diagramma iniziale. A480B4 si trova invece il wordLE32 `0x01114AB8`, dentro il descrittore precedente; la tabella dei record inizia a480C8, mentre480C0 è il word di identificazione `0x04611342`. Gli offset del contenitore non sono indirizzi CPU.

Ogni record RHIR da16byte inizia a `TBM+0x10+16*i`; la somma a+12 equivale alla somma delle paroleLE32 del payload modulo2^32. Tutti i16 payload originali corrispondono al manifest e ai file estratti. Nel patchato soltanto payload00 cambia: somma `0x9237C054 →0x9235C054`, delta−`0x20000`. Non si tratta di CRC32 né di una semplice somma dei byte.

| Blocco | Somma originale | Somma patchata | Payload uguale |
|---|---|---|---|
| 0 | 0x9237c054 | 0x9235c054 | no, solo cmp |
| 1 | 0x1cbdebfc | 0x1cbdebfc | sì |
| 2 | 0xc77beb72 | 0xc77beb72 | sì |
| 3 | 0xc84e85cb | 0xc84e85cb | sì |
| 4 | 0xd84b517c | 0xd84b517c | sì |
| 5 | 0x87ef474f | 0x87ef474f | sì |
| 6 | 0xfd148489 | 0xfd148489 | sì |
| 7 | 0x34852a02 | 0x34852a02 | sì |
| 8 | 0x6de87255 | 0x6de87255 | sì |
| 9 | 0x5f7e03ef | 0x5f7e03ef | sì |
| 10 | 0x79c3c9b1 | 0x79c3c9b1 | sì |
| 11 | 0xdd2f5c65 | 0xdd2f5c65 | sì |
| 12 | 0xa660948c | 0xa660948c | sì |
| 13 | 0xead66772 | 0xead66772 | sì |
| 14 | 0x8e5f5684 | 0x8e5f5684 | sì |
| 15 | 0x1fdcf448 | 0x1fdcf448 | sì |

KHIR è a `TBM+0x1F0 =file0x482A8`. La parola+4 è la somma delle paroleLE32 di **`TBM[0:0x1F0]`**, quindi include i descrittori e i relativi checksum, escludendo KHIR stesso. Non è la somma di tutti i payload. La parola+8 è il complemento bit a bit.

| File | Somma header KHIR | Complemento |
|---|---|---|
| original | 0x21ddcb41 | 0xde2234be |
| patched | 0x21dbcb41 | 0xde2434be |

Il TBIB è identico nei due file; checksum del suo corpo verificato: `0xf3f78173`, lunghezza corpo `0x44bbc`, base `0x1000000`, ingresso `0x1000000`. Gli hash dei due input sono stati ricontrollati dopo l'analisi.

## Ulteriori controlli identificati nel codice

- `0x12AEA0`, raggiunta dal percorso aggiornamento main `0x12AD58`, controlla capienza del selettore6, magic RHIR e wordheader+8 confrontato con `0xC7694`. Il getter ritorna il pool `0xC7698 =0x04611342`, uguale al word del campione a offsetfile480C0; è una guardia di identificazione distinta dal checksum.
- Lo stesso validatore scorre byteheader+6 record e, per tipo1, prepara offset/size in settori512; a `0x12AF16` chiama `0x1ED914`, confrontandolo col checksum record+12 a `0x12AF1A..1E`. Il corpo `0x1ED914` somma parole32, arrotonda `(len+3)>>2` e allinea il pointer in basso a4. Le lunghezze dei16 payload sono multiple di4. Questa routine non prova che tutti i tipi/record siano verificati da questo preciso ingresso.
- `0x12B060`, in un altro ramo di `0x12A794`, esegue **XOR di parole32** (`xor_s 0x12B07C`), distinto dalle somme RHIR/KHIR. La copertura dipende dagli argomenti del parser del formato; non è stato inventato un requisito “XOR del firmware intero uguale0”.
- Callback boot `0x12AA3C` cerca `INFO` (`0x4F464E49`) e `0x55AAAA55` prima di `0x12AE00`. Non equivale alla validazione di firma crittografica o di compatibilità del modello.

Questi controlli appartengono a rami software identificati. Non sono stati eseguiti l'updater, il bootloader completo o un'installazione. Non sono dimostrati autenticazione/trailer, versione consentita, disposizione della flash, compatibilità V1.0, recupero e accettazione della patch. **Checksum corretti non rendono il file installabile né flashabile in sicurezza.** La verifica resta offline e non modifica alcuno dei due firmware.

## Riproduzione e copertura

`python3 S33-sections/analysis_codex/audit_patch.py`: confronto completo,16 somme RHIR in entrambi i file,2 coppie KHIR somma/complemento,TBIB identico e valido,istruzione modificata e hash invariati. `run_analysis.py` aggiunge decodifica, tabelle, modelli locali e manifest delle evidenze. Nessuna compilazione dell'emulatore e nessun accesso USB/SD/NAND. Prossimo: verificare nel simulatore le guardie identità/capienza prima di studiare qualsiasi caricamento; R4 resta aperto.

## Aggiornamento salvato e stop

Vedere [nuove prove e punto di arresto](HIDDENMENU_FOLLOWUP.md): SD Life classificata P per scritture file; store MMIO verificati; ricerca nei16payload; hash firmware invariati. Analisi sospesa su richiesta dell’utente. Restano aperti backend2018, effetti transitivi e completamento fisico.
