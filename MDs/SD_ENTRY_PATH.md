# Ingresso SD ordinario e dispatch dei componenti — 19 ottobre 2026

## Risultato

Sul campione **V1.1**, l'ingresso UI ordinario verso `B:\FIRMWARE\FIRMWARE.BIN` è distinto dal menu NAND Tool. Il parser comune usa una callback pubblica `0xBC3F8` che seleziona per nome i writer registrati; la registrazione statica comprende **sia MainCode sia BootCode**. Quindi la presenza di un BootCode identico nel pacchetto non dimostra che la sua scrittura venga saltata. Questa verifica non dimostra alcun ingresso di recupero avviabile quando il MainCode non parte.

Campione: 29.602.084 byte, SHA-256 `1d34e990a8f99019ffa53ca5de785399df863e942739a667ceb314ec6ce62a39`. Tutti gli indirizzi sotto sono CPU della mappa candidata V1.1; gli offset del pacchetto sono esplicitamente indicati come tali. Nessun trasferimento alla macchina V1.0.

## Catena UI verificata nei byte

1. La pagina `0x96`, main `0x807E9C`, ha callback iniziale `0x807EF4`. Essa chiama il getter `0xC76FC` e `0x12A794` a `0x807F9A`, con callback **di controllo** dal pool `0x80807C = 0xBC308`. Il getter `0xC76FC` è `j_s.d [blink]` seguito dal caricamento in delay slot: pool `0xC7700 = 0x377E23`, stringa `B:\FIRMWARE\FIRMWARE.BIN`.
2. La callback della pagina `0x96` all'evento `0x440E`, `0x8080B4`, ramo `r2 == 1`, apre la pagina `0x9F` tramite `mov_s r0,0x9f` a `0x808104` e `bl 0x1453E4` a `0x808106`.
3. Descrittore `0x9A0414`, indice `0x9F`, nome interno `UpgradeFirmware`, main `0x80813C`. Il record `0x9A0450` lega evento `0x2180` a callback `0x80831C`. Il suo ramo ammesso apre `0xA1` (`0x80834E` / `0x808352`); l'altro apre `0xA6`. Le condizioni e gli helper osservati non sono interpretati come garanzia completa della batteria o della sicurezza fisica.
4. Descrittore `0x9A0624`, indice `0xA1`, nome `UpgradingFirmware`, main `0x8085D4`. Record `0x9A0680`: evento `0x440E` → `0x8086A8`. Nel ramo `r2 == 1`, `0x8086D6` chiama `0xC76FC`, `0x8086DA` carica `r2` dal pool **`0x808794 = 0xBC3F8`**, `r1` riceve il nome e `r0=0`; `0x8086E0` chiama `0x12A794`.

La fase di controllo `0xBC308` e la callback di scrittura `0xBC3F8` sono oggetti distinti. La catena UI e le due fasi sopra sono codice statico, non un'interazione eseguita sul dispositivo.

## Registrazione e dispatch: ponte verso i writer

`0xBBB60` registra tre nomi con `0xBC3A0`. Le chiamate `bl.d` hanno i caricamenti della callback nel rispettivo delay slot:

| Getter nome | Stringa | Chiamata registrazione / delay slot | Pool callback | Callback |
|---|---|---|---|---|
| `0xC76C4` | `B:\TBM_SK501.BIN` a `0x377DB8` | `0xBBB86` / `0xBBB8A` | `0xBBBF8` | `0x12A9FC` |
| `0xC76CC` | `B:\TBIB_SK501.BIN` a `0x377DC9` | `0xBBB90` / `0xBBB94` | `0xBBBFC` | `0x12AA3C` |
| `0xC76E4` | `B:\P1RES` a `0x377E01` | `0xBBB9A` / `0xBBB9E` | `0xBBC00` | `0x12AAA8` |

`0xBC3A0` estrae il basename, copia il nome a tabella runtime `0x42D15C + index*0x44`, poi scrive la callback nel campo `+0x40` a `0xBC3E2`. La formula dell'indice è esplicita: `index<<4`, più `index`, poi `<<2`. Non è un collegamento dedotto dalla vicinanza di parole.

`0xBC3F8` chiama il lookup `0xBC478`, che confronta fino a dieci nomi tramite `0x32DE80`. Se trova corrispondenza, carica il callback da `0x42D19C + index*0x44` a `0xBC438` e lo chiama a `0xBC444`, preservando gli argomenti del parser. Main: `0x12A9FC` controlla RHIR e chiama `0x12AD58` a `0x12AA28`. Boot: `0x12AA3C` cerca INFO e `0x55AAAA55`, quindi chiama `0x12AE00` a `0x12AA8C`.

Sono state riancorate anche chiamate dirette alla registrazione `0xBBB60`: `0xC5C10` nel corpo `0xC5BEC`, e `0xC5E08` nel corpo `0xC5DDC`. La catena completa dal reset e l'esecuzione reale di questa inizializzazione non sono dimostrate qui. La risoluzione pubblica ai writer è quindi un collegamento statico sotto la precondizione che tale inizializzazione sia eseguita e la tabella non venga successivamente alterata.

## Percorso formato V2.0 e ordine del pacchetto

`0x12A794` legge il file tramite `0x12AB24`; confronta `buffer+4` con `V2.0` (pool `0x12A8C0`), poi per questo formato passa al ramo `0x12A830`. La XOR `0x12B060(buffer+4, file_length-4)` viene confrontata con la prima word. La routine legge una word per iterazione con `ld.ab` a `0x12B074`, fa XOR a `0x12B07C` e ripete a `0x12B07E`.

Il loop incrementa **`r18`**, indice dei componenti a partire da 1 (`0x12A846` / `0x12A84C`); `r16` resta la fase 0 passata alla callback, non è l'indice. `0x12AFF0` parte dal descrittore indicato da `buffer+0x10`, segue `descriptor+0x48` come prossimo offset rispetto alla base e copia il record di `0x4C` byte. Il parser costruisce `r2=base+descriptor.data_start`, `r3=descriptor.length`, `r4=r2+workspace_offset`, poi chiama la callback a `0x12A88A`. Il valore `0x1C00139` chiede di continuare; `0xBC3F8` conta i completamenti riusciti e ritorna 0 dopo tre. Non si osserva qui un confronto con una versione installata per saltare BootCode identico.

Il parser locale già presente `coolpix-s33-re/s33_extract.py` è stato riutilizzato su originale e patch, insieme al controllo diretto dei campi seguiti da `0x12AFF0`. Ordine effettivo di entrambi:

| Ordine | Nome nel descrittore | Offset file descrittore |
|---|---|---|
| 1 | `TBIB_SK501.BIN` | `0x20` |
| 2 | `TBM_SK501.BIN` | `0x4806C` |
| 3 | `P1RES` | `0x1114AB8` |

Per entrambi i file, XOR delle word da offset 4 alla fine = **`0xBD4A9BF9`**, uguale alla prima word. Questo controllo non distingue originale e patch corrente; non prova accettazione completa dell'updater.

## Riproduzione e limiti

Comando eseguito: `python3 S33-sections/safety_audit_codex/sd_entry_verify.py`.

Esito: **PASS, 23 finestre GNU ARC700 little-endian, 53 istruzioni, 11 pool, due catene descrittori e due XOR**. L'helper esistente verifica identità dei 16 payload e roundtrip ELF per le finestre. Hash dei due input invariati. Script: [sd_entry_verify.py](../S33-sections/safety_audit_codex/sd_entry_verify.py); dati: [sd_entry_verified.json](../S33-sections/safety_audit_codex/evidence/sd_entry_verified.json); disassemblaggi `evidence/sd_entry_*.txt`. Le parole dei pool sono controllate come dati separati dai getter e dai corpi di codice.

Non controllati qui: selezione fisica delle regioni, intervalli di erase/program, eventuali writer transitivi, avvio da ROM/BootCode dopo corruzione MainCode, recupero da interruzione di alimentazione, confronto versione installata e compatibilità macchina V1.0. Nessun accesso USB/SD/NAND/EEPROM o hardware. Prossimo punto utile: unire questa catena ai writer `0x12AD58`/`0x12AE00` e alla selezione delle regioni, senza chiamare preservato un recupero di cui manca ancora l'ingresso indipendente dal MainCode.
