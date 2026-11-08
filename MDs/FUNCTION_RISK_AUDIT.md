# HiddenMenu: audit delle funzioni e dei rischi

Verifica statica locale del 19 ottobre 2026. Campione **Nikon S33 V1.1**: 29.602.084 byte, SHA-256 `1d34e990a8f99019ffa53ca5de785399df863e942739a667ceb314ec6ce62a39`. Indirizzi CPU della mappa candidata dei payload, salvo esplicita indicazione «offset file». Nessun risultato è una prova di esecuzione sulla S33 V1.0 dei log hardware.

Fonti riproducibili: [catalogo strutture](../S33-sections/analysis_codex/evidence/ui_catalog.json), [traccia e modelli locali](../S33-sections/analysis_codex/evidence/hiddenmenu_trace.json), [audit integrità](../S33-sections/analysis_codex/evidence/patch_audit.json). Esecuzione complessiva dalla radice: `python3 S33-sections/analysis_codex/run_analysis.py`, senza `-O`. GNU `-m arc:ARC700 -EL`, payload verificati e conversioni ELF temporanee ricontrollate byte per byte. Le finestre di contesto possono includere pool/tabelle: le righe che li interpretano come istruzioni non costituiscono flusso eseguibile; per i salti di selezione usare le finestre `case_…` riancorate.

## Classi e livello di prova

- **L**: sola lettura del dato nel corpo identificato; non attribuita automaticamente a tutto il menu chiamante.
- **R**: modifica RAM nei corpi verificati; effetti successivi dei consumatori non esclusi.
- **P**: percorso di scrittura file/formattazione, quindi modifica persistente richiesta; completamento fisico non provato.
- **F**: possibile scrittura NAND/flash, con catena statica verso servizi di partizione/settore oppure indizi specifici dichiarati. Non equivale a controller fisico o protocollo NAND già risolti.
- **U**: effetti non sufficientemente risolti; non significa innocuo.

L'audit copre i callback di0x20 e tutti i29/17 casi dei selettori0x4A/4B, risolvendo gli indiretti tabellari e alcuni callback di backend. Non chiude transitivamente ogni funzione Nikon, hook runtime, interrupt e consumer dei dati modificati. Le etichette sono supporto, non prova autonoma della direzione dei dati.

## Radice 0x20 e dipendenze comuni

| Indirizzo / evento | Classe | Prova e limite |
|---|---|---|
| 0x129920 | L | Lettura byte 0x366880; getter, non apertura menu. |
| 0x635DAC / 0x635BD8 | L | Conteggio lista, indice e lettura item+0x14. Prologhi/stack esclusi dal significato di lettura del dato. |
| 0x7CC714 / 0x4401 | R + U | Store del pointer lista in *(0x8998E4), helper 0x23D478; inoltre 0xD1A00 e possibile 0x809DF4. Effetti transitivi non chiusi. |
| 0x7CC7D8 / 0x440C | R + U | Ricalcolo e chiamata 0x23D478 con struttura UI; rendering/backend non completamente auditati. |
| 0x7CC8AC..0x7CC96C / 0x5000..5006 | R + U | Apertura ID21/25/26/35/36/4A/4B via1453E4; i figli includono calibrazione, cancellazione errori e scritture storage. |
| 0x7CC88C / 0x0480 | U | Apre84 ResetCameraConfirmMenu. Callback84/2180 chiamaC9D84(1,1),CBDF8,177030; non prova di ritorno privo di effetti. |
| 0x145180 / 0x169D78 | R + U | Aggiornamento manager e ciclo vita, più hook runtime 367808/367800/367810. Possibile rifiuto del cambio. |
| 0x20E814 default | U | Delega alla tabella3E8BB4: non è no-op. Altri menu/cambio modalità raggiungibili con opportuni eventi. |

## NAND TOOL — 28 voci, 29 casi

Dispatcher `0x7D444C`: contesto `0x899B88`, guardia byte+4, dato item a+0x14, `sub2 r1,r21,0x19` sottrae100; tabella signed16 `0x7D44EE`, target=`base + 2*entry`. Se `0xCB70C(0)` restituisce3/4, il ramo operativo è escluso localmente. Conferme per alcuni comandi usano byte+8; non sono un meccanismo generale di protezione. Il dato103 ha un case ma nessun record della lista iniziale.

| Dato | Indice visibile | Voce originale | Entrata case | Classe | Prova / limite |
|---|---|---|---|---|---|
| 0x64 | 0 | A1.Update MainCode: TBM_X.BIN | 0x7d4528 | F | 12A794 → callback12A9FC →12AD58 →1EEA4C(partizione6). |
| 0x65 | 1 | A2.Update BootCode: TBIB_X.BIN | 0x7d4542 | F | 12A794 → callback12AA3C →12AE00 →1EEA4C(partizione0). |
| 0x66 | 2 | B1.Erase Main Code | 0x7d455a | F | 2FFF0C(6): buffer FF e1EEA4C. |
| 0x67 | assente | case non esposto | 0x7d456a | F | Non visibile: CDA24 su marker, poi2FFF0C(0). |
| 0x68 | 3 | B2.Erase Calibration | 0x7d4584 | F | 2FFF0C(1), poi(2): lettura preliminare, fill FF parziale e scrittura. |
| 0x69 | 4 | B3.Erase NAND Reserved Area | 0x7d459e | F | 2FFF0C(5). |
| 0x6a | 5 | B4.Erase NAND Start Sector 0 | 0x7d45aa | F | 1695D0(0,1,buffer,0) →169564; sink fisico ancora aperto. |
| 0x6b | 6 | C1.Dump to:MainCode.dmp | 0x7d45c2 | P | 2FFFCC(6) →30017C →12DBFC(mode2),12DE3C,12D604. |
| 0x6c | 7 | C2.Dump to:BootCode.dmp | 0x7d45cc | P | 2FFFCC(0), stessa catena di scrittura file. |
| 0x6d | 8 | C3.Dump to:Calibration.dmp | 0x7d45d6 | P | 2FFFCC(1) e(2), stessa catena file. |
| 0x6e | 9 | C4.Dump to:CalibrationItem.txt | 0x7d45ec | P | 12A268 →12BD5C →18B0BC, scrittura testo. |
| 0x6f | 10 | C5.Dump to:CameraParam.dmp | 0x7d45f4 | P | 2FFFCC(3) e(4), stessa catena file. |
| 0x70 | 11 | C6.Dump to:BootNANDBase.dmp | 0x7d460a | P | 301650 →30017C. |
| 0x71 | 12 | C7.Dump to:BFNSetting.txt | 0x7d4612 | P | 300554 →12DE3C, più righe. |
| 0x72 | 13 | C8.Dump to:NANDPartition.txt | 0x7d461a | P | 30026C →12DBFC; scritture intermedie non tutte espanse. |
| 0x73 | 14 | C9.Dump to:NANDP1.dmp | 0x7d4622 | P | 3000E8 →30017C. |
| 0x74 | 15 | C10.Dump to:NANDReserved.dmp | 0x7d462a | P | 2FFFCC(5) →30017C. |
| 0x75 | 16 | C11.Dump to:ReservedItem.txt | 0x7d4634 | P | 12A38C →12BD5C a12A4B6: salvataggio del testo degli item riservati. |
| 0x76 | 17 | D1.Restore from:Calibration.dmp | 0x7d463c | F | 3001D0 →129D08; ripristino indicato dalla voce, sink non ancora espanso: F candidata. |
| 0x77 | 18 | D2.Restore Camera Parameter | 0x7d4644 | F | 300208 →3019E8, poi128ED4(1)/1290F0; persistenza/sink da chiudere: F candidata. |
| 0x78 | 19 | D3.Reset Camera Parameter | 0x7d465a | F | C9D58/1290F8/128F28(1)/1290F0: reset parametri, persistenza candidata. |
| 0x79 | 20 | D4.Update BFN:BootNANDBase.bin | 0x7d466a | F | 3014C0 →1EEF6C, confronto con lettura1ED5E4. |
| 0x7a | 21 | D5.Udpate BFNSetting:NANDUtility.txt | 0x7d4674 | F | 3016EC →1EEAEC →25F338; backend fisico non chiuso. |
| 0x7b | 22 | D6.Update BFN,BFNSetting,Boot,FW(4in1) | 0x7d467e | F | Catena100/101, poi3016EC e3014C0 dopo conferma. |
| 0x7c | 23 | D7.Change Partition:NANDUtility.txt | 0x7d46e8 | F | 3012F0 →29EFC4; modifica partizioni candidata, backend aperto. |
| 0x7d | 24 | D8.Update all P1 data | 0x7d46f6 | F | Marker CDA24, poi301E1C(1,0) →29E8F0/16F200. |
| 0x7e | 25 | D9.Create Partition+Update All P1 data | 0x7d4716 | F | Conferma, poi301E1C(0,1); possibile cambio partizioni e aggiornamento. |
| 0x7f | 26 | E1.Full Format Card | 0x7d473c | P | 300D0C →12BA68 →18AF04 →21C420/21C698. Formattazione da etichetta + catena filesystem; supporto selezionato da argomenti. |
| 0x80 | 27 | E2.Full Format Internal | 0x7d4746 | F / P | Stessa catena di127 con altra stringa selettore: volume interno da etichetta, associazione fisica da verificare. |

### Catene di scrittura e chiamate indirette risolte

- `0x7D452C` carica r2 dal pool `0x7D47D4 = 0x12A9FC`; il case boot usa `0x7D47D8 = 0x12AA3C`. `0x12A794` conserva quel parametro in r19 e invoca l'indiretta a `0x12A82A` oppure `0x12A88A`, secondo il formato. La prima callback controlla RHIR; la seconda cerca INFO e55AAAA55. Non sono pointer ipotizzati dalla vicinanza.
- `0x12AD9C` chiama `0x1EEA4C(6,buffer,0,len)`; `0x12AE4A` passa partizione0. `0x1EEA4C` allinea lunghezza a settori512, acquisisce sincronizzazione, prepara con `0x260FE4`, poi chiama `0x1EE730`. I rami finali chiamano `0x1EDED8/0x1EDFDC`. Il controller e la semantica fisica erase/program non sono stati chiusi: classificazione **possibile scrittura NAND/flash**, non prova hardware.
- `0x2FFF0C`: per selettori1/2 chiama prima `0x1ED27C`; poi `0x13A954` riempie conFF da buffer+0x60 per lunghezza−112 e invia a `0x1EEA4C`. Per gli altri selettori riempie tutto il buffer. Non implica che la routine sia un comando NAND erase nativo: potrebbe programmare FF o passare a un altro livello.
- `0x30017C` apre con modo2 (`0x300194`), chiama `0x12DE3C` a `0x3001B2` e chiude. Il percorso “dump” scrive un file: non classificarlo L. `0x12DE3C` conduce a `0x1FA090`; close/ritorno0 non provano persistenza completa.
- `0x12BD5C` arriva a `0x18B0BC`; l'indiretta di chiusura a `0x12BDEC` usa il pool `0x12BDFC =0x18B0FC`, chiusura distinta dalla scrittura.

### Errori e durata

`0x7D4840` è un **ciclo locale senza uscita** (`b_s 0`) nel ramo di errore mostrato. Altri rami attendono ripetutamente `0x16F920(0x62)` e puliscono la guardia solo al termine comune `0x7D4880`. Un blocco dell'interfaccia è quindi un rischio concreto, distinto dalla perdita di dati. Il guard byte non dimostra mutua esclusione atomica fra task o gestione di reset durante la scrittura. Nessuna routine è stata eseguita sulla camera.

## SKY TOOL — 16 voci, 17 casi

Dispatcher `0x7D4D94`, contesto `0x899B9C`: il caricamento `.as` a `0x7D4DB4` usa `(PC&~3)−106*4 = 0x7D4C0C`, non il commento non scalato. Jump table signed16 a `0x7D4DD6`. La tabella ha un case14 predefinito senza voce; indici14/15 visibili contengono dati15/16.

| Dato / indice | Voce | Case | Classe | Prova e limite |
|---|---|---|---|---|
| 0x0 / 0 | SD Life | 0x7d4df8 | P | 7D58D8: apertura modo2 a7D5B44, scrittura12DE3C a7D5B60, riletture12D530 e confronto32E508; loop7D5CDE. Percorso2018 con backend runtime ancora aperto. |
| 0x1 / 1 | Infinitely focus.(DISABLE) | 0x7d4e08 | R | EA4A8/EA4B4 scrivono0/1 al byte365F79; store etichetta aitem+0C. Consumatori del flag non chiusi. |
| 0x2 / 2 | Fire full strobe.(DISABLE) | 0x7d4e3e | R | D0430 storebyte a3658BC, getterD044C; effetto fisico dello strobe nei consumatori aperto. |
| 0x3 / 3 | Close shutter.(DISABLE) | 0x7d4e72 | U | 1495E0/1495BC, backend18B794 e altri servizi: possibile comando hardware, nessuna garanzia di sola RAM. |
| 0x4 / 4 | Actual shutter speed.(DISABLE) | 0x7d4ea2 | R | D0394 storebyte a3658BB; getterD03B0. |
| 0x5 / 5 | PWB_SEETING FOR SK204 | 0x7d4ed6 | R + U | D0454 scrive3658BD, CA404 cambia modalità; guardia sul getterCAD30 (2C/A/4). Effetti ulteriori non risolti. |
| 0x6 / 6 | AUTO MODE FOR SK204.(DISABLE) | 0x7d4f0e | R + U | Toggle3658BD, CA404, poi apertura87 tramite pool1453E4. |
| 0x7 / 7 | LCD TIME OUT.(ENABLE) | 0x7d4f6a | R + U | C68B4 store36563C, in un ramo chiama148DCC/DE7DC. Non dimostrata assenza di effetti hardware. |
| 0x8 / 8 | Fill Resource InTo P1 | 0x7d4f9a | F | 2FFF0C(5) prima di7D52A4; quest’ultima chiama129460, con sink1EEA4C(5). |
| 0x9 / 9 | Fill Resource InTo P1Res.bin | 0x7d4fcc | P | 7D555C; C76E4 fornisce nomeP1Res.bin,12D710 e12BD5C salvano il file. Nessuna prova di sola lettura. |
| 0xa / 10 | Fill P1Res.bin InTo P1 | 0x7d4ff2 | F | 2FFF0C(5), poi7D581C legge il file e chiama129460; possibile perdita risorse se fallisce dopo la cancellazione. |
| 0xb / 11 | LV GTE .(Enable) | 0x7d501e | R | 12EF14 store a366920+45hex =366965, condizionato daC7828. |
| 0xc / 12 | QV GTE .(Enable) | 0x7d504e | R | 193080 store a3681E0+14hex =3681F4, condizionato daC781C. |
| 0xd / 13 | FR GTE .(Enable) | 0x7d507e | R | 1BCFB4 store a368790+98hex =368828, condizionato daC782C. |
| 0xe / assente | default | 0x7d512c | R | Case predefinito7D512C: timer e refresh UI, nessuna voce con dato14. |
| 0xf / 14 | Copy P1RES into P1 reserve | 0x7d50ae | U / F candidata | BC62C(0), poi(3), poi(4) solo dopo esito0. BC650 resolve→BD2D4/BD348,1296EC; direzione/commit fisico ancora da risolvere, non dedotta dal testo Copy. |
| 0x10 / 15 | Dump P1RES from P1 reserve | 0x7d5108 | P | BC62C(1) →BD1F8;12DBFC/12DE3C/12D604 producono il dump. Altri effetti transitivi restano aperti. |

L'indiretta `jl_s [r2]` a `0x7D4E02` è risolta dal pool **`0x7D5148 = 0x1453E4`**; r0=87,r1=0. Il descrittore87 ha nome interno **AutoSceneLiveView**, non “SD Life”: l'etichetta della voce descrive l'azione precedente alla navigazione. `0x7D58D8` deve quindi essere isolata prima di una simulazione del solo menu.

Per LV/QV/FR i puntatori dei pool sono rispettivamente `0x12EEA4 →0x366920`, `0x19307C →0x3681E0`, `(0x1BCFC6&~3)−187*4 =0x1BCCD8 →0x368790`. Gli store sono verificati; l'effetto dei successivi consumer, la persistenza e il significato GTE non sono provati. Nessuna prestazione o compatibilità hardware dedotta.

## Continuazione

Controllare gli endpoint persistenti con stub nel simulatore e registrare selector/offset/length/buffer; non eseguire le azioni diagnostiche sul dispositivo. In particolare restano aperti controller NAND, mapping dei volumi, C9D84/reset, SD Life, writer di stato indiretti e sottoalberi calibrazione/debug. La lista U costituisce il limite esplicito dell'audit statico, non una certificazione di sicurezza.

# Nuove prove salvate prima dello stop — 19 ottobre 2026

Lavoro sospeso su richiesta dell'utente dopo il salvataggio. Le prove sono statiche sul campione V1.1; nessuna funzione Nikon è stata eseguita e nessun firmware è stato modificato.

## SD Life: scrittura persistente richiesta

La voce SKY con dato0 entra in `0x7D58D8`. A `0x7D5B44` apre un file con modo2 e nome costruito dal formato `%s\Test%d.log` (pool `0x7D5D48 → 0x98CE85`). A `0x7D5B60` chiama la scrittura `0x12DE3C`; a `0x7D5BC8/0x7D5C84` rilegge con `0x12D530`, confronta con `0x32E508` a `0x7D5CAA` e può ripetere dal salto `0x7D5CDE → 0x7D59E8`. Il contatore a `0x899BA4` viene incrementato a `0x7D5CD4`. Classificazione aggiornata: **P, richiesta di scrittura persistente**, con completamento fisico non provato.

La routine usa anche il percorso `A:` e i messaggi `Format card ...` / `Format Err=%X`; chiama `0x21C420` a `0x7D5A12`. Quest'ultima inoltra la richiesta `0x2018` a `0x1F2348`, che chiama indirettamente il campo+0x1C della tabella del dispositivo. L'endpoint runtime di questa richiesta resta da risolvere: la prova di scrittura file non dipende dall'interpretazione del messaggio di formato.

Fonti: [GNU della routine](../S33-sections/analysis_codex/evidence/007d58d8_sd_life_full_code.txt), [coda dopo il pool](../S33-sections/analysis_codex/evidence/007d5d80_sd_life_tail.txt), [JSON con stringhe e chiamate](../S33-sections/analysis_codex/evidence/storage_followup.json).

## Collegamento al livello MMIO

Nel ramo di aggiornamento partizione0: `0x1EE0FA → 0x2606B4 → 0x260624 → 0x25E0A4`. La routine `0x260624` carica byte dal buffer a `0x26063A` e li passa nel delay slot al writer; `0x25E0B0` esegue `sth.di r0,[r1]`, con r1 dal pool `0x25E0AC = 0x0FF05000`.

Il wrapper comandi `0x25CB3C` usa lo stesso porto tramite `0x25E064/0x25E070`; il chiamante prepara0x80 a `0x2606DA` e0x10 a `0x260786`. `0x25DF24/4C` modificano i bit8/9 del controllo `0x0FF04020`. Sono istruzioni statiche e accessi espliciti: sostengono la categoria F, possibile scrittura NAND/flash. Non provano il modello del chip, la temporizzazione o il completamento di erase/program.

Fonti: [caricamento byte e invio](../S33-sections/analysis_codex/evidence/00260624_storage_data_output_loop.txt), [store MMIO riancorato](../S33-sections/analysis_codex/evidence/0025e0b0_data_port_store.txt), [controllo comandi](../S33-sections/analysis_codex/evidence/0025df24_command_enable_bits.txt).

## Stato di attivazione: ricerca nei16payload

Scansione separata dei16payload, comprese le residenze sovrapposte11–15: un solo candidato di chiamata diretta al setter `0x129904`, a `0xC5DE8`, verificato nuovamente con r0=1; unica occorrenza LE32 del pointer `0x366880` nel pool `0x12991C`.

Tre coincidenze del pattern halfword-swapped del setter nel blocco09 non dimostrano chiamate. La scansione lineare produce anche falsi salti da dati; non esclude scrittori indiretti, gp-relative o indirizzi calcolati. Non è una prova che lo stato resti sempre1 dopo il boot.

Fonti: [ricerca riproducibile](../S33-sections/analysis_codex/sweep_activation_references.py), [risultati e limiti](../S33-sections/analysis_codex/evidence/activation_reference_sweep.json), [writer riancorato](../S33-sections/analysis_codex/evidence/000c5ddc_writer_reanchored.txt).

## Callback di ingresso, uscita e navigazione

| Menu / evento | Callback | Classe locale | Prova e limite |
|---|---|---|---|
|4A /4405|0x7D417C|R + U|Store guardia+4 a7D4198 e pointer lista a7D41A0; chiamate12DF54/129888 e cambi modalità. Effetti transitivi non tutti chiusi.|
|4A /4406|0x7D4330|R + U|169FBC(1),143AFC(1C); chiusura non certificata come priva di effetti.|
|4A /440C|0x7D4354|R + U|23D478 e azzeramento flag a7D43EC; renderer non chiuso.|
|4A /0580|0x7D4400|R + U|7D4928, poi byte contesto+8 da1 a2 a7D4424.|
|4A /0480|0x7D442C|R + U|1453E4(20,0) a7D4444; ciclo vita dell'oggetto successivo.|
|4B /4405|0x7D49DC|R + U|Preparazione lista e riscrittura etichette aitem+0C; chiamate e cambi modalità da chiudere.|
|4B /4406|0x7D4C5C|R + U|169FBC(1),143AFC(1C), analoghi a4A.|
|4B /440C|0x7D4C80|R + U|23D478 e azzeramento flag a7D4D18.|
|4B /0580|0x7D4D2C|R + U|7D5240, poi byte contesto+6 da1 a2 a7D4D50.|
|4B /0480|0x7D4D58|R + U|Apre20 sotto guardia provenienza; altrimenti evento4002/dato16.|
|4A/4B default|0x20E814|U|Delega alla tabella comune; effetti transitivi non chiusi.|

R indica modifiche RAM osservate; U conserva gli effetti dei chiamati ancora aperti. L'ingresso nei menu non è certificato come privo di effetti persistenti.

**Correzione della sintesi precedente:** il nome “chiusura file” attribuito a `0x12DF54` non era provato. Il corpo osservato modifica flag del contesto, chiama `0x5FE90C` e programma un evento; è ora descritto come routine di flag runtime, con effetti transitivi aperti. `0x129888` costruisce uno snapshot INFO nel buffer fornito, senza provare un reset della memoria persistente.

## Controlli effettivi e punto di ripresa

Eseguiti `python3 S33-sections/analysis_codex/sweep_activation_references.py` e `python3 S33-sections/analysis_codex/audit_storage_followup.py`:16identità payload e16roundtrip ELF;23finestre e40istruzioni controllate; stringhe, pointer, loop file e store MMIO verificati. [Evidenza del secondo controllo](../S33-sections/analysis_codex/evidence/storage_followup.json). I due hash firmware sono rimasti invariati.

Alla ripresa: risolvere l'endpoint runtime della richiesta2018 e gli effetti dei callback di inizializzazione/chiusura. Se si passa al simulatore, intercettare le richieste storage. Nessuna compilazione dell'emulatore svolta. Nessun processo di analisi resta da attendere.
