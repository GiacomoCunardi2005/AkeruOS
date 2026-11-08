# Updater SD e sopravvivenza del recupero

**Nuovo dispatch eseguito21ottobre2026:** [dieci casi](S33_NAND_PC_Dispatch_Pacchetto_Boot_Invariato_e_Contatore.md) con registrar/parser/dispatcher/callback originali e servizi inferiori registratori. Il percorso normale richiede ancheBoot invariato; una seconda chiamata diretta dopo errore può saltare componenti a causa del contatore completamenti conservato. Non certificaUI o scrittura/recupero fisico.

**Continuazione21ottobre2026:** [Main updater eseguito offline](S33_NAND_PC_Main_Updater_Rilettura_Retry_e_Limite_Recupero.md),12casi con modelloRAM: scrittura/rilettura/confronto/retry, nessun recupero fisico dimostrato. Le foto successive riportanoMAIN1.1100/BOOT0.1380: le indicazioniV1.0 sotto descrivono il checkpoint storico, non la versione oggi riferita. Dispatch completo e componentiBoot/P1RES restano da eseguire.

**Continuazione del 19 ottobre 2026.** La [verifica successiva del commit BootCode](recovery_commit_report.md) dimostra un produttore nel commit della sorgente fallback RAM 50F31A; non è prova di copia di recupero indipendente al reset. Il [decoder corretto](ALIAS_FIX_BOOT.md) amplia le porzioni di boot eseguite senza dimostrare avvio completo o recupero.

19 ottobre 2026, R4. **La sopravvivenza del recupero non è dimostrata.** La nuova analisi collega l'ingresso UI pubblico V1.1 ai writer di MainCode **e BootCode** e identifica un fallback TBIB precedente al MainCode. Il punto ignoto è ora delimitato: quale copia fisica del TBIB il reset selezioni, quali unità/metadati il writer BootCode riscriva e se una copia utilizzabile resti raggiungibile dopo un'interruzione.

La macchina dei log è V1.0: il codice dell'updater che vi gira durante un primo aggiornamento non è stato acquisito/verificato. La ricostruzione seguente riguarda il campione V1.1, SHA-256 `1d34e990a8f99019ffa53ca5de785399df863e942739a667ceb314ec6ce62a39`. Non trasferisce indirizzi o garanzie a V1.0. Tutte le prove sono statiche; nessuna operazione Nikon è stata eseguita.

## 1. Ingresso pubblico distinto dal NAND Tool

Il percorso usa il nome `B:\FIRMWARE\FIRMWARE.BIN`, getter `0xC76FC`, pool `0xC7700→0x377E23`. È coerente con la posizione documentata per l'aggiornamento ordinario [da Nikon](https://downloadcenter.nikonimglib.com/it/download/fw/193.html). Il collegamento al codice è nei descrittori e negli eventi, non nella sola presenza della stringa:

- UI firmware/versione: `0x807E9C`; il callback timer `0x8080B4` può aprire ID `0x9F` a `0x808106`.
- ID `0x9F`, descrittore `0x9A0414`, nome interno `UpgradeFirmware`, main `0x80813C`: evento `0x2180→0x80831C`; a `0x80834E/352` apre ID `0xA1`.
- ID `0xA1`, descrittore `0x9A0624`, nome `UpgradingFirmware`, main `0x8085D4`: evento `0x440E→0x8086A8`; nel ramo dato1 `0x8086D6` ottiene il filename, `0x8086DA` carica dal pool `0x808794` la callback **`0xBC3F8`**, poi `0x8086E0` chiama `0x12A794` con r0=0, r1=filename, r2=callback.

Il NAND Tool passa direttamente `0x12A9FC` o `0x12AA3C`; la UI pubblica passa invece il dispatcher `0xBC3F8`. Il raccordo fra i due non è stato assunto: `0xBBB60` prepara la registrazione dei nomi e `0xBC3A0` scrive il campo callback+`0x40` a `0xBC3E2`, in record da `0x44` byte. `0xBC478` cerca il basename; `0xBC3F8` legge la callback dal record corrispondente e la chiama a `0xBC444`. L'esecuzione effettiva dell'inizializzazione e il contenuto della tabella RAM non sono osservazioni hardware.

| Componente registrato | Sorgente nome/callback | Callback risultante | Destinazione successiva |
|---|---|---|---|
|TBM_SK501.BIN|getter `0xC76C4`, pool `0xC76C8`; callback pool `0xBBBF8`|`0x12A9FC`|guardia RHIR→`0x12AD58`|
|TBIB_SK501.BIN|getter `0xC76CC`, pool `0xC76D0`; callback pool `0xBBBFC`|`0x12AA3C`|ricerca INFO/sentinella→`0x12AE00`|
|P1RES|getter `0xC76E4`, pool `0xC76E8`; callback pool `0xBBC00`|`0x12AAA8`|`0x129460`, distinto percorso risorse|

Il registratore `0xBBB60` è chiamato a `0xC5C10` e `0xC5E08` nei corpi riancorati `0xC5BEC/0xC5DDC`; non è chiusa tutta la catena dal reset. [Dettaglio ingresso e parser](SD_ENTRY_PATH.md).

Prove riproducibili: [verificatore ingresso](../S33-sections/safety_audit_codex/sd_entry_verify.py), [JSON](../S33-sections/safety_audit_codex/evidence/sd_entry_verified.json), finestre GNU `evidence/sd_entry_*`. I menu sono identificati dai byte dei descrittori, non soltanto dal catalogo precedente.

## 2. Contenitore e ordine di dispatch

`0x12A794` carica il file; riconosce `V2.0` a buffer+4 e nel ramo contenitore confronta l'XOR32 di `[buffer+4,buffer+file_size)` con il primo word. `0x12AFF0` segue il primo descrittore da word buffer+`0x10` e i successivi tramite descrittore+`0x48`. Non è il parser dei record RHIR interni.

I descrittori del campione originale e patchato hanno quest'ordine:

| Nome nel contenitore | Offset descrittore/nome | Intervallo file dei dati | Lunghezza |
|---|---:|---|---:|
|TBIB_SK501.BIN|`0x20`|`[0x6C,0x4806C)`|`0x48000`|
|TBM_SK501.BIN|`0x4806C`|`[0x480B8,0x1114AB8)`|`0x10CCA00`|
|P1RES|`0x1114AB8`|da `0x1114B04`, lunghezza `0xB26616`|`0xB26616`|

L'XOR effettivamente verificato è `0xBD4A9BF9` per entrambi i file, uguale al primo word. È un controllo aggiuntivo ora collegato al formato reale, non una firma crittografica. Il registro r18 conta i descrittori; r16 passato come r0 alla callback non va scambiato per l'indice del componente. Le iterazioni dipendono dagli esiti: un fallimento può impedire quelle successive. L'ordine file non è prova di esecuzione completata.

**Non c'è qui una prova che il BootCode identico venga saltato.** Il dispatch seleziona per nome; la callback BootCode arriva al writer dopo i propri controlli. I confronti di lettura successivi alla scrittura non equivalgono a un confronto preventivo che eviti la riscrittura del TBIB invariato.

## 3. Writer, controlli e intervalli: ciò che è ricostruito

[Verificatore regioni](../S33-sections/safety_audit_codex/audit_sd_update_regions.py), [JSON e finestre](../S33-sections/safety_audit_codex/evidence/updater_regions.json): 14 finestre GNU, 49 istruzioni chiave, 7 destinazioni della tabella di salto riancorate, 8 controlli della sola formula di arrotondamento. Le finestre separano codice e tabella a `0x1EE77A`; una scansione lineare unica avrebbe decodificato dati come istruzioni.

- Main `0x12AD58`: chiama il validatore `0x12AEA0` prima del writer; a `0x12AD94..9C` passa selettore6, buffer, offset logico0 e lunghezza a `0x1EEA4C`. Seguono readback e confronto; il ramo di errore può riprovare fino al limite locale3.
- Boot `0x12AE00`: chiama `0x12AF8C`, prepara campi dal buffer mediante `0x1ED9CC`, quindi `0x12AE42..4A` chiama `0x1EEA4C` con selettore0 e offset0. Anche qui readback/confronto sono successivi alla richiesta di scrittura e non costituiscono rollback.
- `0x1EEA4C` arrotonda la lunghezza a settori512, acquisisce sincronizzazione e chiama `0x260FE4`; il tratto centrale passa unità da2048 byte a `0x1EE730`. Il preparatore può effettuare operazioni di lettura/modifica/scrittura per pagine parziali prima del corpo centrale; quindi non va ignorato quando si delimitano gli effetti.

Con `G = 0x50F52C` (getter `0x25CAEC`, pool `0x25CEC4`) e `D = 0x50F420` (getter `0x25C020`, pool `0x25C3A0`), nel ramo iniziale del dispatcher `0x1EE730`:

| Selettore | Entrata case | Base | Capienza |
|---|---|---|---|
|0 BootCode|`0x1EE782`|`u16(D+0xC4) * u8(G+5)`|`u16(D+0xD2) * u8(G+5)`|
|6 MainCode|`0x1EE874`|`u16(D+0xD0) * u8(G+5)`|`u16(D+0xDE) * u8(G+5)`|

Queste sono quantità nel dominio del driver prima del mapping inferiore, **non intervalli fisici NAND in byte**. A `0x1EE958..974` il controllo considera offset e conteggio, con divisione per `u8(G+0x10)<<9` e arrotondamento se c'è resto, prima di scegliere il backend `0x1EDED8` oppure `0x1EDFDC`. Esistono anche rami condizionali di metadati/rimappatura: le formule iniziali non sono un invariante completo del supporto.

I valori delle strutture G/D non sono nei payload TBM verificati: sono dati runtime. Non si può sostituire una loro lacuna nella mappa con zeri, né dedurne la disgiunzione Boot/Main. Nel dominio logico del writer, il pacchetto contiene `0x48000` byte BootCode e `0x10CCA00` byte MainCode a offset0; l'inviluppo a pagine2048 del secondo è `0x10CD000`. Questo inviluppo **non descrive blocchi fisici cancellati**, spare, copie ridondanti o bad-block mapping. La granularità effettiva di erase e le copie selezionate restano ignote.

## 4. Candidato di caricamento alternativo nel TBIB

La prova nuova sul boot è in [boot_recovery.md](boot_recovery.md), [script](../S33-sections/safety_audit_codex/boot_recovery.py), [JSON](../S33-sections/safety_audit_codex/boot_recovery_evidence.json), [GNU](../S33-sections/safety_audit_codex/boot_recovery_gnu.txt): identità TBIB e 16 payload, checksum, roundtrip ELF, 11 finestre/43 istruzioni/17 parole/7 stringhe.

Il BootTask `0x01001384` è nel TBIB e può tentare sorgenti alternative prima del MainCode: tentativo B anticipato sotto guardie; lettore a settori `0x010010C0`; su errore file `A:\TBM_SK501.BIN`; se fallisce, byte `0x01041105==1` e guardia `0x01000488!=0` permettono `B:\TBM_SK501.BIN` tramite `0x0100125C`. Nel payload i byte `0x01041104/105` valgono0/1, ma l'init può cambiarli in1/0. Non sono valori RAM misurati.

Il lettore attende **RHIR all'inizio del file** e carica i record/ingresso. Non accetta per questa sola proprietà il contenitore pubblico `firmware.bin`, che ha RHIR a offset `0x480B8`. Non si propone di creare file o marker su una SD. Mappa fisica A:/B:, backend della guardia, init e disponibilità dei driver rimangono da dimostrare.

## 5. Punto ignoto preciso e decisione

Il codice prova un **candidato precedente al MainCode**, ma non un recupero **preservato** dall'aggiornamento. Mancano tre raccordi concreti:

1. **Reset/ROM→copia TBIB:** indirizzo/supporto/copia selezionati prima di `0x01000000` e ogni dipendenza da metadati riscritti. Il file distribuito non include una prova della boot ROM residente.
2. **Writer selettore0→unità fisiche/copie/metadati:** valori e origine delle strutture `0x50F420/0x50F52C`, mapping inferiore e selezione delle copie. Il ramo pubblico può arrivare al writer BootCode; non è dimostrato che una copia indipendente sopravviva quando si interrompe questa fase.
3. **TBIB superstite→sorgente alternativa realmente utilizzabile:** condizioni/driver/guardia `0x01000488→0x01007168→0x0101FCC4`, filesystem e trasferimento al MainCode, poi disponibilità del ripristino persistente. Il solo caricamento alternativo non è una procedura di reflashing.

Si aggiunge il limite di versione: per la macchina V1.0 mancano i corrispondenti byte dell'updater/TBIB residente. Non si attribuiscono alla macchina gli indirizzi V1.1.

**Esito della verifica prioritaria:** collegata la catena statica pubblica ai writer e alle regioni logiche; identificati precisamente i raccordi ancora ignoti. La preservazione non è provata e il NO-GO resta. Il prossimo punto utile è l'origine/selezione fisica del BootCode nel ramo selettore0, da raccordare al reset e alle eventuali copie alternative; ampliare l'emulatore non risolve questa lacuna.

Riproduzione: `python3 S33-sections/safety_audit_codex/run_audit.py` per l'audit complessivo, oppure i tre verificatori qui collegati per le sole nuove prove. Hash e istruzioni sono conservati nelle evidenze. Nessun accesso USB, SD o memoria della macchina; nessun firmware modificato. AkeruOS circa10% funzionale, invariato.

## Verifica successiva richiesta sulla variante CMP3

Il [nuovo controllo boot/ripristino CMP3](CMP3_BOOT_RESTORE.md) usa il campione con confronto3, verificato dai byte.25scenari P-code registrano21confini corretti e4limiti del modello; una prova isolata conferma un difetto `ld.ab` con alias nel decoder, riscontrato con GNU ARC700/QEMU. Nessuna conclusione di mancato boot va ricavata dal PC0 emulato. Nuove14finestre/71istruzioni dei backend BootCode restringono origine dei metadati e aggiornamento della mappa, ma non provano una copia recuperabile dopo interruzione. Il linguaggio non è stato modificato; firmware e hardware invariati. NO-GO flash confermato.
