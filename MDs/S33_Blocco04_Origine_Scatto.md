# S33 — blocco 04, richieste JPEG e confine S2

Analisi statica del 17 ottobre 2026. Questo rapporto separa ciò che le istruzioni mostrano da ciò che resta da attribuire alla modalità utente. Il campione è `block_04_type0_load_00796800.bin`, base `0x796800`, dimensione `0x100200`, SHA-256 `c77ef77d465b128843d669012965c146a3ac1bdca0b4ac2ebd6203f1e3644605`.

## Risultato

Le chiamate `0x81B72E` e `0x81BDFE` inviano una richiesta JPEG di tipo 1 a `0x126DD8`. La chiamata `0x81C1A0` non invia direttamente JPEG: passa un payload al wrapper `0x8116CC`, che costruisce una richiesta per il gestore immagini e ne attende il completamento.

Nessuno dei tre percorsi è collegato staticamente al pulsante fisico S2, alla foto normale, alla foto nel video o all'anteprima. I valori 640 e 480 osservati in tutti o parte dei payload non sono una prova della modalità né della risoluzione finale JPEG.

| Sito | Funzione contenente | Osservazione verificata | Classificazione |
|---|---:|---|---|
| `0x81B72E` | `0x81B486..0x81B76E` | `bl 0x126DD8`; passa `fp - 0x30` | produttore JPEG tipo 1; modalità indeterminata |
| `0x81BDFE` | `0x81BB56..0x81BE2A` | `bl 0x126DD8`; passa `fp - 39` | produttore JPEG tipo 1; modalità indeterminata |
| `0x81C1A0` | `0x81BFE4..0x81C226` | `bl 0x8116CC` con `fp - 840` | invio payload al gestore immagini; modalità indeterminata |

## I due produttori JPEG

### A — `0x81B486..0x81B76E`

Il ramo con `r0 == 0` a `0x81B4B0` torna senza inviare una richiesta. Nel ramo che arriva al sito, il codice prepara un'area locale contigua a partire da `fp - 0x30`, inclusi i valori 640 e 480 alle mezze parole `-0x18` e `-0x16`. Dopo `0x81B72E`, se l'invio riesce, chiama `0x15A5C8` e poi `0x13C730`.

Le routine precedenti `0x14BF98`, `0x8126B0` e `0x13B5F4` fanno parte della preparazione osservata. Non è stata assegnata un'ABI al payload oltre alle scritture viste nelle istruzioni.

### B — `0x81BB56..0x81BE2A`

Questo percorso filtra un valore di stato prima di proseguire e, in un ramo, usa `0x14C45C`, `0x8126B0` e `0x13B5F4` prima dell'invio. A `0x81BDFA` passa `fp - 39` a `0x126DD8`; il valore è un immediato in byte, non un offset moltiplicato per quattro.

Il frame contiene anche accessi ARC `.as` scalati, che toccano un'altra area del frame. Non è dimostrato che inizializzino direttamente l'oggetto passato a `fp - 39`; quindi B non va descritto come una copia del layout A. Dopo l'invio non chiama localmente `0x15A5C8`: su errore condizionale usa `0x81A9B8` e segnala il codice `0x16` a `0x12A738`.

## Il terzo sito e il wrapper

La funzione `0x81BFE4..0x81C226` crea il payload `P = fp - 840`. Prima di `0x81C1A0` scrive 640 e 480 in `P + 24` e `P + 26`, allinea un valore a 16 byte e popola altri campi fino a `P + 38`; la semantica dei campi non è stata attribuita.

`0x8116CC..0x811712` costruisce quattro parole locali osservate `{1, P, 0x1E77C8, 0}`, chiama `0x13B198`, quindi `0x15A570`; se questa restituisce zero, attende con `0x15A5C8`. Questo dimostra il passaggio di un payload e della callback `0x1E77C8` al gestore immagini. Non dimostra il salvataggio finale su SD o l'origine della richiesta.

La scansione dei 16 blocchi trova come chiamanti diretti in contesto codice della funzione `0x81BFE4` sette siti nel blocco 06: `0x9D298A`, `0x9D29AE`, `0x9D4A84`, `0x9D4A90`, `0x9D64AC`, `0x9D64CE` e `0x9E1CC0`. Appartengono a quattro funzioni: `0x9D291C`, `0x9D47F4`, `0x9D6324` e `0x9E1C04`. Ognuna sceglie una o due varianti di parametri tramite byte o valori geometrici del proprio contesto; nessuna contiene nel tratto esaminato un marcatore S2, una chiamata a CapMgr o una stringa affidabile che la classifichi come foto, video o anteprima. Per A e B non sono emerse chiamate dirette `bl`/`bl_s` né parole assolute little-endian ai loro entry point. Questo non esclude tabelle, chiamate indirette, indirizzi calcolati o codice non presente nel campione.

## Il punto raggiunto su S2

Aggiornamento del 18 ottobre: il [rapporto sui nuovi marcatori](S33_S2_Marcatori_e_PTP_Vendor.md) ricostruisce sei siti `0xB00106 = S2 event`, l'evento interno `0x100` di CaptureLiveview e un collegamento con la catena immagini PTP. Non risolve ancora l'origine fisica del pulsante. Il marcatore `0xB80021` discusso qui sotto è distinto.

Nel blocco 02 è stata verificata questa sequenza di marcatori diagnostici:

```text
0x65F230: bl.d 0x12CAD4, con 0xB80022 = Recorder Capture Image Start
0x65F262: bl   0x1B9EA8, ingresso noto verso CapMgr
0x65F268: bl.d 0x12CAD4, con 0xB80023 = Recorder Capture Image End
```

La sequenza dimostra che un percorso di acquisizione avvolge una chiamata a CapMgr con i marcatori di inizio e fine della cattura. Non mostra chi emette `0xB80021` (`S2 ISR CallBack`) né collega l'interrupt fisico a questo percorso. Non è quindi sicuro riusare ancora questo punto come comando di scatto per un firmware nuovo.

La funzione contenente il tratto è `0x65ED6C..0x65F45A`. Nel blocco 03, la tabella a `0x783D9C` contiene la sequenza osservata `0x4405, 0x65ED6C, 0x4406`; la stringa a `0x783E0C` è **CaptureImage**. Questo attribuisce il ramo a un handler registrato chiamato CaptureImage, senza dimostrare il formato della tabella o l'origine del suo invocatore. Il ramo dei marcatori è selezionato soltanto quando il byte al contesto `0x681FF0 + 0x1D` vale `0x0A`.

Nei 16 blocchi validi non compare una parola raw little- o big-endian `0x00B80021`. È una ricerca negativa limitata alla rappresentazione del valore: non esclude un marcatore costruito a runtime o un percorso non presente nel campione.

## Call graph riproducibile

Lo [script](../outputs/trace_s33_block04.py) verifica lunghezza e SHA-256 dei 16 blocchi validi del manifest, crea ELF temporanei con round-trip byte per byte e scansiona le chiamate `bl`, `bl.d` e `bl_s` di GNU ARC. La [mappa](../outputs/s33_block04_callgraph.json) riporta cinque candidati diretti a `0x126DD8`: `0x127DE2`, `0x81B72E`, `0x81BDFE`, `0x9D898C`, `0x9DC328`. Le [finestre disassemblate](../outputs/s33_block04_disassembly.txt) contengono i controlli puntuali sopra descritti.

La prima riproduzione controllata REA è nel [bundle iniziale](../outputs/s33_rea_block04_evidence.json), record `ev_8fd439d02d0bc48b111e6fd81ec412d4349379dbfa95bc2e1f9c17a12a184ade`. Il [bundle CaptureImage](../outputs/s33_rea_block04_captureimage_evidence.json), record `ev_429e3bf7551ac967786a20219dcb75790448b4b1668ffc2604b19da0d530679f`, verifica anche la tabella e l'assenza raw del marcatore S2; entrambi i processi sono terminati con codice 0. Il tracciatore JPEG precedente usa ora il campione locale del progetto: [trace_s33_jpeg.py](../outputs/trace_s33_jpeg.py).

## Limiti e prossimo punto utile

La scansione lineare individua soltanto chiamate dirette candidate: non recupera chiamate indirette, salti di coda, tabelle o codice caricato a runtime. L'analisi non ha eseguito, modificato o installato firmware, né usato la fotocamera.

Il prossimo collegamento utile è seguire la provenienza del chiamante del blocco 02 che emette i marcatori e determinare se vi è una transizione osservabile dal gestore dell'interrupt S2 alla richiesta CapMgr. Solo dopo quel collegamento si potrà scegliere un confine riusabile per lo scatto essenziale.
