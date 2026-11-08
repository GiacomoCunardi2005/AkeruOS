# AkeruUSB: apertura endpoint e allocazioni

26 ottobre 2026. **90 casi CPU GNU PASS**, 778.286 istruzioni, uscita zero,
nessun fault e nessuna segnalazione di lettura da memoria non dichiarata.
Questa tappa collega apertura, submit e preparazione originale del controller
in un unico banco, chiarendo quale allocazione riguarda il payload.
Il software di dump RAM completo resta da collegare e verificare.

Riproduzione: `make -C AkeruOS usb-ram-open-buffer-verify`.
Sorgenti: `Python_Trace_Scripts/s33_verify_akeru_usb_open_buffer.py`,
`AkeruOS/tests/usb_open_buffer_gnu_test.c`; target aggiunto ad `AkeruOS/Makefile`.
Evidenza: `Risultati/AkeruUSB_RAM_Debug/Open_Buffer/20261026T130945Z/verified_evidence.json`.
Il puntatore `Open_Buffer/latest.json` individua il risultato PASS.

## Catena eseguita e confini

Sono eseguite istruzioni originali V1.1, senza patch al firmware:

| Corpo originale | Evidenza CPU |
|---|---|
| `0x278F30`, inizializzazione record endpoint | 90 ingressi; lista vuota, proprietario, numero/direzione e campi iniziali |
| `0x27864C` → `0x2792D0`, apertura | 90 ingressi ciascuno; descrittore USB, associazione endpoint e maxpacket |
| `0x278854` → `0x279658`, submit/coda | 41 ingressi al wrapper; 40 successi e un fallimento allocazione |
| `0x2DBFB8`, preparazione controller | 40 ingressi dalla catena submit originale |
| `0x278F0C` → `0x243BC8`, wrapper allocazione ausiliaria | 13 ingressi ciascuno; 12 successi e un fallimento |

Sono originali anche ricerca del record `0x279488`, helper bitfield,
divisione, moltiplicazione e prologhi/epiloghi. Sedici intervalli sono estratti
dai payload verificati e riestratti dall'ELF di prova con confronto SHA256.
Identità firmware e 16 payload verificate. Il controllo finale ha verificato
73 file dell'evidenza, 21 input e l'hash della traccia decompressa.

**Sono fixture** allocatore `0x243A0C`, risorse `0x1593AC/0x1594A4`, logging,
configurazione endpoint del controller `0x2DBCF8` e helper di registro
`0x243B2C/0x243B6C/0x243BA8`. Questi ultimi registrano richieste senza
dereferenziare MMIO. La configurazione restituisce volutamente 999, ignorato
dal chiamante originale in questi casi; non dimostra configurazione fisica.

Parent, controller, tabelle, endpoint, descrittore USB, request, stack e buffer
di 1024 byte sono predisposti. L'allocatore restituisce slot sintetici di
512 byte anche per la richiesta di 32: le dimensioni richieste sono osservate,
la geometria e l'implementazione dell'allocatore reale restano ignote.
La RAM GNU sintetica di 128 MiB non è una mappa fisica Nikon. Il modello DSP
GNU già esistente è provvisorio e non misura il silicio Nikon.

## Allocazioni distinte dal payload

1. L'apertura legge byte2 del descrittore USB e ne trasferisce bit7 nel bit8
   del record controller; legge maxpacket dai byte4/5 e tipo dai bit0/1 di
   byte3. Il wrapper registra maxpacket a endpoint+20.
2. Con controller+99 nonzero e tipo diverso da 1, l'apertura chiama
   `0x278F0C(record+28,64)`. Il wrapper moltiplica 64 per 8 e passa **512 byte**
   all'allocatore tramite `0x243BC8`. Il puntatore restituito è scritto sia
   a record+28 sia a record+32. È un'area ausiliaria separata dal payload;
   il suo uso scatter/gather durante il trasferimento non è eseguito qui.
3. Il submit richiede **32 byte** per il nodo di coda. Vi copia request,
   puntatori e lunghezza; non vi copia i byte del payload.
4. Nei 40 submit riusciti, request+8, nodo+4/+8 e record+24/+36/+40
   conservano il puntatore payload del chiamante. Nessuna allocazione
   aggiuntiva ne arrotonda la capacità nella catena eseguita.

Il record scelto nei casi provati è `device+0x68+(numero-1)*68` per IN e
`device+0x464+(numero-1)*68` per OUT. Sono layout software V1.1 su contesti
sintetici, non indirizzi liberi da assegnare al futuro adapter.

## Matrice e risultati

**48 aperture:** IN/OUT, numeri endpoint 1/2/15, maxpacket64/512,
controller+99 a zero/uno e tipo1/2. Le associazioni, i campi del descrittore,
il maxpacket del wrapper e le richieste di allocazione sono controllati.
Le risorse sono prese/rilasciate una volta per apertura riuscita.

**40 submit integrati:** IN/OUT, maxpacket64/512, PIO/DMA lineare,
lunghezze 0/1/32/65/513, endpoint1 e tipo2. La traccia e le asserzioni
controllano puntatori, lunghezza logica, cursori, coda, conteggio richieste,
stato pending della request e indirizzi/valori delle richieste di registro.
Tutti i 1024 byte del payload predisposto restano invariati durante la
preparazione; non viene eseguito un trasferimento USB o DMA.

Nel ramo OUT il campo byte programmato viene arrotondato al pacchetto:
**32→64 e 65→128 con maxpacket64; 32→512 con maxpacket512.** La lunghezza
logica nel nodo di coda rimane quella richiesta. I casi IN mantengono il
campo byte logico; il numero di pacchetti è arrotondato per eccesso.
La lunghezza zero al livello inferiore programma un pacchetto, come nel
banco separato della preparazione controller.

**Due fallimenti sintetici:**

- Fallimento allocazione512 all'apertura: wrapper → `-7`, nessuna chiamata
  alla configurazione controller, risorsa rilasciata. Restano già scritti
  descrittore USB, associazione endpoint e flag software; maxpacket a
  endpoint+20 resta zero. Non è un rollback completo.
- Fallimento allocazione32 al submit: wrapper → `-7`, nessuna preparazione
  controller, nessun inserimento in coda e nessuna acquisizione aggiuntiva.
  La request è già stata marcata `-10` dal wrapper prima del fallimento;
  questo stato non prova che sia stata accodata.

Non è verificato il riutilizzo di questi contesti dopo errore. Ritorno del
wrapper, campi già scritti, accodamento e disponibilità del buffer sono
condizioni distinte.

## Conseguenza per il dumper e prossima prova

Il padding del payload deve essere posseduto dal chiamante nel percorso
OUT osservato: le allocazioni da 32 e 512 byte non lo forniscono. Questo
esclude di usare quelle due allocazioni come prova che un buffer ricevente
AkeruRAM da soli 32 byte sia sufficiente. Non dimostra un overflow fisico:
il banco possiede 1024 byte, non esegue DMA e sostituisce la configurazione
controller con una fixture.

Il prossimo raccordo è seguire la provenienza e capacità dei buffer del
worker/chiamante; poi eseguire configurazione controller originale,
completamento/IRQ, short packet/ZLP, cancel e momento del rilascio. Restano
inizializzazione/dispatch live, scatter/gather, cache, residenza, whitelist
fisica RAM, avvio e recupero. Le prove worker/cancel precedenti conservano
il loro ambito e non diventano automaticamente parte di questa catena.

Il tentativo `130905Z` fallisce al link: il trampoline logging lungo
invadeva la routine originale adiacente `0x243A54`. È stato sostituito con
un branch di quattro byte. `130919Z` rileva un'aspettativa del test errata:
record+28 contiene il puntatore dell'area ausiliaria, non il conteggio64.
Corretta l'aspettativa; nessun byte Nikon o GNU modificato. Entrambi i
tentativi restano conservati come FAIL, senza pubblicazione in `latest`.

Nessun hardware, dumper, flash, NAND/vendor, reset USB o scrittura SD.
GNU e firmware originali invariati. **NON_INSTALLARE**.
