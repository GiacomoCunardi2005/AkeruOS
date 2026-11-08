# AkeruUSB: preparazione controller e capacità dei buffer

26 ottobre 2026. Proseguita la ricerca del software di dump RAM tramite il
servizio USB dedicato scelto il 24 ottobre. **290 casi CPU GNU PASS**, 429.596
istruzioni, uscita zero e nessun fault, sulla routine originale `0x2DBFB8`.
Il collegamento completo del servizio alla fotocamera resta incompleto.

Riproduzione: `make -C AkeruOS usb-ram-controller-start-verify`.
Sorgenti: `Python_Trace_Scripts/s33_verify_akeru_usb_controller_start.py` e
`AkeruOS/tests/usb_controller_start_gnu_test.c`.
Evidenza: `Risultati/AkeruUSB_RAM_Debug/Controller_Start/20261026T123528Z/verified_evidence.json`;
puntatore riproducibile: `Controller_Start/latest.json` nella stessa radice.

## Punto di partenza verificato

Il rapporto worker del 24 ottobre descriveva 44 casi più due polling limitati.
L’evidenza corrente `Worker/20261024T154705Z` include anche **16 casi endpoint**:
costruttore vtable, submit/coda, cancel/rimozione e callback rientrante. La
vtable installa submit `0x278854` e cancel `0x278930`. Il loro confine inferiore
`0x2DBFB8` era ancora una fixture `ep_start`; il nuovo banco esegue quel corpo
originale. Non riesegue l’intero worker né collega automaticamente i due banchi.

Sono istruzioni Nikon inalterate la preparazione controller, prologhi/epiloghi,
helper dei bitfield, divisione e moltiplicazione. Undici intervalli originali
sono estratti dai payload verificati, collocati agli indirizzi V1.1 e riestratti
dall’ELF di prova con confronto SHA256. Firmware e 16 payload sono verificati.

Sono fixture i tre helper di registro `0x243B2C` (lettura), `0x243B6C`
(scrittura) e `0x243BA8` (richiesta di modifica). Registrano indirizzi/valori,
senza dereferenziare MMIO. Controller, descrittore, flag, registro globale,
stack e buffer sono predisposti. Il banco sintetico di 128 MiB non prova una
mappa RAM fisica. La moltiplicazione usa il modello DSP GNU provvisorio già
esistente; non è una misura del comportamento numerico del silicio Nikon.

REA 6.3.0 ha rifiutato l’ELF ARC con `unsupported ELF architecture`; la risposta
è conservata in `Controller_Start/rea_admission_20261026.json`. Sono quindi
usati disassemblatore e CPU GNU esistenti, senza installare o cambiare provider.

## Risultati

La matrice contiene 288 combinazioni: due rami bit8, PIO/DMA lineare, pacchetto
64/512, seed registro 0/0xA5A55A5A, cursore iniziale 0/7 e lunghezze
0/1/17/63/64/65/511/512/513. Due casi aggiuntivi verificano il gate del ramo
bit8=1 e la richiesta di modifica registro con flag software zero.

Il costruttore originale `0x2792D0` legge byte2 del descrittore endpoint,
estrae bit7 a `0x279330` e lo trasferisce nel bit8 del record tramite helper
`0xB18AC`. Questo raccordo è **statico**, ancorato ai byte originali e alle
chiamate; l’apertura dell’endpoint non è eseguita dal nuovo banco.
Nel formato del descrittore USB il ramo bit8=0 corrisponde a OUT, bit8=1 a IN.
La corretta inizializzazione del contesto live resta da dimostrare.

| Operazione nel banco | Risultato verificato |
|---|---|
| Ramo bit8=1, lunghezza positiva | Campo byte uguale ai byte pendenti; pacchetti arrotondati per eccesso |
| Ramo bit8=0, lunghezza positiva | Campo byte e cursore preparato arrotondati al multiplo del pacchetto |
| Lunghezza zero al livello inferiore | Un pacchetto; campo byte 0 nel ramo bit8=1, maxpacket nel ramo bit8=0 |
| DMA lineare | Richiesta di scrittura del puntatore buffer nel registro endpoint+0x14 |
| Gate bit8=1 disabilitato | Una lettura, zero scritture/modifiche; il cursore non avanza |
| Valori seed nonzero | Conservati i bit fuori dai campi aggiornati nei registri predisposti |

Le richieste di scrittura del controllo endpoint sono distinte dalla scrittura
successiva al registro condiviso nel ramo bit8=1. Il primo tentativo di oracolo
ne accorpava erroneamente due: la traccia mostra entrambi, e sono state corrette
soltanto le aspettative del test. Nessuna istruzione Nikon è stata cambiata.
Il tentativo iniziale di compilazione usava una divisione C non risolta:
l’oracolo ora usa shift per i due pacchetti potenza di due. I tentativi falliti
restano conservati senza puntatore `latest` né stato PASS.

## Conseguenza per il servizio RAM

**65 byte logici con maxpacket64 diventano 128 byte programmati nel ramo OUT.**
La matrice verifica anche che il campo capacità del descrittore resti al valore
iniziale, mentre il cursore preparato può superarlo dopo l’arrotondamento.
Non è una prova di overflow reale: il chiamante potrebbe possedere già un
buffer arrotondato, e nel banco non avviene DMA.

Il futuro adapter deve distinguere lunghezza logica, capacità posseduta e
conteggio effettivo. Per esempio, la richiesta AkeruRAM di 32 byte richiede di
verificare una capacità ricevente di almeno un pacchetto nel percorso qui
osservato, anziché assumere che 32 byte allocati bastino a ogni backend.
Letture o scritture di registri richieste, ritorno della funzione, payload
ricevuto e restituzione dell’ownership rimangono eventi distinti.

Il nucleo `usb_ram.c` elabora frame completi in un task e non è un driver
asincrono: questo risultato non dimostra un suo overflow. Nessun binding verso
gli endpoint originali viene introdotto prima di averne chiuso capacità e
lifetime. Il client host già legge buffer arrotondati al pacchetto; ciò non
dimostra la capacità del buffer sul dispositivo.

I sedici word sentinella campionati nel buffer rimangono invariati. Questo
controlla l’assenza di copie in quei punti durante la preparazione; non prova
assenza di DMA, cancellazione fisica o integrità di tutta la RAM.

## Stato e prossime prove

Il protocollo/client e il nucleo C mantengono le loro evidenze separate del
24 ottobre. Questa tappa aggiunge la preparazione dei registri richiesta dal
codice originale, senza attestare boot o trasporto USB completo.

Prossimo: seguire l’apertura endpoint originale e le allocazioni per stabilire
la capacità effettiva dei buffer; quindi completamento/IRQ, short packet/ZLP,
annullamento e momento del rilascio. Restano scatter/gather, scheduler/dispatch,
inizializzatore dedicato, residenza, whitelist fisica RAM e avvio/recupero.

Nessun hardware, dumper, flash, NAND/vendor, reset USB o scrittura SD.
GNU e firmware originali invariati. **NON_INSTALLARE**.
