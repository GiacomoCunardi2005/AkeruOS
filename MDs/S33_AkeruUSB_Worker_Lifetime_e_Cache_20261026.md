# AkeruUSB: buffer del worker, callback e durata dei nodi

26 ottobre 2026. **52 scenari CPU GNU PASS**, 578.757 istruzioni, exit0,
nessun fault né lettura da memoria non dichiarata. Il nuovo banco collega
worker, apertura, submit, preparazione controller, ponte callback e
rimozione/liberazione del nodo. I completamenti sono input sintetici e non
provengono da IRQ o DMA della fotocamera. **NON_INSTALLARE**.

Riproduzione: `make -C AkeruOS usb-ram-worker-lifetime-verify`.
Sorgenti: `Python_Trace_Scripts/s33_verify_akeru_usb_worker_lifetime.py` e
`AkeruOS/tests/usb_worker_lifetime_gnu_test.c`. Il test C include e riusa
fixture, inizializzazione e controlli di `usb_open_buffer_gnu_test.c`, che
resta invariato. La sua precedente matrice90 non viene rieseguita qui.

Evidenza: `Risultati/AkeruUSB_RAM_Debug/Worker_Lifetime/20261026T131840Z/verified_evidence.json`;
puntatore: `Worker_Lifetime/latest.json`. Verificati hash di84file,22input,
19intervalli originali estratti/riestratti dall'ELF e traccia gzip lossless.
Firmware e16payload verificati; GNU e firmware originali invariati.

## Provenienza del buffer: precisazione dell'analisi statica

Il livello superiore conserva il buffer ricevuto inr1, senza sostituirlo nei
corpi esaminati: receive`1906B4` lo pubblica a record`423C00+20` a`190752`;
send`1908DC` lo pubblica a record+0 a`19096E`. I produttori del worker
`190DAC/190EA4` preparano la request con `buffer+count` e
`min(total-count,globale3680A0+4C)`. Il limite di blocco non è una prova della
capacità posseduta dal buffer e nel nuovo banco è predisposto a64/512.

La funzione`17FAF8`, descritta in precedenza come confine di «registrazione
buffer», **seleziona operazioni cache**. Nel ramo con indirizzo e lunghezza
diversi da-1 chiama`26E654`; quest'ultima allinea l'inizio con
`address & FFFFFFC0`, procede a passi di64 fino a`address+length-1` e chiama
`26E64C`, che esegue `sr r0,[dc_fldl]`. Il caso(-1,-1) arriva invece a
`26E640`, che esegue `sr 1,[dc_flsh]`. Nomi AUX dal disassemblatore GNU.

Questa è **analisi statica**, conservata in`buffer_provenance_static.txt`:
non vengono eseguite queste operazioni cache dal nuovo banco, non se ne
misura il completamento sul silicio e non si dimostra coerenza DMA.
L'allineamento a64 non alloca padding e non aumenta la capacità del payload.
Non si attribuisce un'allocazione implicita agli altri servizi esterni senza
seguirli. La provenienza fisica e la capacità iniziale del buffer del futuro
adapter AkeruRAM restano da stabilire.

## Catena CPU e limiti

Sono byte originali i costruttori/apertura già provati, i produttori
`190DAC/190EA4`, il submit`278854/279658`, la preparazione`2DBFB8`,
il ponte`278AA4`, i callback worker`190E1C/190F10`, la rimozione`2794D0`,
il cancel endpoint`278930/279904`, il pubblicatore`190D54` e gli helper.

Le vtable sono predisposte: endpoint+16→`278854`, endpoint+20→`278930`,
device-vtable+12→`278AA4`. Non è provata la loro installazione live.
Il record superiore è inizializzato dal banco; il livello send/receive
superiore non viene eseguito nella nuova matrice. Il completamento normale
entra direttamente in`2794D0` con lock acquisito dalla fixture e count/status
iniettati. Il cancel entra invece dal wrapper originale`278930`.

Restano fixture configurazione controller`2DBCF8`, allocatore/free,
acquire/release, helper registri, logging ed event-set. Nessun registro MMIO
fisico viene dereferenziato e nessun payload viene trasferito. Stack,
contesti,1024byte payload e RAM128MiB sono sintetici; la moltiplicazione usa
il modello DSP GNU provvisorio esistente. Non sono prove di mappa fisica,
timing, IRQ, cache reale, trasporto USB, scheduler o boot.

## Risultati della matrice

Ogni caso usa endpoint1 bulk, IN/TX oppure OUT/RX, packet64/512 e PIO/DMA
lineare. Otto combinazioni per ciascuno dei primi sei scenari, quattro per
l'ultimo, applicabile solo aRX:

| Scenario | Esito osservato nei corpi originali |
|---|---|
| Richiesta32, actual32 | Count32, done1, coda vuota, vecchio nodo liberato |
| Totale packet+32, primo blocco packet, actual17 | Count17, done1 per short, coda vuota |
| Stessa richiesta, actual0 | Count0, done1 per short, coda vuota |
| Primo blocco intero, totale packet+32 | Countpacket, nuova request32 a buffer+packet, done0 |
| Cancel endpoint con actual17 | `-1008` inferiore tradotto in`-54`; request.actual17, count worker0, done0 |
| Actual33 iniettato su request/total32 | Count33, underflow del restante e nuova request grande packet a buffer+33; done0 |
| RX con flag extra, totale/actualpacket | Flag extra cancellato, nuova request1 allo **stesso puntatore iniziale**, countpacket, done0 |

L'oversized è deliberatamente impossibile, non osservato sulla periferica:
verifica che il ponte non aggiunga un controllo di limite prima del worker.
Il caso RXextra non prova ZLP fisico e non viene fatta una seconda ricezione:
non è verificato quale dato arriverebbe al buffer in quella richiesta.

Ingressi verificati in traccia:52aperture,52submit iniziali,
20submit rientranti,52preparazioni controller,52ponti callback,
52rimozioni/liberazioni e8cancel. Tutti i1024byte del payload predisposto
restano invariati nel banco.

## Ordine e significato del rilascio

`2794D0` rimuove il vecchio nodo dalla lista e ne azzera i link. Imposta
temporaneamente il flag di occupazione, rilascia la risorsa e chiama il
ponte`278AA4`. Il ponte scrive status/actual nella request e invoca il
callback originale del worker. Il callback può creare un secondo nodo.
Poi`2794D0` riacquisisce la risorsa, decrementa il conteggio, ripristina
il flag precedente e chiama free sul **vecchio nodo**, sotto lock.

La fixture free controlla link azzerati e flag ripristinato; registra count,
active, testa della coda e status della request. Nei20casi rientranti vede
già il secondo nodo e la stessa request di nuovo pending`-10`, con actual0:
il callback è terminato e ha accodato il seguito prima del free del vecchio
nodo. Il payload e la request globale non sono l'oggetto liberato.

Durante questa rientranza non c'è un secondo ingresso in`2DBFB8`. IN/PIO
richiede però una modifica del registro`FE50010` tramite`243BA8`, usando
il globale predisposto`351E2C` con bit4 impostato. Quindi non si deduce che
la nuova coda sia bloccata: la successiva elaborazione del controller/dispatch
è ancora fuori dal banco. Gli altri rami non richiedono quella modifica.

Il flag active del record superiore rimane1 in tutti i casi, anche dopo free
e cancel. Il pubblicatore, chiamato dopo il completamento, emette soltanto
le24notifiche done attese e ne cancella il flag; active resta1. Il cancel
endpoint non genera da solo una notifica done e non richiede altri accessi
registro nei corpi qui eseguiti. Non equivale al cancel superiore`1905D8`,
che conserva le proprie prove separate del24ottobre.

**Conseguenza:** free del nodo, callback, count, pending, evento e proprietà
fisica del payload sono condizioni diverse. Per il binding RAM serve ancora
una prova della cessazione del trasferimento e del momento in cui il buffer
può essere riutilizzato.

## Tentativo iniziale e prossimo passo

`131759Z` è conservato FAIL: il tracker ferma una lettura del globale`351E2C`
nel nuovo ramo IN/PIO rientrante. Il nuovo input è dichiarato e predisposto
esplicitamente; la fixture verifica indirizzo, maschera e valore della
modifica richiesta. Nessuna modifica all'emulatore o ai byte Nikon.
`131840Z` è l'unico risultato pubblicato PASS di questa tappa.

Prossimo: eseguire configurazione controller originale e consumatore della
coda dopo callback/IRQ, ricostruire actualcount e rilascio fisico, quindi
chiudere il binding con capacità posseduta, whitelist RAM, residenza e
avvio/recupero verificati. La ricerca resta attiva; il dumper non è completo.

Nessun accesso hardware, dumper, flash, NAND/vendor, reset USB o scrittura SD.
