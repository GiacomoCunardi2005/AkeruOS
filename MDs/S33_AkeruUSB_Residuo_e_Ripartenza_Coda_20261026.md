# AkeruUSB: conteggio dal residuo e ripartenza della coda

26 ottobre 2026. **16 scenari CPU GNU PASS**, 182.358 istruzioni, exit0,
nessun fault o lettura da memoria non dichiarata. Il banco esegue il
consumatore originale`27CDA8`, che ricava actualcount dal registro residuo,
e`27CCE0`, che prepara il successivo nodo della coda. Nei quattro scenari
a due blocchi viene eseguita anche la seconda preparazione controller e
il secondo completamento. Nessun trasferimento fisico. **NON_INSTALLARE**.

Riproduzione: `make -C AkeruOS usb-ram-queue-consumer-verify`.
Sorgenti: `Python_Trace_Scripts/s33_verify_akeru_usb_queue_consumer.py` e
`AkeruOS/tests/usb_queue_consumer_gnu_test.c`, che riusa per inclusione le
fixture di`usb_open_buffer_gnu_test.c` senza modificarlo. La matrice90
precedente non viene eseguita dal nuovo main.

Evidenza: `Risultati/AkeruUSB_RAM_Debug/Queue_Consumer/20261026T132542Z/verified_evidence.json`;
puntatore: `Queue_Consumer/latest.json`. Verificati89file,22input,
21intervalli originali estratti/riestratti dall'ELF e hash della traccia
decompressa. Firmware e16payload verificati; GNU e firmware invariati.

## Riduzione del confine precedente

Nel banco Worker_Lifetime il test scriveva actual nel nodo e chiamava
direttamente`2794D0`. Qui il test **non scrive actual nel nodo**: chiama
`27CDA8(record)` e fornisce alla fixture di lettura soltanto il valore
del registro endpoint+10hex. L'originale calcola/aggiorna il cursore,
scrive actual nel nodo e raggiunge`2794D0` quando il suo ramo lo prevede.

Dopo callback e free del vecchio nodo,`27CDA8` azzera i campi precedenti e
chiama`27CCE0`. Se esiste un nuovo nodo, quest'ultima carica i puntatori e
la lunghezza del nuovo payload, azzera i cursori e chiama`2DBFB8`.
Se la lista è vuota, ritorna senza un nuovo start.

Sono originali anche apertura, produttori worker, submit/coda, preparazione
controller, ponte callback, callback worker, rimozione e pubblicatore.
Gli ingressi controllati in traccia sono:

| Corpo | Ingressi |
|---|---:|
| Inizializzazione/apertura | 16 ciascuno |
| Submit`278854` | 20 |
| Preparazione`2DBFB8` | 20 |
| Residuo`27CDA8` | 20 |
| Rimozione`2794D0` e ponte`278AA4` | 16 ciascuno |
| Successivo nodo`27CCE0` | 16 |
| Produttori RX/TX`190DAC/190EA4` | 10 ciascuno |
| Pubblicatore`190D54` | 16 |

## Conteggi e condizioni provate

Si usano endpoint1 bulk, direzioni OUT/RX e IN/TX, packet64/512 e
preparazione DMA lineare. Il limite di blocco worker è predisposto al
pacchetto. Quattro scenari per ciascuna combinazione direzione/pacchetto:

| Direzione/scenario | Input alla fixture residuo | Risultato CPU |
|---|---|---|
| OUT, richiesta32 | packet-32 | actual32, count32, done, nodo liberato |
| OUT, richiesta32 breve | packet-17 | actual17, count17, done per short |
| OUT, richiesta32 vuota | packet | actual0, count0, done per short |
| OUT, totale packet+32 | 0, poi packet-32 | Primo actualpacket e secondo actual32; count finale packet+32 |
| IN, richiesta32 completa | 0 | actual32, count32, done, nodo liberato |
| IN, residuo byte nonzero | 1 | Pending-10, nodo conservato, count0, nessun done/free |
| IN, residuo pacchetti nonzero | 1<<19 | Pending-10, nodo conservato, count0, nessun done/free |
| IN, totale packet+32 | 0, poi0 | Primo actualpacket e secondo actual32; count finale packet+32 |

Nel ramo OUT/DMA lineare il codice usa i19bit bassi del residuo e calcola
l'incremento come`cursore_preparato - cursore_actual - residuo_byte`;
aggiorna puntatori e cursore actual. Il count consegnato alla callback è
il campo actual del record controller, scritto nel nodo a`27CFE4`.
Non è provata la validazione di residui arbitrari o incoerenti.

Nel ramo IN/DMA lineare provato, i campi residui byte e pacchetti devono
essere entrambi zero per il percorso che aggiorna actual e completa.
I due input nonzero esercitano il ramo che lascia il nodo pending;
non vengono interpretati come completamenti parziali riusciti.

Nei quattro casi a due blocchi il callback worker accoda una request32 a
`buffer+packet`; dopo il free del primo nodo, il consumatore originale
installa quei puntatori e la prepara. Le asserzioni controllano coda,
conteggio richieste, puntatori, lunghezza, cursori e numero di richieste
di scrittura registro:6OUT oppure8IN sulle due preparazioni DMA.
Il secondo passaggio completa la request32 e svuota la coda.

Il pubblicatore emette12notifiche done e nessuna nei4casi IN pending.
Il flag active superiore rimane1 anche nei percorsi completati. Tutti i
1024byte del payload predisposto restano invariati: non si esegue DMA.

## Limiti e raccordi ancora aperti

**Sono fixture** lettura/scrittura/modifica registri, configurazione
controller`2DBCF8`, allocatore/free, lock, logging ed event-set. Le vtable,
il record superiore, stack, controller e tabelle sono predisposti. Prima di
ogni ingresso nel consumatore il test acquisisce il lock della fixture;
non esegue il dispatcher padre né la consegna di un interrupt.
I valori residui sono indipendenti dalle scritture registrate: non esiste
un modello di periferica che li produca. Nessuna prova W1C o di timing.

Il nuovo banco supera la chiamata diretta al completamento, ma non dimostra
che i residui corrispondano ai byte effettivamente trasferiti, che DMA sia
cessata o che il payload possa essere riutilizzato sulla fotocamera.
I4casi pending vengono osservati e poi il banco riparte da contesti nuovi:
non viene qui provato il loro cleanup/cancel.

Restano fuori PIO, scatter/gather, ZLP, registrazione/dispatch IRQ, cache
fisica, allocatore live, capacità del buffer adapter, whitelist RAM,
residenza e avvio/recupero. La RAM128MiB e il payload1024byte sono
sintetici; modello DSP GNU provvisorio già esistente.

La ricerca statica locale nell'intervallo`279000..27E000` ha individuato
chiamate a`27CDA8` dai PC`27D304` e`27D822`. Sono punti di partenza per
il raccordo padre; non è un censimento globale delle xref né esecuzione IRQ.
Prossimo: seguire questi chiamanti e sostituire la configurazione
controller`2DBCF8` ancora simulata, poi verificare origine del residuo e
rilascio fisico prima del binding completo AkeruRAM.

Nessun accesso hardware, dumper, flash, NAND/vendor, reset USB o scrittura SD.
