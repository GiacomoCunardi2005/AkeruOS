# AkeruRAM — adapter asincrono e catena USB originale

26 ottobre 2026. Ricerca offline verso il dump RAM. **NON_INSTALLARE**.

Precisazione successiva: l'attribuzione di pubblico+0x14 a «stato configurato»
non era provata. La [notifica originale](S33_AkeruUSB_Registrazione_Applicazione_e_Notifica_Stato_20261026.md)
mostra un codice derivato dal selettore controller, senza provare SET_CONFIGURATION.

Il core `usb_ram.c` è ora collegato, nel banco CPU, a un adapter che
possiede i buffer e serializza ricezione, elaborazione e risposta. Il
percorso originale Nikon V1.1 costruisce il dispositivo, apre entrambi
gli endpoint, accoda le richieste e completa i nodi tramite il callback
registrato. Le risposte coincidono byte per byte con il riferimento Python.
La mappa e i dati RAM sono sintetici; non è un dump della fotocamera.

**PASS host ASan/UBSan e GNU ARC700: 36 scambi integrati, 72 submit,
77 chiamate al callback registrato, 72 completamenti e 72 free.
2.686.925 istruzioni CPU, uscita 0, nessun fault.**

## Riproduzione ed evidenze

```sh
PYTHONDONTWRITEBYTECODE=1 make -C AkeruOS usb-ram-transport-verify
```

- [Adapter e contratto](../AkeruOS/usb_ram_transport.h), [implementazione](../AkeruOS/usb_ram_transport.c).
- [Test proprietà/errori](../AkeruOS/tests/usb_ram_transport_test.c), [integrazione originale](../AkeruOS/tests/usb_ram_transport_gnu_test.c).
- [Verificatore](../Python_Trace_Scripts/s33_verify_akeru_usb_ram_transport.py).
- [Esito, hash, contatori e limiti](../Risultati/AkeruUSB_RAM_Debug/Transport/20261026T184623Z/verified_evidence.json).
- SHA256 esito: `b697b5dac04d25f9800a973ddf0e87a60fcb491a524f3f2b66f1d1bd8a24df83`.

Ricontrollati 158 artefatti, 34 input e SHA256 del contenuto della traccia
gzip. Le sezioni originali estratte dall'ELF sono identiche ai byte del
payload verificato. GNU e firmware originali non sono stati modificati.
Il verificatore riusa il prefisso delle fixture del banco precedente e
i suoi helper, senza alterare quei sorgenti storici.

## Contratto dei buffer

| Proprietà | Vincolo implementato |
|---|---|
| RX logico | Submit di 32 byte; soltanto `status=0, actual=32` raggiunge il core |
| Capacità RX | 512 byte posseduti dal dispositivo, per l'arrotondamento originale a maxpacket64/512 |
| TX | Fino a 4.128 byte logici; area posseduta da 4.160 byte |
| Allineamento | RX e TX a 64 byte, con capacità multipla di 64 |
| Ordine | RX pronto → RX pendente → TX pronto → TX pendente → RX pronto |
| Frame corto, lungo entro maxpacket o CRC errato | Scartato prima di qualsiasi lettura RAM |
| Errore RX o actual oltre maxpacket | Stato fermo; nessun riuso automatico |
| Errore TX o actual diverso dalla risposta | Stato fermo; buffer e lunghezza conservati |
| Submit fallito | La prenotazione resta pendente finché il backend non stabilisce la quiescenza |

Un solo task ordinario possiede servizio, stato e buffer per l'intera
sessione. L'inizializzazione si applica a un oggetto inattivo; non annulla
I/O esistenti. Le API di completamento richiedono un evento corrispondente
alla richiesta e il ritorno dal percorso callback/free del backend.

Nel banco, il callback applicativo registra esclusivamente status e actual.
Il task chiama il core dopo il ritorno dal dispatcher, verificando free,
count0, coda vuota e rilascio del nodo. La callback di lettura sintetica
controlla esplicitamente che non sia in fase IRQ né prima del free.
La profondità lock0 nel callback non viene scambiata per prova di un task RTOS.

Il core e il protocollo preesistenti restano invariati. Non sono aggiunti
allocatori, primitive USB, indirizzi Nikon o whitelist fisiche all'adapter.
L'allineamento e lo spazio posseduto non provano la coerenza cache/DMA.

## Verifiche eseguite

| Banco | Copertura |
|---|---|
| Host con AddressSanitizer e UndefinedBehaviorSanitizer | 18 vettori sequenziali per maxpacket64 e512; guardie esterne, allineamento, ordini errati, completamenti duplicati, lunghezze limite, errori e conservazione TX |
| GNU, test del medesimo adapter | Gli stessi 36 vettori e controlli negativi del test host |
| GNU con USB originale | 18 scambi per ciascun maxpacket, due aperture per sessione, confronto esatto prima e dopo TX |

I vettori comprendono HELLO, mappa, letture da1/4096/513 byte, errore della
callback di lettura, intervalli vietati/overflow, opcode e argomenti errati,
STATUS e ABORT persistente. Ogni sessione invoca quattro volte il lettore
sintetico, una con errore; le letture riuscite sono tre. Totale integrato:
otto callback e sei letture riuscite. Non sono letture degli indirizzi
fisici Nikon: il callback genera un pattern da indirizzi numerici di fixture.

Il percorso originale riunito nel banco è:

`243838 → 278DD8 → 279068 → 278CD0/278BCC → 243AD4`,
poi `27864C → 278854`, e i puntatori registrati
`50B4B8/50B4BC → 278BC4 → 27DB3C → 2794D0 → 278AA4`.

Le vtable e gli oggetti dispositivo/endpoint sono costruiti dall'originale.
Il test fornisce stato configurato e tabella operazioni applicativa, risorse,
allocatore e MMIO. Dopo ciascun completamento il nodo può essere riutilizzato
solo quando il free originale ha terminato; non viene riciclato dal callback.

## Segmentazione e trasferimento vuoto IN

Le capacità iniettate producono un limite iniziale di `0x7ff` byte.
Per una richiesta maggiore, `27CCE0` arrotonda il limite al multiplo
inferiore di maxpacket; `2DBFB8` prepara ogni segmento. La risposta da
4.128 byte esercita realmente tre avvii nel percorso CPU:

| Maxpacket | Byte dei segmenti IN |
|---:|---|
| 64 | 1.984 + 1.984 + 160 |
| 512 | 1.536 + 1.536 + 1.056 |

Il test verifica indirizzo DMA progressivo, lunghezza e numero packet
programmati, permanenza pending tra segmenti e actual finale di4.128 byte.
Le quattro ripartenze portano a76 ingressi in `2DBFB8` per72 submit.

Con gli attributi richiesta del banco (`request+12=2`), HELLO lungo64 byte
e maxpacket64 attiva il ramo `27CFC4 → 2DC214`: viene programmato un packet
con zero byte e puntatore alla fine dei dati. Il primo evento non pubblica
completion né libera il nodo. Un secondo evento con residuo0 completa la
richiesta; il buffer resta TX pendente fino ad allora. Da qui77 chiamate
registrate per72 completamenti. È preparazione CPU di un trasferimento
vuoto con MMIO modellato, non osservazione di uno ZLP sul bus fisico.

I primi tentativi FAIL sono conservati nelle rispettive directory. Hanno
evidenziato il ramo originale non ancora incluso `2DC214`, il suo literal
e il globale diagnostico `353404`, ora dichiarato e inizializzato come
fixture insieme a353400. Sono stati corretti perimetro e aspettative del
banco, senza modificare istruzioni originali o motore GNU.

## Limiti e prossimo passo

Restano fixture: dati trasferiti dal DMA, letture/scritture registri,
capacità, maschere, status/residui, registrazione della primitiva IRQ,
allocazione/lock, ritardi e servizi piattaforma, stato e operazioni app.
Il modello DSP preesistente resta provvisorio. I128 MiB sintetici non
costituiscono una mappa RAM fisica.

Mancano consegna reale degli eventi al task, manutenzione cache/barriere,
cancel/timeout/disconnessione e prova della quiescenza fisica. Non sono
verificati enumerazione/classe AkeruRAM, boot, residenza, recupero o
whitelist fisica. Nessuna operazione USB/NAND/SD o installazione eseguita.

Prossimo lavoro offline: seguire i produttori originali dello stato pubblico
e della tabella applicativa `public+0x14/+0x48`, quindi il passaggio evento/task
e il contratto cache/cancel prima di un eventuale binding. **NON_INSTALLARE**.
