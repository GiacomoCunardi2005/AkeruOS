# AkeruUSB — setup dispositivo e completamento nello stesso banco

26 ottobre 2026. Ricerca offline verso il dump RAM. **NON_INSTALLARE**.

Precisazione successiva: pubblico+0x14 non è dimostrato essere un flag di
configurazione USB. La [notifica originale](S33_AkeruUSB_Registrazione_Applicazione_e_Notifica_Stato_20261026.md)
scrive codici derivati dal controller; il valore1 iniettato qui non prova SET_CONFIGURATION.

Il banco esegue ora il padre `243838`, il setup dispositivo originale
`278DD8 → 279068`, la costruzione del contesto pubblico `278CD0/278BCC`,
la registrazione `243AD4`, apertura/configurazione/submit e il callback
registrato `278BC4 → 27DB3C`. Nei casi ammessi prosegue fino a
`2794D0 → 278AA4`, callback applicativo e free del nodo.
Questi percorsi sono riuniti in una singola esecuzione CPU, con le
vtable prodotte dall'originale; non sono la somma di banchi separati.

**120 scenari GNU ARC700 PASS,5.114.627 istruzioni,uscita0,nessun fault.**
160 chiamate al callback registrato,32 completamenti e32 free di nodo.
Nessun trasferimento fisico USB o dump RAM dimostrato.

## Riproduzione ed evidenze

```sh
PYTHONDONTWRITEBYTECODE=1 make -C AkeruOS usb-ram-device-completion-verify
```

- [Verificatore](../Python_Trace_Scripts/s33_verify_akeru_usb_device_completion.py).
- [Banco C](../AkeruOS/tests/usb_device_completion_gnu_test.c).
- [Esito CPU, hash, contatori e limiti](../Risultati/AkeruUSB_RAM_Debug/Device_Completion/20261026T182601Z/verified_evidence.json).
- Prove: `Risultati/AkeruUSB_RAM_Debug/Device_Completion/20261026T182601Z/`.
- SHA256 esito: `744d8a4aebe6da15a856a090b478a1512a63c5ed440fb2b9a1cb93864e7f04e5`.

Verificati128 artefatti,22 input e hash del contenuto della traccia gzip;
compilazione `-Wall -Wextra -Werror`, confronto delle sezioni originali
con l'ELF e12 contatori PC. Setup dispositivo, registrazione243AD4,
dispatcher e bridge di completamento non sono fixture di questo banco.

## Cosa costruisce l'originale

Oltre agli oggetti controller già studiati, il percorso richiede
un dispositivo da `0x874` byte, due aree da40 e2 byte, un oggetto16 byte
e un contesto pubblico868 byte. L'allocatore fixture restituisce regioni
distinte azzerate. In DMA i due buffer passano dal wrapper originale
`243BC8`; in PIO dall'allocatore. Non viene esercitato scatter/gather.

Il dispositivo risulta in wrapper+12; il globale `36B588` riceve il
contesto pubblico, che punta al dispositivo. L'originale inizializza
i record endpoint e le liste, costruisce le vtable a `51A360...` e collega
la vtable callback `51A3A4` al dispositivo. Il suo slot+12 vale `278AA4`.
Il test non sostituisce questi puntatori con una vtable manuale.

`243AD4` registra `278BC4` e il dispositivo in `50B4B8/50B4BC`.
Il test invoca i valori letti da quegli slot, senza chiamare direttamente
il dispatcher direzionale. `278BC4` passa il contesto a `27DB3C`, che
gestisce il lock, legge stato/maschere e raggiunge il consumatore.
La primitiva di registrazione IRQ243A58 rimane fixture: non c'è consegna
di interrupt da hardware o RTOS.

Il puntatore servizio in dispositivo+0x860 è `36ACBC`; la parola originale
copiata dal payload vale `0x02200002`. Gli helper fixture verificano
acquire/release e profondità, senza provare l'esistenza/lifetime di una
risorsa RTOS fisica con quell'identificativo.

## Stato pubblico prima dell'apertura

Il setup lascia contesto pubblico+0x14 e +0x48 a0. Ogni scenario verifica:

1. L'apertura restituisce-58 prima di abilitare lo stato applicativo.
2. Il callback originale `278B00(...,1)` imposta pubblico+0x14; con
   pubblico+0x48 ancora0 l'apertura continua a restituire-58.
3. Il test fornisce una tabella operazioni applicativa sintetica in+0x48;
   l'apertura riesce e raggiunge la configurazione originale del controller.

Quindi360 ingressi nell'API di apertura corrispondono a240 rifiuti
attesi e120 aperture positive. Questo non esegue l'enumerazione USB,
il percorso reale di configurazione da host o la registrazione di una
classe AkeruRAM. La tabella applicativa è esplicitamente una fixture.

## Matrice e completamento

Si variano tre modalità capacità0/1/2, flag101=0/1, direzione IN/OUT,
packet64/512 e cinque stati di completamento. Le capacità e le letture
MMIO sono sintetiche. Flag101 viene richiesto tramite la tabella opzioni
in RAM e il mapper originale; gli altri slot rimangono-1. CapacitàSG=0.

| Gruppo | Casi | Risultato controllato |
|---|---:|---|
| PIO, modalità0 | 40 | Setup, apertura e submit; nessun completamento PIO tentato |
| DMA lineare, modalità1/2 | 80 | Due chiamate del callback registrato per caso |
| Prima chiamata DMA, stato0x14 bit0=1 | 80 | Nessun acquire, callback applicativo o free; richiesta pending conservata |
| Seconda chiamata DMA, stato0x14 bit0=0 | 80 | Valutazione di maschere, stato endpoint e residuo |
| Completamenti della seconda chiamata | 32 |24 OUT e8 IN; status0,actual corretto,coda vuota,count0,callback1 e free1 |
| Richieste DMA trattenute | 48 | Maschera/stato assenti oppure residuo IN; pending,coda e count1 conservati |

Le righe della tabella descrivono gruppi sovrapposti della stessa matrice,
non scenari da sommare. I cinque stati sono maschere assenti, stato
endpoint assente, completamento32 byte, trasferimento parziale17 byte
OUT/residuo1 byte IN e trasferimento0 byte OUT/residuo1 packet IN.

`2DABFC` maschera il bit0 dello stato0x14 e lo inverte nel delay slot
`2DAC0C`. Con bit0=1 il dispatcher dispositivo ritorna prima del lock;
con bit0=0 supera quel controllo. Il banco verifica entrambi i valori,
senza assegnare significato fisico a uno stato letto dalla fotocamera.

Le maschere endpoint comuni/per-endpoint sono fornite esplicitamente
alla fase IRQ, insieme a stato e residuo. Nel modello del setup i valori
comuni non bastavano a completare la richiesta senza tale ingresso.
Non è quindi provata l'abilitazione fisica delle maschere da parte
dell'intero programma, né una semantica W1C dei registri.

Il callback applicativo di prova riceve endpoint e request, legge status
e actual pubblicati da `278AA4` e osserva count1 prima del free; dopo
il ritorno l'originale decrementa il contatore e libera il nodo. Sono
verificati ordine software e durata del nodo nel dominio del banco.
Il buffer payload1024 byte rimane identico al pattern iniziale.
Nessun motore DMA copia dati e nessuna persistenza viene osservata.

## Confini del laboratorio

Restano fixture allocazione, clear/copy, log, risorse, primitiva IRQ,
attese, query/servizi, applicazione e accessi MMIO. I byte dati necessari
in `351E00..351FFF`, `3533A0..3533F7`, le tabelle e il servizio36ACBC
provengono dai payload verificati. Non si è dedotta RAM libera da zeri.
ABI C NOBITS e RAM128MiB sono assunzioni del laboratorio, non mappa Nikon.

Lo stack sintetico è `520000..523FFF`: le vtable originali a51A360
superavano il vecchio stack510000 e l'init_stack del simulatore rifiutava
l'ELF prima dell'esecuzione, senza riepilogo. Il nuovo verificatore
controlla che gli altri segmenti finiscano prima dello stack. GNU e
indirizzi/byte originali del firmware non sono stati modificati.

Gli esiti esplorativi sono conservati:181821Z errore di compilazione
per variabili inutilizzate;181836Z/181946Z mancato avvio ELF per il layout
stack;182118Z controllo modo non soddisfatto;182208Z maschere comuni
insufficienti;182306Z guard su dati351F00 non ancora caricati.
182414Z e la verifica definitiva182601Z sono PASS.

## Seguito verso il dumper

Il componente [usb_ram.c](../AkeruOS/usb_ram.c) rimane separato da questa
catena asincrona. Prossimo: adapter con buffer RX posseduto e arrotondato
al maxpacket, consegna al core soltanto di frame completi da32 byte
secondo actualcount, buffer TX distinto e conservato fino al completamento;
prima prova con whitelist e lettore RAM sintetici, senza binding installabile.

Restano da dimostrare mappa RAM fisica/whitelist, capacità e lifetime
dell'adapter reale, lettura RAM fisica, coerenza cache/DMA, cancellazione
fisica, residenza, boot e recupero. Nessun dumper, flash, comando vendor/NAND,
reset USB o scrittura SD eseguito. **NON_INSTALLARE** invariato.
