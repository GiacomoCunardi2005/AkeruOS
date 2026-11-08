# AkeruUSB — costruttore, tabella e inizializzazione originali

26 ottobre 2026. Ricerca offline verso il dump RAM; **NON_INSTALLARE**.

La catena CPU ora esegue il costruttore controller V1.1 `2D9E58`,
i parametri predefiniti `2D9C68`, l'inizializzazione `2DA724` e poi
l'apertura `27864C/2792D0 → 2DBCF8`. Nei casi senza scatter/gather
prosegue con `278854/279658 → 2DBFB8`.
La tabella degli indirizzi e i flag98..102 vengono prodotti dal codice
originale, a partire da letture di capacità e servizi simulati.
Questo elimina la loro assegnazione manuale dal percorso controllato.

**192 scenari GNU ARC700 PASS, 3.743.173 istruzioni, uscita0, nessun fault.**
128 submit:112 programmano il trasferimento nel modello,16 mantengono
la request accodata senza programmarlo. Altre64 aperture seguono
l'allocazione ausiliaria scatter/gather senza eseguire submit.
Non sono trasferimenti USB fisici.

## Riproduzione e fonti

```sh
PYTHONDONTWRITEBYTECODE=1 make -C AkeruOS usb-ram-controller-init-verify
```

- [Verificatore](../Python_Trace_Scripts/s33_verify_akeru_usb_controller_init.py).
- [Banco C](../AkeruOS/tests/usb_controller_init_gnu_test.c), che riusa
  `usb_open_buffer_gnu_test.c` senza modificarlo.
- [Esito e hash](../Risultati/AkeruUSB_RAM_Debug/Controller_Init/20261026T175844Z/verified_evidence.json).
- Directory prove: `Risultati/AkeruUSB_RAM_Debug/Controller_Init/20261026T175844Z/`.
- SHA256 dell'esito: `50c747d82dec82f39d05af79cfa2e2b684ca125ecf12190aa4986e12221cb146`.

Compilazione `-Wall -Wextra -Werror`, confronto byte per byte delle
sezioni originali con l'ELF,9 contatori d'ingresso della traccia verificati.
Controllo finale:86 artefatti,22 input e hash del contenuto della traccia
gzip corrispondono. Originali e installazioni/build/sorgenti GNU preservati.

## Tabella prodotta dal costruttore

L'argomento `base` è un ingresso del banco, impostato a `0x0FE50000`.
La provenienza di quell'argomento nel chiamante runtime non è provata qui.
Il codice originale richiede, nell'ordine,160,252,76,16 e260 byte.
L'allocatore fixture restituisce cinque regioni distinte azzerate;
il contenuto iniziale dell'allocatore fisico resta sconosciuto.

| Oggetto/campo | Valore prodotto e controllato |
|---|---|
| Controller, tabella, oggetto ausiliario, evento, parametri | Allocazioni160/252/76/16/260 byte |
| Tabella+0 | `base+0x800` |
| Tabella+4+4×i, i=0..15 | `base+0x900+32×i` |
| Tabella+0x44+4×i, i=0..15 | `base+0xB00+32×i` |
| Ausiliario+0 / +4 | `base+0x400` / `base+0x440` |
| Ausiliario+8+4×i, i=0..15 | `base+0x500+32×i` |
| Controller+0x1C+4×i, i=0..15 | `base+0x1000+0x1000×i` |
| Controller+0x18 | `base+0xE00` |

Per endpoint1 la tabella porta quindi IN a `base+0x920` e OUT a
`base+0xB20`. Le precedenti prove usavano una tabella fixture che
indirizzava entrambi a `base+0x120`: quei valori erano ingressi del banco,
non una ricostruzione del costruttore. Nessuna misura di registri fisici
si ricava dal confronto. Tutte le16 posizioni di ciascuna tabella sono
controllate; apertura e submit di questa matrice usano solo endpoint1.

## Parametri e flag

La matrice varia tre modalità nel campo capacità48, bit3..4; capacità
scatter/gather nel campo50 bit30; campo50 bit25; risposta0/1 del servizio
`190D00`; direzione; packet64/512; risposta0/1 nel bit16 dello stato2C.
Tutte queste capacità/risposte sono iniettate, non lette dalla Nikon.

I default originali producono parametri+8=1 nelle modalità1/2,0 nella
modalità0. Il parametro+12 diventa1 solo con modalità1/2 e capacità SG1.
Il parametro+136 vale1; parametro+20 segue la risposta0/1 di `190D00`.
Parametri+244/+248 sono0 dopo i setter originali. Non sono stati
dedotti dalla memoria iniziale dell'allocatore: il codice dei default
inizializza il blocco e richiama i setter.

`2DA724` deriva flag controller+98/+99 da questi parametri; +100/+101
valgono0 nel profilo provato. Il flag+102 segue il bit25 delle capacità,
e i conteggi tabella+133/+134 valgono3 nei campioni scelti. La geometria
iniettata offre tre endpoint nelle due direzioni e tre risorse IN;
non sono provati tutti i limiti, combinazioni o clamp.

Questa è la configurazione predefinita nel contesto sintetico.
Eventuali setter chiamati dal programma reale dopo il costruttore
possono cambiarla: non è ancora il profilo operativo della fotocamera.

## Template originali e distinzione fra coda e avvio

Gli88 byte originali `3533A0..3533F7`, inclusi `3533EC/F0/F4`, sono
copiati dal payload verificato come sezione dati dell'ELF; sono tutti zero.
Il banco li controlla prima del costruttore e dopo l'inizializzazione in
ogni scenario. Questo raccorda quei dati al percorso CPU provato e
riduce l'assunzione rispetto ai pattern iniettati della tappa precedente.
Non censisce tutte le scritture intermedie né esclude writer esterni,
alias o modifiche in altre fasi del boot.

Nel ramo IN di `2DBFB8`, se controller+102=0 e i bit16..23 della
lettura `base+0x2C` sono tutti0, il ramo `2DBFF0 → 2DC1F6` evita la
programmazione. Nei16 casi della matrice, submit ritorna0, request+32
resta-10, il nodo è in coda e il contatore dispositivo vale1, ma non
arriva alcuna scrittura di avvio agli helper e il controllo endpoint
resta quello dell'apertura. Il fenomeno è provato sia in PIO sia in
DMA lineare; con flag+102=1 quel controllo viene saltato.

Negli altri112 casi il modello registra lunghezza/numero pacchetti e,
per DMA, indirizzo del buffer. OUT32 viene preparato al packet64/512;
IN32 conserva lunghezza32. Il buffer sintetico possiede1024 byte e
rimane identico al pattern iniziale. Non è una prova di trasferimento,
di padding posseduto dall'adapter reale o di rilascio fisico.

## Limiti e seguito

L'allocatore è azzerante nel banco; lock, log, accessi MMIO, query190D00,
servizio263DCC e attese145C3C/19A774 sono fixture. Il modello fornisce
esplicitamente reset-complete e modo1 alle letture della routine2DA018:
non misura reset, tempi o polling hardware. Il ramo finale alternativo
`2DA3D4` non viene eseguito. Registri simulati come normali parole R/W,
senza semantica fisica W1C, DMA, IRQ, scheduler o cache coerente.
Nessun dispatcher/completamento è ancora integrato in questo nuovo banco.

Le prove esplorative175525Z/175629Z hanno respinto aspettative errate
sui default e sull'offset del parametro della query. La175715Z ha
evidenziato la request IN accodata senza programmazione con stato2C=0.
La175750Z ha completato96 casi CPU, ma è stata respinta nella produzione
del disassemblato perché la finestra terminava a metà istruzione.
Gli esiti sono conservati; la175844Z verifica esplicitamente entrambi
gli stati2C e usa finestre complete. Nessun firmware o GNU modificato.

Prossimo: seguire il chiamante reale di `2D9E58/2DA724`, la base fornita
e gli override dei parametri; integrare configurazione e completamento
nello stesso banco. Mappa RAM fisica/whitelist, capacità e lifetime del
buffer adapter, binding, residenza, boot e recupero ancora incompleti.
Nessun hardware, dumper, flash, comando vendor/NAND, reset USB o scrittura
SD eseguito. **NON_INSTALLARE** invariato.
