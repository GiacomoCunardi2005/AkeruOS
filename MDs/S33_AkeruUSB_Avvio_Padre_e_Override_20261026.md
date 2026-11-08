# AkeruUSB — wrapper padre, base e opzioni

26 ottobre 2026. Ricerca offline verso il dump RAM. **NON_INSTALLARE**.

Il wrapper originale V1.1 `243838` raggiunge il costruttore `2D9E58`
al callPC `243882`, applica le opzioni tramite `243584`, registra un
callback e chiama `2DA724` al callPC `243926`. La base viene dal literal
originale `243954 = 0x0FE50000`, caricato dal wrapper: in questo banco
non viene passata direttamente dal test al costruttore.

La CPU GNU esegue questi byte originali e poi apertura/configurazione
endpoint e submit. **192 scenari PASS,3.967.208 istruzioni,uscita0,
nessun fault.** I confini di inizializzazione dispositivo e registrazione
IRQ restano fixture; questo non è un boot completo della fotocamera.

## Riproduzione ed evidenze

```sh
PYTHONDONTWRITEBYTECODE=1 make -C AkeruOS usb-ram-parent-startup-verify
```

- [Verificatore](../Python_Trace_Scripts/s33_verify_akeru_usb_parent_startup.py).
- [Banco C](../AkeruOS/tests/usb_parent_startup_gnu_test.c).
- [Esito CPU e hash](../Risultati/AkeruUSB_RAM_Debug/Parent_Startup/20261026T180830Z/verified_evidence.json).
- [Supplemento statico callback/base/opzioni](../Risultati/AkeruUSB_RAM_Debug/Parent_Startup/20261026T180830Z/callback_static.json).
- Directory prove: `Risultati/AkeruUSB_RAM_Debug/Parent_Startup/20261026T180830Z/`.

Esito CPU SHA256 `89e34b07dd6b4a6d871dc29b35d786940b21cec1f60c0fdc8eefe685b4b80f7f`.
Verificati107 artefatti,22 input e hash del contenuto della traccia gzip;
compilazione `-Wall -Wextra -Werror`, sezioni originali confrontate con
l'ELF e14 contatori PC controllati. Il supplemento statico, aggiunto
separatamente al manifest CPU congelato, ha SHA256
`714f2bd40dd271c487f7ea72451c728d0fdf85d1d17d171bf0189cb7e9fcf261`.

## Dal wrapper alla configurazione

Il padre alloca24 byte, li azzera tramite helper fixture, memorizza
base e controller e associa il wrapper a contesto+32. Il costruttore
originale richiede poi160/252/76/16/260 byte, come nella tappa precedente.
Il controllo originale sull'identificativo accetta i campioni iniettati
con `(id & 0xFFFFF000) == 0x4F542000`; il ramo di rifiuto/cleanup
non è esercitato in questa matrice.

L'originale `243584` legge la tabella260 byte a `3F5EFC`. Nel payload
verificato tutti i65 elementi sono `0xFFFFFFFF`: gli slot consultati
vengono saltati e rimangono i parametri predefiniti. Non è una fotografia
della tabella dopo l'intero boot. La ricerca di literal LE, allineati a
halfword, nell'intervallo della tabella nei16 payload trova `243948`
per `3F5EFC` e `24394C` per `3F5FA4`. Non esclude writer con indirizzi
calcolati, alias o percorsi di configurazione esterni.

La matrice ha due profili,96 scenari ciascuno:

| Profilo | Contenuto della RAM di prova e comportamento osservato |
|---|---|
| Valori del payload originale | Tutti gli slot a-1; mapper eseguito, override selezionati saltati |
| Perturbazione controllata | Slot+8=0,+12=0,+244=1; altri a-1; mapper originale applica i tre override |

La perturbazione avviene soltanto nella RAM sintetica. Il firmware su
disco e la tabella sorgente rimangono invariati. Le corrispondenze non
sono tutte un'identità di offset:

| Slot opzioni | CallPC originale | Setter | Destinazione |
|---|---|---|---|
| +8 | `2435A8` | `2D84FC` | parametro+8 → flag controller+98, DMA |
| +12 | `2435B8` | `2D844C` | parametro+12 → flag controller+99, SG |
| +244 | `2437BE` | `2D97E0` | parametro+248 → flag controller+101 |

Ognuno di questi tre callPC viene eseguito96 volte. Il campione capacità48
ha bit20 impostato, necessario al percorso che abilita parametro+248.
Questo bit è una fixture, non un valore misurato sulla Nikon.
Con il secondo profilo DMA e SG sono disabilitati anche nelle modalità
che nei default li abilitavano; flag101 diventa1. Con il primo profilo
flag101 resta0 e DMA/SG derivano dalle capacità simulate.

## Apertura e submit dopo il padre

Si variano modalità capacità0/1/2, capacitàSG0/1, capacitàbit25=0/1,
direzione IN/OUT,packet64/512 e stato2C bit16=0/1; la query190D00
restituisce0. Le tabelle registri vengono ancora costruite dal codice
originale: IN `base+0x900+32*i`, OUT `base+0xB00+32*i`.

Le192 aperture raggiungono la configurazione originale `2DBCF8`.
32 seguono l'allocazione ausiliaria SG e non eseguono submit; le altre160
seguono la preparazione PIO o DMA lineare. In20 casi IN, con flag102=0
e stato2C senza bit16..23, submit ritorna0 con request pending, nodo
accodato e contatore1 ma nessuna scrittura di avvio. Gli altri140 casi
programmano lunghezza/pacchetti e, quando DMA è abilitato, il buffer.
Il buffer sintetico1024 byte rimane invariato: non è traffico USB.

## Callback e prossimo confine da rimuovere

La registrazione originale `243AC8` scrive callback `243540` e contesto
wrapper in `50B4B0/50B4B4`, controllati prima che la fixture243A58
restituisca successo. Il supplemento statico verifica che `243540`
legge wrapper+4 e salta a `2D81F8`. Il callback non viene invocato
dal banco; non sono dimostrate consegna IRQ o semantica dei registri.

Il successivo `278DD8` resta una fixture che restituisce0 e controlla
gli argomenti. La lettura statica dell'originale mostra che chiama
`279068`, memorizza il risultato in wrapper+12 e passa dalla
registrazione `243AD4`. Il nuovo banco conserva invece il contesto
endpoint sintetico preesistente. Questi limiti impediscono di dichiarare
integrata la catena fino ai dispatcher e al completamento già studiati.

Prossimo passo: seguire `278DD8 → 279068`, la registrazione243AD4
e il callback del dispositivo, poi riunire preparazione e completamento
nello stesso banco. Rimane aperta anche la provenienza runtime delle
eventuali modifiche alla tabella opzioni.

## Limiti

Solo percorso positivo del padre. Allocatore azzerante, azzeramento24 byte,
IRQ registration, setup dispositivo, lock, log, MMIO, query/servizi,
attese e risposte reset-complete/modo restano fixture. I registri sono
parole R/W modellate; nessuna prova di W1C, trasferimento DMA/PIO,
cache coerente, scheduler, interrupt fisico, enumerazione o dump.
La prima esecuzione180657Z e quella definitiva180830Z sono entrambe
PASS; i risultati precedenti sono conservati.

Mappa RAM fisica/whitelist, capacità e lifetime del buffer adapter,
binding, residenza, boot e recupero non dimostrati. GNU e firmware
originali preservati; nessun hardware, dumper, flash, comando vendor/NAND,
reset USB o scrittura SD eseguito. **NON_INSTALLARE** invariato.
