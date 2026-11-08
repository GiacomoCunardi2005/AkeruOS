# AkeruUSB RAM Debug — scelta della prima modalità

24 ottobre 2026. Nuovo obiettivo dell'utente: servizio USB read-only per leggere
intervalli RAM dal PC CachyOS, con client Python/PyUSB/libusb. Sostituisce il
precedente obiettivo attivo dell'aggiornamento RAM→SD. Il lavoro SD già verificato
rimane disponibile, ma non è il trasporto della prima versione USB.

**Decisione tecnica: prima modalità AkeruRAM dedicata, una interfaccia vendor
specific con bulk IN/OUT; composito rinviato.** La motivazione è il layout
effettivamente consumato dal codice Nikon, non un limite dimostrato del silicio.
Nessun servizio USB personalizzato è ancora installabile. **NO-GO installazione.**

## Evidenza nuova riproducibile

`python3 Python_Trace_Scripts/s33_verify_akeru_usb_descriptors.py`

**8 casi CPU PASS**: routine originale `0x19133C` su quattro configurazioni
(MSDC/PTP originali, dedicataFF e composita sintetiche), ciascuna con query
velocità esplicita0/1. Endpoint/descriptor preparation esegue istruzioni Nikon;
la query `0x27DD74`, puntatori globali, header device e buffer sono predisposti.
Non viene eseguito il controller elettrico né l'intero boot/enumerazione.

Manifest e tracce: `Risultati/AkeruUSB_RAM_Debug/Descriptors/latest.json`.
Contiene hash16payload originali e sorgenti, snapshot, finestre GNU con assert,
tabelle EP0 decodificate come dati e traccia P-code. Nessun byte Nikon alterato.

| Template V1.1 | Interfacce | Endpoint dati | Pacchetti statici |
|---|---:|---|---|
| PTP `0x3900F0`,39byte |1, classe06/01/01|81bulk IN,02bulk OUT,83interrupt IN|512,512,8 |
| MSDC `0x3901B0`,32byte |1, classe08/06/50|81bulk IN,02bulk OUT|64,64 |

Gli endpoint PTP costituiscono evidenza di tre endpoint dati nel template
supportato dal software; non rivelano quanti endpoint aggiuntivi abbia il
controller né una riserva DMA/buffer per un composito.

### Perché una seconda interfaccia non si aggiunge modificando solo i byte

La selezione configurazione `0x191110` legge il numero endpoint a config+13
e costruisce puntatori a config+18,+25,+32. Sono gli offset della prima
interfaccia nei template attuali. Il ramo `0x1912EC` abilita il terzo collegamento
solo se quel numero supera2. La classe per il callback viene letta da
config+14 a `0x191322`. Non è stato trovato in questi corpi un walker generale
che instradi due interfacce indipendenti.

La preparazione `0x19133C` scorre il numero endpoint della prima interfaccia
con passo7byte (`0x1913B2..C4`) e adatta i loro pacchetti. Il caso composito del
test ha due interfacce e quattro endpoint bulk: **in high speed soltanto i
primi due diventano512; i due della seconda interfaccia restano64, invariati**.
Il descrittore dedicato con classeFF e una coppia bulk invece segue la stessa
preparazione del MSDC, sia a64 che a512.

Questo è un controesempio concreto all'idea di collegare semplicemente un
secondo descrittore allo stack attuale. Non prova che un nuovo stack/controller
non possa gestirlo. La configurazione composita richiederebbe almeno un parser
e routing diversi, più verifica delle risorse di endpoint/buffer/DMA.

La routine originale chiarisce anche la differenza storica fra template MSDC
64byte e descrittori hardware high-speed512byte osservati il24ottobre: nel
laboratorio il codice originale produce proprio l'adattamento64→512. Non è
una nuova osservazione della fotocamera né prova che ogni ramo live coincida.

### EP0 e punto di integrazione individuati

- `0x190C3C` registra otto puntatori nel contesto globale `0x3680A0` e invia
  una notifica. Il puntatore configurazione corrente è a `0x3680A4`.
- `0x191570` legge bRequest dal byte1 della richiesta; la tabella signed16 a
  `0x1915B4` porta request6 a `0x1916DA` (GET_DESCRIPTOR).
- La tabella tipi descrittore a `0x1916F2` porta tipo2 a `0x19177C`, che usa
  il puntatore configurazione registrato. Le tabelle sono decodificate dai
  byte, non interpretate come istruzioni del listato lineare.
- Request9 raggiunge `0x1917F8`; `0x19182C..32` passa wValue al selettore
  `0x191110`. Questa rotta è verificata staticamente, non come transazione EP0.
- Il callback d'inizializzazione `0x1392CC` distingue **classe6 e tutte le
  altre**: il ramo non6 entra a `0x1393DE` e seleziona il backend MSDC.
  **Cambiare soltanto classe08→FF non crea AkeruRAM:** occorre un nuovo
  inizializzatore/handler registrato e isolato dai backend PTP/MSDC.

Restano da seguire le funzioni inferiori del controller e i loro descrittori
di trasferimento, l'IRQ/completamento, annullamento e proprietà dei buffer.
`1908DC` e `1906B4` sono piste di send/receive già presenti, non API AkeruUSB
pronte. Non vengono riutilizzate come se avessero un contratto provato.

## Architettura da realizzare

La prima versione utilizzerà EP0 per enumerazione/configurazione e una coppia
bulk dedicata al protocollo AkeruRAM v1. I numeri81/02 sono candidati riusabili
nella modalità separata, non risorse assegnate a un composito già funzionante.
VID/PID nuovi non sono assegnati; `04b0:035d` identifica lo storico MSDC Nikon,
non una prova di presenza del nuovo servizio.

Il client dovrà riconoscere l'interfaccia dedicata e completare HELLO prima di
leggere; non dovrà inviare il protocollo privato al Mass Storage esistente.
Il claim dell'interfaccia e la gestione dei trasferimenti seguiranno le API
[libusb](https://libusb.sourceforge.io/api-1.0/group__libusb__dev.html) e
[PyUSB](https://github.com/pyusb/pyusb/blob/master/docs/tutorial.rst).
Nessun auto-detach di usb-storage, cambio modalità o reset della Nikon durante
lo sviluppo offline. La [specifica USB2](https://www.usb.org/document-library/usb-20-specification)
definisce descrittori/interfacce/endpoint; la compatibilità S33 richiede le
prove sul codice sopra e non discende dal solo standard.

Comandi richiesti: HELLO,GET_MAP,READ_RAM,GET_STATUS,ABORT. Niente writeRAM/NAND.
Il GET_MAP deve descrivere una whitelist verificata; senza mappa fisica
confermata non dichiarare tutta la RAM disponibile. Buffer dedicati, controllo
overflow/bordi/MMIO, checksum, errori espliciti senza byte inventati, timeout,
trasferimenti parziali e ripresa restano requisiti del protocollo/client.

Prossimi passi: chiudere il contratto controller/endpoint e buffer; poi
implementare client e dispositivo sintetico con quei cinque comandi, integrare
il servizio read-only e verificare offline boot, callback e lifetime. La prima
prova hardware richiede evidenza distinta di installazione/avvio/recupero.

Il controllo SD già avviato prima del cambio obiettivo è terminato: marker C
14casi PASS e regressione write/close7PASS, descritti in
`S33_Dumper_RAM_Marker_C_Identita_e_Pin_20261024.md`. Non è stato proseguito
l'adapter SD dopo la nuova richiesta.
