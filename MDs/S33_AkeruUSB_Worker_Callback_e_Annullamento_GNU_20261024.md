# USB Nikon — produttori, callback e annullamento su GNU ARC700

Continuazione del 26 ottobre: [preparazione controller e capacità dei buffer](S33_AkeruUSB_Controller_Preparazione_e_Buffer_20261026.md).
L’evidenza Worker corrente154705Z comprende anche16casi endpoint;il rapporto
seguente conserva data e limiti delle44prove worker iniziali.

24 ottobre 2026, verifica15:34:07UTC. **44casi PASS**,2.097.580istruzioni,
exit0,nessun fault; altri2casi osservano polling persistente e terminano mediante
una guardia della fixture,non mediante un timeout Nikon.

Riproduzione: `make -C AkeruOS usb-ram-worker-verify`.
Sorgenti: `Python_Trace_Scripts/s33_verify_akeru_usb_worker.py` e
`AkeruOS/tests/usb_worker_gnu_test.c`.
Manifest: `Risultati/AkeruUSB_RAM_Debug/Worker/20261024T153407Z/verified_evidence.json`;
puntatore: `Risultati/AkeruUSB_RAM_Debug/Worker/latest.json`.

## Codice realmente eseguito e confini

GNU esegue byte originali dei produttori RX`190DAC`,TX`190EA4`,callback
RX`190E1C`,TX`190F10`,pubblicatore differito`190D54` e cancel`1905D8`.
Sono originali anche prologhi/epiloghi334124..3341E4 e helper di bitfield
336700..336764 con i wrapper necessari. Ogni sezione del nuovo ELF è riestratta
e confrontata con i byte del payload verificato,senza patch alle istruzioni.
Gli hash dei16payload e del firmware originale sono registrati e preservati.

Sono **fixture eseguibili**: endpoint/vtable e submit,close,restart,cancel;
event-set158CBC;lettura243B2C/scrittura243B6C dei registri;delay19A774;
logger243A50. Non vengono dereferenziati registri MMIO reali: i loro indirizzi
sono argomenti passati alle fixture. Nessun payload è trasferito.

Harness a1000,stack16KiB a510000,globali/record/request e buffer sintetici;
RAM laboratorio8MiB inizializzata a zero,senza attribuirla alla mappa Nikon.
Motore GNU fissato SHA
`7d6ccd1bc2291f377201e8cd1027c6ecf94d30901f13251c1c6bf647aa8a43dc`,
montatoRO in Podman senza rete. Tracce `.trace.gz` lossless,hash del contenuto
non compresso verificato e registrato. Nessuna modifica GNU o firmware.

## Preparazione delle richieste endpoint

Record globale423C00 e contesto3680A0,come nel precedente contratto superiore.
TXrequest47DA24,callback190F10;RXrequest47DA4C,callback190E1C.
Entrambi chiamano vtableendpoint+10 con r0endpoint,r1request,r2=20hex.

La request usa buffer+0,length+4,secondo puntatore buffer+8,control+12,
callback+16,status signed+32 e actual+36. Il produttore usa
`buffer+count` e `min(total-count,contesto+4C)`.
Il campo+4C è un limite di blocco del firmware,non il maxpacket USB:
nel banco vale512 per esercitare più blocchi; l'inizializzatore originale
191534/19154A vi scrive512000HS/64000FS,da analisi statica.

| Casi | Esito nel banco |
|---|---|
|9submit:vuoto,breve,cappato,ultimo,flag0,underflow e RX | Puntatore,limite e callback coerenti;nessuna copia payload |
|RXendpoint assente |02200342,eventobit19,nessun submit |
|2submit con endpoint che ritorna999 | Il produttore ignora il ritorno e restituisce0 |

TX imposta controlbit1 dal byte record+17 soltanto all'ultimo blocco e
azzera bit2;RX azzera bit1 e imposta bit2. Il significato sul controller,
in particolare la garanzia short-packet/ZLP,**non è ancora verificato**.
Il parametro r2=20hex non è una lunghezza né una durata fisica qui dimostrata.

## Completamento,conteggio e notifica

22casi callback coprono per ciascuna direzione completamento esatto,short17,
zero,ripartenza,actual65su request64 e6status nonzero:1,-1,-53,-54,-58,-59.
Con status0 il callback somma actual al count senza controllo del limite.
Short o uguaglianza col totale segnalano done;altrimenti viene preparato
il blocco successivo. Con actual65,total64 la sottrazione unsigned va in
underflow e viene accodata una nuova richiesta512 nel modello.
È un guasto iniettato per misurare la validazione,non un dato hardware.

Gli status nonzero provati raggiungono il logger con puntatore368118RX o
368138TX,senza aggiornare count né notificare direttamente un evento nei
corpi locali eseguiti. Non è dimostrato cosa faccia il task/controller esterno.

2casi aggiuntivi RX: a conteggio esatto con record+37 nonzero,il callback
azzera+37 e risottomette la stessa request con length1. Un successivo
completamento actual0 conclude la sequenza nel banco. Non è una dimostrazione
di ZLP fisico né di cosa accada al buffer durante quella richiesta aggiuntiva.

DoneTX è byte record+18,doneRX è+38. Il pubblicatore190D54,in4combinazioni,
li azzera e invia eventi1000hexTX/2000hexRX;un ritorno999 dell'event-set
viene ignorato e i flag sono comunque cancellati.
I callback e il pubblicatore **non cancellano activeTX+16/activeRX+36**.
Il precedente livello superiore li cancella nel proprio percorso normale:
notifica,active e proprietà fisica del buffer non sono la stessa osservazione.

## Annullamento e attese

4casi esercitano activeTX/RX pari a00,01,10,11. Cancel manda comunque
evento8000hex e non azzera i due active nel corpo eseguito.
Per RX chiama vtable+4,poi vtable+0 con puntatore`*(3680A0+4)+25`decimale;
i ritorni777 delle fixture sono ignorati. La cessazione di DMA resta da provare.

Per TX,con tutte le letture controller a0 nel banco:

- 4letture,3scritture richieste:FE50920←08000000,FE50920←48000000,
  FE50010←00000060. L'ultimo valore parte da uno scratch azzerato,
  non da una lettura preventiva di FE50010.
- Delay richiesti100,5,5,5,5:sono argomenti osservati,non tempi misurati.
- Alla fine viene chiamata vtable+14hex con la requestTX47DA24.

Due negativi mantengono rispettivamente FE50920bit30 o FE50010bit5:
la traccia ripete19062E o190662. Alla decima lettura la fixture verifica
activeTX1,assenza di evento/cancel endpoint e termina il guest con97;
10.818 e10.909istruzioni,nessun fault. **La funzione originale non è tornata**
in questi casi e non viene attribuito un timeout al suo ciclo.

## Conseguenze per AkeruRAM

Non collegare il protocollo al solo ritorno0 del produttore/upper USB:
count,limiti,completion ed effettivo rilascio endpoint devono essere distinti.
Su timeout non riusare automaticamente il buffer e non equiparare8000hex
o una chiamata cancel al completamento fisico dell'annullamento.
La sessione del client già si interrompe sugli errori di trasporto;il futuro
binding firmware deve conservare buffer/stato finché l'ownership non è risolta.

Prossimo confine concreto: risalire all'implementazione reale della vtable
endpoint+10 e dei suoi submit/callback/cancel,poi al dispatch del task USB.
Servono ancora short-packet/ZLP,controller/DMA/cache/IRQ,lifecycle/initdedicato,
whitelist fisica e integrazione boot/recupero. Il nucleo C/protocollo già
eseguito su GNU resta una prova separata,non è ancora integrato in questo banco.
Nessun accesso hardware,NAND/SD o firmware installabile: **NON_INSTALLARE**.

## Tentativi conservati

Il primo ELF collocava lo stack prima delle sezioni firmware e GNU rifiutava
il layout prima dell'esecuzione. Lo stack è stato spostato dopo il laboratorio
e la RAM sintetica è stata dichiarata esplicitamente. Il primo caso eseguito
richiedeva erroneamente5letture nel cancel: la traccia e il codice mostrano4,
perché lo scratch FE50010 parte da zero. Corretto il solo test;byte Nikon invariati.
