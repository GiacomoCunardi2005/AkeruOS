# AkeruUSB RAM Debug — protocollo v1, client e simulatore

24 ottobre 2026. **Client Python, trasporto PyUSB e dispositivo sintetico
implementati;21test host e6invocazioni CLI PASS**, inclusi dump9513byte e ripresa.
È una nuova implementazione offline: non un protocollo Nikon già presente,
non un dispositivo USB enumerato. È stato aggiunto anche il nucleo C del
protocollo, senza binding al driver: si veda la verifica distinta più sotto.
**NON_INSTALLARE** resta lo stato del progetto.

Sorgenti: `Python_Trace_Scripts/akeru_ramdump.py`, launcher `akeru-ramdump`,
test `test_akeru_ramdump.py`. Verifica riproducibile:

```bash
python3 Python_Trace_Scripts/s33_verify_akeru_ramdump_client.py
Python_Trace_Scripts/akeru-ramdump --simulate --info
Python_Trace_Scripts/akeru-ramdump --simulate --map
Python_Trace_Scripts/akeru-ramdump --simulate --dump --output /tmp/nikon_ram_synthetic.bin
Python_Trace_Scripts/akeru-ramdump --simulate --dump --output /tmp/nikon_ram_synthetic.bin --resume
```

L'output di dump nuovo usa creazione esclusiva: non sovrascrive file esistenti.
Il nome dell'esempio identifica dati sintetici. Il simulatore restituisce due
intervalli fittizi1000/9000byte e8000/513byte, pattern `(address ^ (address>>8))&255`.
**Non sono intervalli RAM verificati della S33.**

Manifest, snapshot/hash, log dei test e artefatti CLI:
`Risultati/AkeruUSB_RAM_Debug/Client/latest.json`.

## Wire format proposto

Frame massimo4128byte: header32little-endian seguito da0..4096byte payload.
Header Python `<4sHHIIIIII`:

| Offset | Campo | Contratto |
|---:|---|---|
|0|magic4|ASCII AKRM |
|4|versionu16|1 |
|6|opcodeu16|1HELLO,2GET_MAP,3READ_RAM,4GET_STATUS,5ABORT |
|8|sequenceu32|incrementale per connessione; risposta deve coincidere |
|12|addressu32|indirizzo READ_RAM,0per altri comandi |
|16|lengthu32|lunghezza READ_RAM,0per altri comandi |
|20|statusu32|richiesta0; risposta0OK,1BAD_REQUEST,2BAD_RANGE,3READ_ERROR,4ABORTED |
|24|payload_lengthu32|0nelle richieste di questa versione; massimo4096 |
|28|CRC32u32|IEEE/zlib CRC sui primi28byte header concatenati al payload |

La risposta usa `opcode|8000` ed eco esatto di sequence,address,length.
Errori: payload vuoto, nessun dato fittizio. Richieste con payload o comandi
diversi vengono rifiutati dal simulatore. **Non esiste opcode di scrittura RAM/NAND.**
Vettore golden READ_RAM(seq7,address1000,length3,payloadabc) per framing/CRC:
`414b524d0100030007000000001000000300000000000000030000003897afb4616263`.
Il payload del vettore serve al test del codec; una richiesta READ_RAM effettiva
con quel payload è rifiutata dal dispositivo.

| Comando | Payload risposta OK |
|---|---|
|HELLO|32byte: ASCII AkeruRAM8,epoch16nonzero,max_blocku32,flagsu32 |
|GET_MAP|1..16coppie `(addressu32,lengthu32)` ordinate, disgiunte |
|READ_RAM|esattamente lengthbyte,1..max_block, tutto entro un singolo intervallo ammesso |
|GET_STATUS|5u32: letture riuscite,ultimo indirizzo,ultima lunghezza,ultimo stato,aborted |
|ABORT|vuoto; nel simulatore disabilita le READ successive, conserva HELLO/MAP/STATUS |

FlagsHELLO: bit0synthetic,bit1full_map; altri bit rifiutati. `atomic=false`
è invariabile del client: letture separate non costituiscono snapshot atomico.
Epoch identifica la sessione/avvio del servizio e il dispositivo; il futuro
firmware deve produrla in modo che un riavvio o una diversa macchina non possa
apparire come la stessa sessione. Nel simulatore è l'identità della fixture
immutabile. Una mappa non completa resta utile per intervalli verificati,
ma non va etichettata come dump di tutta la RAM fisica.

Il client controlla dimensione totale frame/CRC/identità risposta; whitelist
vuote, sovrapposte o che entrano nell'areaMMIO nota da0FE00000 sono rifiutate.
Il rifiuto MMIO è soltanto un limite prudenziale, non un metodo per scoprire
RAM fisica. Anche il futuro servizio deve applicare whitelist e controllo
overflow prima di qualunque dereferenziazione.

## Trasporto, timeout e annullamento

Una sola richiesta pendente. Il client gestisce frammentazione del byte-stream
entro una scadenza totale finita2000ms, non una scadenza che riparte a ogni
frammento. Conteggi zero/eccessivi, CRC/identità errati o eccezioni di trasporto
rendono la connessione inutilizzabile. **Nessun retry automatico** sulla stessa
connessione potenzialmente desincronizzata. Un errore applicativo con frame
valido è distinto da un errore del trasporto.

PyUSB legge buffer multipli del maxpacket (4608byte inHS) e conserva l'eccesso
per il parser; non richiede soltanto32byte al bus per un header quando il
dispositivo può inviare header e dati nello stesso pacchetto. Il servizio
firmware dovrà terminare ciascuna risposta con shortpacket o ZLP se la sua
lunghezza totale è multipla di maxpacket. Il binding Nikon di questo requisito
non è ancora provato. Il simulatore è un byte-stream frammentato in processo,
non emula handshake USB, ZLP, DMA o enumerazione.

ABORT è elaborato ai confini delle richieste, fra blocchi limitati4096byte.
Non dimostra interruzione IRQ/DMA di una richiesta in corso. Una READ bloccata
scade sul PC; il driver del firmware deve ancora garantire la conclusione
o la quarantena del suo buffer. Non inviare ABORT sulla connessione già
desincronizzata come se certificasse l'annullamento del controller.

## Selezione USB prudente

Trasporto reale predisposto con `--usb --vid NUMERO --pid NUMERO`, senza VID/PID
predefiniti: nessuna identità USB di produzione assegnata. Richiede configurazione
già attiva con **una sola interfaccia, alternate0,FF/41/01**, esattamente un
bulkIN e un bulkOUT con maxpacket64o512. Questi subclass/protocol sono scelte
del nuovo protocollo, da applicare anche al futuro descrittore firmware.

Non esegue set_configuration,reset,SET_INTERFACE o detach del driver kernel;
rifiuta una interfaccia già gestita da un driver e il Mass Storage08/06/50.
Dopo il claim deve riuscire HELLO. I test PyUSB usano un'API finta per controllare
selezione,claim,rilascio e letture dimensionate a pacchetti; **nessun comando è
stato inviato a un dispositivo reale**. PyUSB resta un import opzionale del
solo percorsoUSB; nessuna dipendenza è stata installata per il simulatore.

## File, errori e ripresa

`output.bin` contiene soltanto i blocchi validi concatenati. `output.bin.json`
contiene identità/epoch/capacità/mappa, per ogni blocco address,length,offset,
CRC32,status e gli errori distinti. Gli intervalli disgiunti non vengono
riempiti con zeri: usare il sidecar per ricostruire gli indirizzi.

Un errore interrompe il dump, registra indirizzo/lunghezza/status e lascia
`complete=false`; nessun byte per quel blocco viene inventato. Il caso di test
legge4096byte, riceve READ_ERROR al blocco2000, poi riprende da quel blocco
con un nuovo client e verifica tutti9513byte finali. La storia degli errori
rimane anche dopo il completamento successivo.

La ripresa richiede stessa epoch,mappa e capacità, ordine/offset/status
dei blocchi coerenti e rilettura CRC di tutti i byte già registrati. Rifiuta
cambi sessione,corruzione,troncamenti e byte aggiuntivi non registrati;
non tronca automaticamente un output ambiguo. Il dato è sincronizzato prima
di pubblicare il sidecar mediante file temporaneo univoco e sostituzione.
Un'interruzione tra i due passi può lasciare dati aggiuntivi: ripresa rifiutata
e recupero manuale, preservando entrambi i file. Non è una transazione atomica
fra due file né una garanzia contro ogni perdita di alimentazione.

## Stato rispetto all'obiettivo intero

`AkeruOS/usb_ram.c/.h` implementa i cinque comandi con soli frame completi,
whitelist ordinata1..16regioni,limiti/overflow/MMIO,CRC e lettura tramite callback
con contratto copia-esatta o errore. Usa la struttura regioni e costanti del
motore RAM esistente, senza chiamarne file/SD o supporre indirizzi Nikon.
Il chiamante fornisce epoch,flags,mappa e buffer risposta4128byte dedicato;
nessuna allocazione o stato globale. ABORT impedisce letture successive,
non pretende di interrompere DMA già in corso.

`make -C AkeruOS usb-ram-core-verify`: **18risposte wire C identiche byte per
byte al simulatore Python e10rifiuti configurazione/framing/buffer**, callback
RAM chiamata soltanto4volte nei casi ammessi,guardie memoria intatte e richiesta
immutata. TestC host con ASan/UBSan; compilazione ARC700 senza simboli irrisolti,
data/BSS0 e senza rilocazioniSDA. Il verificatore ora esegue anche lo stesso
oggetto ARC700 nel simulatore GNU fissato del progetto. Manifest:
`Risultati/AkeruUSB_RAM_Debug/Core/latest.json`.
Il caso callbackfallita scrive dati nel buffer ma ritornaerrore: il frame C
invia solo header32/status3,payload0,identico al riferimento Python.

### Esecuzione GNU ARC700 — 24 ottobre 2026, 15:15:03 UTC

Evidenza: `Risultati/AkeruUSB_RAM_Debug/Core/20261024T151503Z/verified_evidence.json`,
con manifest GNU separato in `gnu/verified_evidence.json` e comandi/log/disassemblato.
Il simulatore esegue **375.810 istruzioni**, uscita0,nessun fault: gli stessi
18casi confrontano sul guest tutti i byte delle risposte con vettori verificati
contro il riferimento Python. Passano10rifiuti e4callback RAM, richieste immutate
e guardie16byte intatte prima/dopo il buffer. Passa anche il test hostASan/UBSan.

Il medesimo sorgente `AkeruOS/tests/usb_ram_test.c` serve host e guest;
nel guest le operazioni file sono sostituite da vettori costanti e confronti,
senza libc né simboli irrisolti. Startup di laboratorio a0x1000, stack16KiB
esplicito: nessun reset vector, hook o servizio Nikon viene esercitato.
L'oggetto del nucleo resta1564byte di testo,data/BSS0.

Motore GNU SHA-256
`7d6ccd1bc2291f377201e8cd1027c6ecf94d30901f13251c1c6bf647aa8a43dc`,
riusato tramite Podman senza rete, alberoGNU montato sola lettura; hash degli
input preservati. Nessuna ricompilazione/modifica del simulatore o del firmware.
Il callback genera byte da una formula sugli indirizzi e un errore esplicito:
**non dereferenzia RAM Nikon e non usa endpoint, DMA, IRQ o MMIO del controller**.
Questa è esecuzione CPU ARC del servizio, distinta dalla simulazione Python,
dall'esecuzione P-code delle routine USB e dalla prova hardware ancora assente.

Client e dispositivo sintetico coprono i cinque comandi,checksum,timeout,
frammentazione,errori e ripresa. La prova USB originale35casi è distinta:
`S33_AkeruUSB_RAM_Debug_Contratto_Trasferimenti_20261024.md`.
Produttori/callback/cancel originali ora verificati su GNU in44casi e2polling
limitati dalle fixture: `S33_AkeruUSB_Worker_Callback_e_Annullamento_GNU_20261024.md`.
Mancano binding del nucleo C a lettore RAM e whitelist fisica verificata,endpoint/worker/IRQ
e annullamento/buffer,inizializzatore dedicato,residenza e compatibilità boot.
Installazione,avvio e recupero fisico non verificati: nessuna prova hardware
autorizzata o eseguita da questo lavoro. Il goal resta attivo.
