# AkeruUSB — contratto delle funzioni USB superiori Nikon

Continuazione: [produttori,callback e annullamento su GNU](S33_AkeruUSB_Worker_Callback_e_Annullamento_GNU_20261024.md),
44casi+2polling. Riduce i confini del presente banco;controller ed endpoint
restano fixture e le35prove superiori qui descritte conservano i propri limiti.

24 ottobre 2026. **35scenari CPU PASS** sui corpi originali send`1908DC`,
receive`1906B4` e getter configurazione`190528`. Ricostruiscono stato,conteggi,
pubblicazione del buffer e uscite in errore. Non trasferiscono payload fisico
e non certificano ancora il controller o la durata DMA del buffer.

Riproduzione: `python3 Python_Trace_Scripts/s33_verify_akeru_usb_transfers.py`.
Probe: `S33-sections/analysis_ghidra/scripts/ProbeAkeruUSBTransfers.java`.
Evidenza con snapshot/hash16payload,sorgenti,finestreGNU e traccia:
`Risultati/AkeruUSB_RAM_Debug/Transfers/latest.json`.

## Risultati per il futuro adapter

| Condizione nel modello | Send e receive originali |
|---|---|
| Completamento con64byte | status0,count64 |
| Completamento parziale17 | **status0,count17** |
| Count65su richiesta64 | **status0,count65**: il livello superiore non ne controlla il limite |
| Wait0,eventi0 | status0,conteggio fornito dal worker; nessuna obbligatorietà del bit completion |
| Query evento restituisce777 | ignorato/rimpiazzato dal canale bit nel caso; status0 |
| Bit15 |02200105 |
| Bit16 o bit15+16 |02200341, precedenza del bit16 |
| Acquire risorsa999 |errore999, nessun release/notifica |
| Release risorsa888 |ignorato nel risultato del caso normale, status0 |
| Buffer nullo |02200100 |
| Lunghezza0 |status0,count0, nessuna risorsa acquisita |
| Contesto assente o configurazione0 |02200003; il getter anticipa il ramo no-context inferiore |
| Endpoint nullo |02200342 |
| Halt predicato nonzero |02200343 |

Nel send, wait-error200305 conserva quell'errore, lascia il count di uscita
inizialeA5A5A5A5 e il flag active1, poi rilascia la risorsa. Nel receive,
lo stesso wait-error viene trasformato in02200103, raggiunge il confine cancel
`1905D8`,lascia count iniziale e active1 nel modello e rilascia la risorsa.
**Il confine cancel è simulato: active1 non prova cosa farà il controller reale.**

Il receive normale richiede wait5000ms; il nono argomento stack nonzero
sceglie wait0. Send usa wait0 nei casi provati. Il valore20 passato nel quarto
argomento viene pubblicato per il worker; non è il timeout superiore di quel
wait. Non interpretare i due tempi come un unico contratto.

## ABI e storage osservati

Entrambe ricevono buffer inr1,lengthr2,parametro worker inr3,count-outr4.
Send conserva inoltre il flagr5; receive usar6 e legge il nono argomento dal
frame stack originale. Non viene qui dichiarata una firma pubblica completa
per tutti gli argomenti non consumati nei rami provati.

Contesto corrente: cella`368114`, che coincide con globaleUSB`3680A0+74`.
Record trasferimenti`423C00`: sendbuffer+0,length+4,count+8,parametro+12,
activebyte+16. Receivebuffer+20,length+24,count+28,parametro+32 e activebyte+36.
Evento`02200001`: notifica worker100send/200receive,maschere wait19000/1DA000.
Risorsa comune`02200005`. Questi sono slot globali condivisi: non avviare
due richieste indipendenti come se ciascuna possedesse un record privato.

Il probe controlla notifica,acquire/release,registrazione buffer,stack,
registri callee-saved e nesting dei critical simulati. Receive raggiunge anche
cleanup buffer`17FAA4(-1,-1)`; send non lo chiama nei rami provati. Non attribuire
a queste chiamate un rilascio fisico DMA senza seguire il consumatore reale.

## Confini espliciti

Sono fixture: predicato connessione`263DDC`,halt`19059C`,prereceive`1905D4`,
cancel`1905D8`,query controller`243B2C`,critical,registrazione/cleanup buffer,
risorsa e tutti i servizi evento. Count/event bits/errori sono input controllati;
oversized è un input deliberatamente impossibile per misurare i controlli,
non un comportamento osservato della periferica. Il buffer rimane invariato.
Il wait non esegue scheduler o scadenza reale; il controller e l'IRQ non girano.

Tentativi iniziali conservati: eliminato blocco memoria sovrapposto al payload1;
corrette attese del probe sul caso contesto assente e sulla traduzione timeout
receive. Nessun byte Nikon cambiato per far passare la matrice.

**Conseguenza:** l'adapter AkeruUSB deve inizializzare count,verificarne il limite
e distinguere stato/numero byte/completamento/ownership. Su errore o timeout
non riusare un buffer soltanto perché la funzione è ritornata o la risorsa è
stata rilasciata. Prossimo: worker consumatore di423C00 e annullamento originale,
endpoint/DMA/cache e notifiche reali,prima di legare il servizio C al trasporto.
Il client/protocollo sintetico può essere sviluppato separatamente senza
spacciare questi confini per un driver completo. Nessun hardware,NAND/SD o
firmware installabile: **NON_INSTALLARE**.
