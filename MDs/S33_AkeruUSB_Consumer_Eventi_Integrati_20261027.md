# AkeruUSB — consumer TX/RX e notifiche evento integrate

27 ottobre 2026. Ricerca offline verso il dump RAM via software.
**NON_INSTALLARE**. Nessun accesso alla fotocamera.

L'ipotesi della prova precedente è stata verificata nello stesso scenario
di laboratorio: consumer originali TX `1908DC` e RX `1906B4`, notifica di
classe `19199C`, e API evento originali SET/WAIT/query/CLEAR sono eseguiti
insieme. Due banchi indipendenti passano ciascuno **8 casi**: Ghidra P-code
e GNU ARC700. La sequenza di chiusura e l'auto-clear sono introdotti dal banco;
non sono osservazioni del normale funzionamento della fotocamera.

Se il bit close viene pubblicato prima del wait:

| Causa immessa | Auto-clear | Risultato TX e RX | Conteggio |
|---|---:|---:|---:|
| Close `00010000` | 0 | `02200341` | 0 |
| Close `00010000` | 1 | `0` | 0 |
| Bit di completamento sintetico | 0 oppure 1 | `0` | 0 |

Nell'ultimo caso il banco pubblica il bit di completamento direttamente e
non trasferisce dati: non è una prova di un vero completamento USB a zero
byte. In tutti i casi il flag software active del consumer torna a 0, ma
questo non dimostra che il DMA o il controller abbiano smesso di usare il
buffer. L'auto-clear 1 è un valore iniettato, non una configurazione runtime
accertata della Nikon.

## Evidenze e riproduzione

```sh
PYTHONDONTWRITEBYTECODE=1 python3 Python_Trace_Scripts/s33_verify_akeru_usb_event_consumer.py
PYTHONDONTWRITEBYTECODE=1 python3 Python_Trace_Scripts/s33_verify_akeru_usb_event_consumer_gnu.py
```

- [Banco P-code](../S33-sections/analysis_ghidra/scripts/ProbeAkeruUSBEventConsumer.java),
  [verificatore](../Python_Trace_Scripts/s33_verify_akeru_usb_event_consumer.py),
  [traccia delle 8 combinazioni](../Risultati/AkeruUSB_RAM_Debug/Event_Consumer/20261027T110243Z/trace.txt),
  [manifest](../Risultati/AkeruUSB_RAM_Debug/Event_Consumer/20261027T110243Z/verified_evidence.json).
  SHA256 manifest `0136ee0d768204438c1df302b66b7a4baed4c6614edf7f9ee5c87b0eb7ddf5b5`.
- [Banco GNU C](../AkeruOS/tests/usb_event_consumer_gnu_test.c),
  [verificatore](../Python_Trace_Scripts/s33_verify_akeru_usb_event_consumer_gnu.py),
  [manifest GNU](../Risultati/AkeruUSB_RAM_Debug/Event_Consumer_GNU/20261027T110411Z/verified_evidence.json):
  8 casi, 22.372 istruzioni, uscita 0 e nessun fault. SHA256 manifest
  `f7f4f83b096e42e49ff0bb7fa0339d8414342bdc71943dbfb34ef70307054005`.

Il banco GNU controlla nel C i risultati di tutti gli 8 casi e verifica la
traccia: 4 ingressi RX, 4 TX, 4 notifiche classe, 8 wait e 8 query. Il
verificatore confronta le sezioni ELF con i byte originali V1.1. Ricontrollati
17 input e 69 artefatti GNU; per P-code verificati gli hash degli input e
della traccia. I tentativi P-code `110202Z` e `110223Z` restano FAIL: il
primo banco non aveva previsto lo slot fixture di pre-cancel RX, attraversato
quando active RX è 1. Aggiunto lo slot al solo banco; nessuna istruzione
firmware è stata cambiata.

## Cosa è stato eseguito

I due banchi inizializzano record evento `373308`/ID `02200001`, oggetto
kernel, task corrente, lista waiter vuota ed endpoint sintetici. Il consumer
originale cancella i vecchi bit di wait e pubblica la richiesta al worker.
Il banco introduce quindi una delle due cause: chiama il callback originale
di classe `19199C`, oppure pubblica direttamente un bit di completamento
tramite il setter originale. Seguono wait già soddisfatto, query e clear
originali; il consumer interpreta il risultato e rilascia la risorsa fixture.

Nel banco P-code la chiamata annidata C-ABI è inserita all'ingresso del wait;
stack e registri callee-saved vengono controllati prima di riprendere il
wait. Nel banco GNU un hook sostituisce il confine scheduler `B2D34` durante
il SET della notifica worker e inserisce la causa prima del wait. Sono due
tempi di inserimento controllati; nessuno rappresenta consegna IRQ fisica o
uno scheduler avviato. Nel caso RX close la classe tenta anche pre-cancel:
il relativo slot e le due chiusure endpoint sono fixture che restituiscono
-7. La classe continua comunque e pubblica il bit close.

Il kernel/task, la lista eventi, l'attivazione del record, l'auto-clear e
gli endpoint sono preparati. Le risorse, i predicati connessione/halt,
cache registration/cleanup, logger, endpoint close e pre-cancel sono
fixture; nel banco GNU anche il confine scheduler è fixture. RX usa timeout
0 fornendo il nono argomento; la scelta del ramo di divisione RX differisce
tra i due banchi. Il buffer rimane `A5` e il count rimane 0: non c'è stato
trasferimento di payload o accesso a RAM fisica Nikon.

## Implicazione per AkeruRAM

In un futuro binding che passasse direttamente il risultato RX `status=0,
actual=0` all'adapter attuale, `akeru_usb_ram_transport_received` lo tratta
come frame non valido, ritorna 0 e rimette lo stato in `RX_READY`. Il test
esistente [delle guardie](../AkeruOS/tests/usb_ram_transport_test.c) copre
già lunghezza zero. Quindi, nella condizione sintetica provata, il solo
stato/count non basta al chiamante per distinguere close da un frame scartato;
è necessaria una notifica di lifecycle affidabile prima di decidere se
riarmare. Questa è una conseguenza condizionale del contratto attuale, non
un binding già eseguito. La precondizione dell'adapter che richiede
quiescenza del backend prima di invocare la completion resta valida.

## Limiti e passi aperti

Non sono provati configurazione auto-clear, ordine effettivo di disconnessione,
task realmente sospeso/risvegliato, IRQ, DMA, cache o dati trasferiti sulla
fotocamera. Rimangono da integrare il ciclo worker/task e la prova della
quiescenza, oltre a whitelist RAM fisica, residenza, boot e recupero. Il
modello DSP GNU è provvisorio e 128 MiB sintetici non sono una mappa fisica.
