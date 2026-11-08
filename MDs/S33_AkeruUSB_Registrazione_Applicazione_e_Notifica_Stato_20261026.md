# AkeruUSB — registrazione applicazione e notifica di stato originali

26 ottobre 2026. Ricerca offline verso il dump RAM. **NON_INSTALLARE**.

Il banco AkeruRAM ora usa l'API originale `278578` per associare la tabella
applicativa e il percorso registrato `278BC4 → 27DB3C → 27A6A0 → 278B00`
per aggiornare il campo pubblico+0x14. Non scrive direttamente pubblico+0x48
e non chiama direttamente il setter278B00 per abilitare l'apertura.
Le implementazioni dei callback applicativi e le letture MMIO restano fixture.

**PASS GNU ARC700, 2.696.567 istruzioni, uscita0, nessun fault.**
Due sessioni maxpacket64/512:36 scambi AkeruRAM,72 submit/completamenti/free,
22 chiamate di registrazione,10 di deregistrazione,8 notifiche di stato
e8 casi con notifica mascherata. Totale93 ingressi nel callback registrato.
ASan/UBSan host e la suite delle guardie sul medesimo adapter restano PASS.

## Evidenze e riproduzione

```sh
PYTHONDONTWRITEBYTECODE=1 make -C AkeruOS usb-ram-application-verify
```

- [Banco C](../AkeruOS/tests/usb_application_gnu_test.c).
- [Verificatore](../Python_Trace_Scripts/s33_verify_akeru_usb_application.py).
- [Esito CPU, hash, contatori e limiti](../Risultati/AkeruUSB_RAM_Debug/Application/20261026T185648Z/verified_evidence.json).
- SHA256 esito: `ccae145c056b0d6c8ada5855747a87966c493e7e02213af4c2ca408053ef1d2a`.

Ricontrollati164 artefatti,35 input e contenuto decompresso della traccia
gzip. Le sezioni originali nell'ELF coincidono con i byte del payload V1.1.
GNU, firmware originali e precedenti sorgenti di test restano invariati.
Il banco riusa i prefissi dei test dispositivo e trasporto già verificati.

## Correzione dell'interpretazione di pubblico+0x14

Nei rapporti precedenti il valore1 iniettato in pubblico+0x14 era descritto
come stato configurato. Questa attribuzione non era provata e viene ritirata.
L'esecuzione originale qui mostra una provenienza più precisa:

1. Il dispatcher dispositivo valuta il bit13 dello stato mascherato.
2. `27A6A0` richiama `2DBC74` e aggiorna dispositivo+8 a1.
3. `27A660` legge un selettore a2 bit dalla word del controller aBASE+0x808,
   precisamente `(word >> 1) & 3`.
4. Il valore ricavato passa attraverso lo slot0 della vtable dispositivo,
   costruita dal setup originale: `278B00` lo scrive in pubblico+0x14.

| Selettore iniettato | Codice scritto in pubblico+0x14 |
|---:|---:|
| 0 | 3 |
| 1 | 2 |
| 2 | 1 |
| 3 | 2 |

Il gate di apertura verifica che questo campo sia nonzero; non dimostra
una transazione USB SET_CONFIGURATION. Il codice è compatibile con una
classificazione della velocità, ma l'attribuzione fisica ai singoli valori
non è verificata da questo banco. I descrittori64/512 sono parametri di test;
non sono certificati rispetto ai diversi selettori di stato simulati.

Con maschera0, il campo conserva il valore precedente e non entra
nell'handler. Con bit13 abilitato avviene la notifica tramite vtable.
Gli otto casi ammessi eseguono effettivamente handler, decodifica e setter;
gli otto casi mascherati non lo fanno. Nessuna lettura RAM del servizio
AkeruRAM, allocazione di nodo o completamento dati è causato dalla notifica.

## Contratto dell'API applicativa

`278578` riceve la tabella applicativa in r0. Controlla che non sia nulla
e che i campi+4/+8/+C/+10/+14 siano nonzero. Il campo+4 non viene invocato:
nel costruttore originale contiene3. Non va trattato come un callback.

| Caso eseguito | Esito originale |
|---|---|
| Tabella nulla o uno dei cinque campi richiesti nullo | -7, nessuna associazione |
| Contesto globale nullo con tabella valida | -4 |
| Applicazione già associata | -5, nessuna seconda inizializzazione |
| Inizializzazione applicativa con esito-17 | -17; pubblico+0x48 e+0x38 vengono azzerati |
| Inizializzazione applicativa con esito0 | 0, associazione conservata |

Prima dell'inizializzazione, l'API scrive pubblico+0x48=tabella e
pubblico+0x38=tabella+32. Il callback a tabella+8 riceve pubblico+4;
il banco verifica ordine, argomento e visibilità di entrambe le associazioni.
Il rollback dei due puntatori non prova che un callback reale abbia
annullato eventuali altre allocazioni o attività.

`278610` richiede esattamente la tabella associata; NULL, un altro puntatore
o una tabella già rimossa danno-7. Invoca il callback a tabella+C con
pubblico+4, poi azzera pubblico+0x48. Nei due casi di shutdown per sessione
il callback restituisce-19 e0: l'API restituisce0 in entrambi.

**La deregistrazione lascia pubblico+0x38=tabella+32.** Il test lo controlla
e non interpreta il ritorno0 come prova di quiescenza, annullamento DMA o
permesso di liberare la tabella e i buffer. Tutte le deregistrazioni di
questo banco avvengono senza richieste pendenti.

## Chiamante della classe originale: evidenza statica

La finestra ancorata a `190408` costruisce una tabella in RAM a `47DA9C`
e raggiunge l'API con il tailcall `190432 → 278578`.
Il verificatore conserva la disassembly e controlla i literal del payload.
I valori ricostruiti sono:

| Offset tabella | Valore costruito |
|---:|---|
| +0 | 349034 |
| +4 | 3 |
| +8 | 191A04, inizializzazione |
| +C | 1919D4, shutdown |
| +10 | 191570 |
| +14 | 19199C |
| +18 | 191A60 |
| +1C | 191B08 |
| +20 | 349044 |

`191B0C → 278610` è un ulteriore chiamante diretto osservato nella ricerca
lineare, mentre `278D4C` raggiunge la stessa API durante la distruzione del
contesto. Il censimento lineare non esclude altri chiamanti indiretti o
istruzioni nascoste da pool dati. La copia integrale di queste routine di
classe non è stata eseguita: il banco usa propri callback applicativi.
Le aree RAM47DA9C e i puntatori descrittore non sono dichiarati liberi o
utilizzabili dal dumper.

## Scambi RAM dopo la registrazione

Dopo la registrazione, pubblico+0x14 resta0 e l'apertura restituisce-58.
Dopo le notifiche originali l'apertura dei due endpoint riesce. Seguono
i18 vettori AkeruRAM per sessione, con risposte identiche al riferimento
Python prima e dopo il completamento TX. Il core viene chiamato nel task
modellato dopo il ritorno dal callback/free, mai durante la notifica IRQ.

Sono conservate segmentazione4128IN e richiesta vuota IN del banco
[adapter](S33_AkeruRAM_Adapter_Asincrono_e_USB_Originale_20261026.md):
76 ingressi in2DBFB8, uno in2DC214 e72 completamenti dati. Gli altri16
ingressi nel callback registrato sono le prove di notifica/mask di stato.

## Limiti e prossimo passo

Risorse, allocatore, callback applicativi, dati RAM, payload DMA, capability,
letture/scritture MMIO, IRQ registration e consegna eventi/task sono modellati.
La manutenzione cache/barriere e la quiescenza fisica restano da provare;
il modello DSP GNU preesistente è provvisorio.128 MiB sintetici non sono
una mappa RAM fisica. Nessun trasferimento USB o dump della fotocamera.

Prossimo lavoro: seguire inizializzazione/shutdown della classe originale
`191A04/1919D4`, interfaccia pubblico+4 e passaggio evento/task, poi cancel
e cache. Whitelist RAM fisica, residenza, boot e recupero restano aperti.
Nessun comando hardware, NAND, SD o installazione eseguito. **NON_INSTALLARE**.
