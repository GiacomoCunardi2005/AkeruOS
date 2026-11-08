# S33 — errori di acquisizione e confine del recupero

Analisi locale del 18 ottobre 2026, campione V1.1. Nessuna esecuzione del firmware o operazione sulla fotocamera. Continuazione R2 della [gestione delle risorse](S33_Descrittori_e_Ciclo_Buffer.md) e dell'[ingresso acquisizione](S33_Ingresso_Acquisizione.md).

## Risultato

Le uscite di errore di `0x18ED60` e `0x1B8F24` sono ora distinte dal percorso che pubblica il buffer per ImgMgr. In particolare, se l'estrazione del buffer riesce ma non si trova un descrittore libero, il corpo locale conserva il puntatore all'acquisizione corrente ed esce senza ripubblicarlo. La pulizia condizionale già ricostruita richiede invece quel puntatore nullo: non basta invocarla per dimostrare il recupero di questo caso.

Questo identifica un requisito ancora mancante per AkeruOS, **non dimostra una perdita di risorse nel firmware Nikon**: la raggiungibilità del caso dipende dagli invarianti originali e possono esistere altri percorsi di recupero. R2 resta parziale; avanzamento funzionale invariato, circa 10%.

## 1. Il booleano della riserva e lo stato del servizio sono distinti

`0x18E204` riceve l'indirizzo di una cella di uscita. Trovato un record con stato zero, a `0x18E22A..30` scrive il puntatore nella cella, imposta stato 1 e restituisce **1**. Con argomento nullo o ricerca esaurita restituisce **0**, a `0x18E23A`; in quei casi non scrive la cella. Non è il contratto «zero significa successo» del servizio superiore.

In `0x18ED60`, con primo argomento nullo e senza acquisizione corrente:

| Condizione | Istruzioni e risultato locale |
|---|---|
| Estrazione da A fallita | `0x18EDBE/C2 → 0x18EDD8`: carica il valore `0x40100003`, poi `0x18EDDA → 0x18EE3C`; salta le scritture nella cella del chiamante |
| Estrazione riuscita, riserva descrittore restituisce zero | `0x18EDCC → 0x18E204`, `0x18EDD0 → 0x18EDD8`: stessa uscita immediata; l'elemento estratto rimane in contesto `0x368024+0x1C` nel tratto locale |
| Entrambe riuscite | `0x18EDD2` legge elemento+8; `0x18EE12` pubblica il descrittore nella cella del chiamante e il seguito ne popola i campi |
| Preparazione pool restituisce un errore | `0x18EDAA → 0x18EE06 → 0x18EE2A`: evita le scritture di uscita, esegue il controllo di disponibilità e ritorna lo stato conservato in `r14` |

Il letterale **`0x18EE4C = 0x40100003`** viene verificato nei byte originali. Lo stesso numero è usato come identificatore del canale eventi risorse in altre chiamate: questo non gli assegna automaticamente un nome semantico di errore. Le due uscite immediate non inizializzano a zero la cella del chiamante e non attraversano `0x141E14`. Lo zero iniziale a `fp-36` è una cella **locale**, distinta da quella del chiamante.

Non è presente, lungo queste due uscite locali, una chiamata che reinserisca il buffer in A, lo pubblichi in B o azzeri acquisizione corrente. Il perimetro della constatazione è il ramo seguito fino all'epilogo; non comprende effetti asincroni o tutti i chiamanti.

## 2. L'acquisizione già corrente richiede un invariante aggiuntivo

Se la preparazione del pool ritorna zero ma `contesto+0x1C != 0`, `0x18EDB2` salta a `0x18EE06` evitando estrazione e riserva. Nel flusso locale ricostruito `r14` è zero e la cella del descrittore a `fp-36` conserva l'inizializzazione zero. Il percorso raggiunge quindi la scrittura del puntatore nullo nella cella del chiamante a `0x18EE12`, seguita dall'accesso tramite quel puntatore a `0x18EE16`.

È una sequenza statica da conservare come **limite di validità dell'ingresso**. Non viene dichiarato un crash osservato o un difetto del dispositivo: restano da verificare raggiungibilità, mappa degli indirizzi bassi, concorrenza e invarianti del chiamante. Non si può descrivere questo ramo semplicemente come «ritorno zero senza lavoro».

## 3. Le uscite superiori evitano la pubblicazione normale

Nel ramo diverso dal discriminante `0x10`, `0x1B9004` chiama il servizio, `0x1B900A` conserva il risultato in `fp-188` e `0x1B900E` salta direttamente a **`0x1B93BC`** se nonzero. Se il servizio restituisce zero ma la cella è nulla, il codice scrive ancora `0x40100003` nello stato locale e prende la stessa uscita a `0x1B9020`. Per questo letterale ARC scalato l'indirizzo corretto è `(0x1B9018 & ~3) + 176*4 = 0x1B92D8`.

Altre uscite verificate verso quell'epilogo:

- `0x1B904A`: risultato nonzero del servizio `0x12B0DC`, dopo l'allocazione;
- `0x1B90FA`: errore del preparatore `0x1BA558`, con delay slot conservato;
- `0x1B91AA/BA`: errore di CapMgr `0x14AA24`, con due chiamate aggiuntive soltanto nel ramo in cui `0x141ED8()` vale 1. Non sono state attribuite qui a restituzione del buffer.

Tutte queste uscite saltano **`0x1B93B0 → 0x18EE50`**, il passaggio normale verso la coda B, e le due chiamate immediatamente successive. L'epilogo legge lo stato da `fp-188`. Il wrapper `0x1B9EA8` lo conserva e lo passa come argomento dell'evento `0x7CE2` a `0x1B9F28`: la notifica dell'esito resta distinta da una prova di restituzione delle risorse.

Il discriminante `0x10` mantiene un ciclo diverso, già documentato nel rapporto d'ingresso; non si estende a quel ciclo la propagazione del singolo stato descritta sopra.

## 4. Disponibilità e scarto non completano da soli il recupero

`0x141E14` inoltra a **`0x18E72C`**. Quest'ultima controlla il pool attivo, il risultato «coda A vuota» e `0x18E2D8`. Quest'ultimo helper chiama `0x18E29C(0)` e restituisce **1 quando non trova un descrittore in stato zero**, altrimenti zero. Se A è vuota oppure manca un record libero, il predicato può richiedere la cancellazione della maschera 16 sul canale `0x40100003`. Non reinserisce un buffer e non azzera il puntatore corrente nel corpo esaminato.

La pulizia **`0x18E680`**, già collegata a CaptureImage, legge acquisizione corrente a `0x18E6AA` e, se nonzero, a `0x18E6AE` salta a `0x18E6FE`, evitando il drenaggio e il reset. Anche la chiusura ordinaria richiede acquisizione corrente nulla. Pertanto il buffer conservato dopo riserva fallita non è spiegato dal solo protocollo di scarto già noto.

**Prossimo passo R2:** individuare gli scrittori che azzerano o trasferiscono `0x368040` sui percorsi d'errore e collegarli al consumatore `0x7CE2`; verificare se gli invarianti impediscono l'esaurimento dei descrittori dopo estrazione. Poi completare esiti worker/scrittura/chiusura e ultimo uso dei puntatori. Nessuna di queste osservazioni prova già disponibilità del prossimo scatto o persistenza SD.

## Continuazione: scrittori e reset collegati

Il [rapporto acquisizione corrente e reset](S33_Acquisizione_Corrente_e_Reset.md) distingue ora sei scritture dirette al campo globale dagli alias del contesto worker. Collega AutoScene a `0x1435FC → 0x18E41C`, con attesa e scarto precedenti non verificati nel chiamante. Il reset viene saltato se configurazione richiesta e corrente coincidono: non chiude il recupero universale. Il prossimo nodo è la transizione della configurazione risorse, insieme a `0x2019C0` e agli invarianti sui descrittori.

## Evidenze e riproduzione

Eseguire dalla radice attuale:

```bash
python3 Python_Trace_Scripts/s33_trace_acquisition_errors.py
```

[Script](../Python_Trace_Scripts/s33_trace_acquisition_errors.py), [JSON](../Ghidra_Results/ghidra_reports/acquisition_errors/verified_evidence.json), [disassemblaggio GNU](../Ghidra_Results/ghidra_reports/acquisition_errors/gnu_verified.txt). Esito: **16 blocchi verificati per dimensione/SHA-256, roundtrip ELF del blocco 00 identico, 18 finestre ARC700 e 22 collegamenti controllati**. Il JSON conserva hash dello script, hash dei payload, finestre e limiti. Le finestre ripartono da ingressi noti per evitare disallineamenti dovuti ai pool dati della disassemblazione lineare.

REA MCP non è disponibile in questa sessione; la diagnosi del client rileva registrazione assente. L'analisi usa GNU ARC700 locale e non modifica la configurazione degli strumenti. Non è un nuovo risultato del decompilatore Ghidra. Il campione V1.1 e i log hardware V1.0 restano distinti.
