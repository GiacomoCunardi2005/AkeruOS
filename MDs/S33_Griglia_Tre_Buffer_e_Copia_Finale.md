# S33 — griglia, tre buffer e copia finale

Analisi statica V1.1, 19 ottobre 2026. Continuazione dell'[interpolatore a due componenti](S33_Interpolazione_Griglia_due_Componenti.md). Nessuna esecuzione sulla fotocamera.

## Risultato

Collegati tre ruoli distinti nel percorso selezionato del worker:

| Campo del payload worker | Uso ricostruito |
|---|---|
| +0 | buffer di lavoro: coordinate della griglia, poi coppie di campioni dopo l'interpolazione |
| +4 | destinazione finale dei cicli di scrittura halfword verificati |
| +`0x10` | puntatore alla sorgente dei campioni, pubblicato a `0x369604` e letto dall'interpolatore |

È stato seguito un ramo semplice del fallback che **costruisce la griglia**, chiama l'interpolatore che la **sovrascrive**, quindi legge i campioni dallo stesso buffer e li **trasferisce alla destinazione finale con shift di un bit**. Questo raccorda preparazione, elaborazione e copia nei tratti selezionati. Allocazione, esclusività e rilascio finale restano aperti. Stima funzionale: circa 10%.

## 1. Puntatore sorgente pubblicato dal backend

Il worker carica r0/r1/r2 da payload+0/+4/+`0x10`. I wrapper conservano e inoltrano questi registri ai due backend già verificati.

| Backend | Scrittura |
|---|---|
| `0x1FE470` | `0x1FE4BE`: r2 → controllo `0x3695DC+40` |
| `0x200620` | `0x20066E`: r2 → controllo `0x3695DC+40` |

L'offset 40 è in byte: **`0x3695DC+0x28 = 0x369604`**. Le chiamate dell'interpolatore caricano poi r4 da questa cella a `0x1FD9D4`, `0x1FE0DE` e `0x200440`.

La sorgente dell'interpolatore viene quindi dal terzo argomento del backend. Non va confusa con il suo r0: r0 alimenta il buffer di lavoro, usato come sorgente dai successivi cicli di copia dopo essere stato trasformato in campioni.

Questa è una catena statica diretta. Non prova che nessun altro task o alias possa modificare la cella condivisa; la sincronizzazione resta da verificare.

## 2. Preparazione dei due buffer di lavoro e destinazione

Il backend fallback conserva r0 in r25 e r1 a stack+`0x1C`; al sito `0x1FE6FC` li inoltra a `0x1FD614`. Questa routine conserva r0 in r13 e r1 a stack+4.

Il backend preferito conserva r0 in r22 e r1 in r23; al sito `0x2007DC` li inoltra a `0x1FEAA0`. Come documentato nel rapporto precedente, questa routine conserva r0 in r18 e r1 a stack+4.

Il significato di uno stesso registro cambia tra livelli. In particolare, il terzo argomento delle routine inferiori non viene automaticamente identificato con il puntatore sorgente del backend: quest'ultimo è già passato attraverso la cella `0x369604`.

## 3. Costruzione della griglia nel ramo semplice del fallback

Nella routine `0x1FD614`, il byte letto in ingresso viene confrontato con 2 a `0x1FD6B6`; il ramo a `0x1FD736` separa la continuazione più complessa. Nel tratto inferiore a 2, il successivo confronto a `0x1FD740` seleziona i due costruttori verificati:

- valore 0: ciclo `0x1FD7A8..812`;
- valore 1: ciclo `0x1FD826..892`, con un offset aggiuntivo di 16 sulla prima coordinata.

Questo byte è un argomento della routine inferiore; **non viene equiparato al selettore globale `0x369620`**, che è un altro dato.

I costruttori usano il buffer r13 come tabella di coppie halfword. Nel primo ciclo r9/r10 derivano da r13 e avanzano di quattro byte per punto. La prima halfword contiene il valore costruito dall'indice di riga; la seconda quello costruito dall'indice di colonna.

Quando la colonna coincide con il limite in r4, il codice conserva la coordinata corrispondente. Per le colonne successive scrive quella stessa coordinata, invece di continuarne la crescita. Il secondo costruttore presenta lo stesso schema con registri differenti.

Nel dominio dei contatori senza avvolgimenti, posto `s` lo shift di controllo caricato nel tratto precedente, la struttura locale è compatibile con:

```text
coordY = u16((riga << (s+5)) + (argomento_byte == 1 ? 16 : 0))
coordX = u16(min(colonna, limite_colonna) << (s+4))
```

La formula descrive questi due cicli: non è una specifica universale delle griglie prodotte da tutti i rami. Numero di righe/colonne ammesso, dimensione dell'allocazione e significato delle unità rispetto alla modalità della fotocamera restano aperti.

## 4. Griglia → campioni → destinazione finale

Dopo il costruttore selezionato, il tratto di preparazione converge sulla chiamata **`0x1FD9F2 → 0x1FD4E4`**. Qui:

- r3 viene ripreso da r13, quindi punta alla griglia costruita;
- r4 viene letto da `0x369604`, quindi punta alla sorgente dei campioni;
- le due parole della griglia vengono lette dal corpo dell'interpolatore e sostituite con il risultato, come verificato dal modello precedente.

Al ritorno, il ciclo **`0x1FDA1A..58`** rilegge halfword dal buffer r13 e scrive nella destinazione caricata da stack+4. Ogni lettura del tratto interno passa attraverso uno shift aritmetico di un bit prima della scrittura halfword.

L'ordine e gli offset sono rilevanti: il ciclo interno comincia con la lettura a sorgente+2, poi legge a +4 con avanzamento, e usa offset analoghi in destinazione. **Non viene qui dichiarata una copia integrale a partire dal byte zero**, né una prova che tutti i byte della destinazione siano inizializzati.

La catena verificata nei tratti selezionati è:

```text
payload+0: coordinate scritte nel buffer di lavoro
                     ↓
payload+0x10 → cella 0x369604 → sorgente dell'interpolatore
                     ↓
buffer di lavoro sovrascritto con coppie di campioni
                     ↓
letture halfword, shift di un bit, scritture verso payload+4
```

Altri rami inferiori costruiscono o trattano i dati in modo diverso. Non si presume che questi tre puntatori identifichino allocazioni disgiunte, che la griglia sopravviva alla chiamata, o che il completamento locale autorizzi ogni successivo riuso.

## Evidenze e prossimo passo

[Script](../Python_Trace_Scripts/s33_trace_grid_buffer_flow.py), [JSON](../Ghidra_Results/ghidra_reports/grid_buffer_flow/verified_evidence.json), [GNU](../Ghidra_Results/ghidra_reports/grid_buffer_flow/gnu_verified.txt). Riproduzione: `python3 Python_Trace_Scripts/s33_trace_grid_buffer_flow.py`.

Verificati **16 SHA-256, roundtrip ELF del blocco 00, 15 finestre, 8 collegamenti diretti e 50 istruzioni chiave**. Le finestre raccordano gli argomenti del worker, le pubblicazioni del puntatore sorgente, i costruttori semplici, l'interpolatore e la copia successiva. Nessuna esecuzione hardware o verifica di persistenza JPEG.

Prossimo: risalire ai produttori dei tre puntatori nel payload e alle dimensioni assegnate, poi collegare il successivo consumatore della destinazione. Costruzione complessa della griglia, formato delle componenti, lettore dell'esito e rilascio sicuro restano aperti.


## Continuazione: produttori dei tre puntatori

Il [rapporto sull’origine dei puntatori](S33_Origine_Puntatori_Worker_e_Aree_Riservate.md) risolve le tabelle per stato/indice, il getter sorgente e i passi delle aree preparate dall’inizializzatore. Capienza della regione, limiti indice, indirizzo sorgente finale e rilascio restano aperti.
