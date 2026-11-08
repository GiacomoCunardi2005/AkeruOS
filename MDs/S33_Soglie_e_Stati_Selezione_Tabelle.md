# S33 — soglie e stati della selezione delle tabelle

Analisi statica V1.1, 19 ottobre 2026. Continuazione delle [sorgenti numeriche statiche](S33_Sorgenti_Numeriche_Statiche_Interpolatore.md). Nessuna esecuzione hardware.

## Risultato

Ricostruita la logica del ramo `0x252B34` che sceglie le tabelle sorgente: confronta un **indice di stato letto come byte**, un **valore hardware halfword**, e tre soglie ottenute da una curva di sette elementi. Due regimi usano pesi **8/10,8/10,8/10** oppure **5/10,4/10,3/10**.

Il modello delle condizioni coincide con un interprete limitato ai rami decodificati in **4.336 casi**, compresi **2.270 ritorni del puntatore precedente**. Questo chiarisce il comportamento locale senza attribuire ancora significati come zoom, focale o modalità di ripresa ai valori letti. Circa 10% funzionale invariato.

## 1. Origine dei valori di confronto

| Funzione usata | Catena verificata | Dato osservato |
|---|---|---|
| `0x14941C` | salto a `0x148288` | byte a **`0x366F12`**, conservato nel selettore in r13 |
| `0x149EAC` | salto a `0x148278`, chiamata `0x23300C` | halfword MMIO a **`0x0FF20018`**, estesa con segno; sottrazione di 750 e nuovo troncamento signed16 |
| `0x149424` | chiamata `0x148250` | elemento signed16 della curva **`0x3908EC`**, poi sottrazione di 750 e troncamento signed16 |
| `0x233798` | lettura diretta | byte a **`0x36A3C0`**, che sceglie il regime delle soglie |

Il getter della curva limita gli indici superiori a 6. Non presenta un limite inferiore locale; l'uso sicuro dipende dai chiamanti. Il selettore prepara anche indici precedenti con sottrazione e troncamento a byte: non viene trattato come un contratto universale per indici arbitrari.

La curva nel payload iniziale è:

```text
403, 750, 874, 947, 1033, 1138, 1317
```

Dopo la sottrazione di 750:

```text
-347, 0, 124, 197, 283, 388, 567
```

Questi sono valori dell'immagine verificata, non una lettura runtime della RAM. Le unità fisiche e gli scrittori dei campi restano da attribuire.

## 2. Costruzione delle tre soglie

Il record `0x8996E0` fornisce tre indici ai byte +1/+2/+3; nel payload iniziale valgono **2,3,4**. Per ciascun indice m, il codice legge il valore della curva al punto m e al predecessore, costruisce la differenza signed16, la pesa, poi aggiunge il valore precedente.

Per il dominio positivo senza overflow delle differenze iniziali:

```text
T = curva[m-1] + trunc(peso * (curva[m]-curva[m-1]) / 10)
```

| Regime | Numeratori dei pesi | Soglie con curva e indici iniziali |
|---|---|---|
| byte `0x36A3C0` uguale a 1 | 8, 8, 8 | **99, 182, 265** |
| altro valore | 5, 4, 3 | **62, 153, 222** |

Il primo peso del secondo regime è **5/10**: l'istruzione `add2 r0,r18,r18` calcola r18+4*r18. Analogamente `add1 r0,r18,r18` dà 3*r18. Leggere queste istruzioni come somme non scalate cambierebbe le soglie.

I passaggi includono troncamenti signed16 e helper di divisione. La formula leggibile e i numeri sopra non estendono la verifica a overflow o a tutti i possibili record modificati a runtime.

## 3. Scelta della famiglia e condizioni della tabella

Dopo le soglie, il codice decide fra le due famiglie di indirizzi già estratte:

- nel regime uguale a 1, legge il byte **`0x3657C8`** attraverso `0xD0528`;
- nell'altro regime chiama `0xDE254`, che ottiene un oggetto da `0xF6F04` e legge il suo byte +8.

Il confronto con **`0x6A`** seleziona la famiglia A; l'altro ramo usa B. L'oggetto del secondo lettore e il significato del valore `0x6A` restano aperti.

Posti `v` il valore hardware trasformato, `c` l'indice di stato, `b` il valore iniziale della curva, `T1/T2/T3` le soglie e `k1/k2/k3` gli indici del record:

| Ordine di verifica | Condizione | Indice della tabella nella famiglia |
|---|---|---|
| 1 | `(b ≤ v < T1 e c ≤ k1)` oppure `c=0` | 0 |
| 2 | `T1 ≤ v < T2` e `record[0] ≤ c ≤ k2` | 1 |
| 3 | `T2 ≤ v < T3` e `k1 ≤ c ≤ k3` | 2 |
| 4 | `v ≥ T3` e `c ≥ k2` | 3 |
| nessuna precedente | mantieni il puntatore della famiglia | scelta precedente |

`record[0]` vale 1 nei dati iniziali. Gli intervalli sono quelli dei confronti signed osservati. In particolare `c=0` fa scegliere la prima tabella indipendentemente dall'intervallo di v, dopo aver raggiunto questo tratto della funzione.

Famiglia A: `0x8C8210/0x8D1040/0x8D9E70/0x8E2CA0`, cella precedente `0x899704`. Famiglia B: `0x89BB20/0x8A4950/0x8AD780/0x8B65B0`, cella precedente `0x899708`.

Il ramo iniziale record+0x0E=1 che restituisce direttamente `0x89BB20` precede questa selezione e rimane distinto. Nessuna di queste condizioni è presentata come osservazione di quale tabella usi la fotocamera in un dato momento.

## 4. Verifica dei rami e limiti

[Script e modello delle condizioni](../Python_Trace_Scripts/s33_trace_source_table_selection.py), [JSON](../Ghidra_Results/ghidra_reports/source_table_selection/verified_evidence.json), [GNU](../Ghidra_Results/ghidra_reports/source_table_selection/gnu_verified.txt). Riproduzione: `python3 Python_Trace_Scripts/s33_trace_source_table_selection.py`.

Verificati **16 SHA-256, roundtrip ELF del blocco 00, 9 finestre, 9 collegamenti diretti, 22 istruzioni chiave e 15 valori di pool**. La curva e gli indici iniziali sono letti dai payload con hash verificati.

Il confronto del modello comprende valori attorno a ciascuna soglia, categorie 0..7, entrambe le famiglie, i due insiemi di soglie iniziali e 2.000 casi aggiuntivi con soglie ordinate variabili. L'interprete esegue solo il tratto di selezione `0x252C9E..0x252D54`, con letture di record e pool modellate; fallisce se incontra operazioni non previste.

Il modello non esegue la costruzione delle soglie né i lettori hardware, non prova la semantica del silicio e non sostituisce una verifica delle modalità runtime. I 4.336 confronti dimostrano l'accordo locale fra predicati e rami decodificati sotto le ipotesi dichiarate; non provano la correttezza fotografica o il ciclo dei buffer.

Prossimo: attribuire gli scrittori e il significato dei due stati, verificare come la geometria dei chiamanti usa il layout 130×70, e seguire il consumo della destinazione dopo il worker. Capienza, indice dei buffer e lettore finale dell'esito restano aperti.
