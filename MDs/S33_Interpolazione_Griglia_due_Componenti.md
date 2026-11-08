# S33 — interpolazione su griglia a due componenti

Analisi statica V1.1, 19 ottobre 2026. Continuazione dei [cicli sui campioni](S33_Cicli_Campioni_Configurazione_e_Reset_Esito.md). Nessuna esecuzione sulla fotocamera.

## Risultato

La routine comune **`0x1FD4E4`** ricostruisce **due componenti a 16 bit per punto**, leggendo quattro posizioni vicine nella sorgente e applicando due interpolazioni orizzontali e una verticale. Le frazioni hanno 8 bit; gli arrotondamenti sono separati e le differenze vengono troncate a signed16.

La tabella passata in r3 è **modificata sul posto**: ogni coppia iniziale di coordinate viene sostituita dalla coppia di campioni risultante, poi il puntatore avanza di quattro byte. Non si tratta quindi di una tabella di coordinate preservata dalla routine.

Un modello aritmetico ricostruito coincide con un interprete limitato al corpo delle istruzioni decodificate in **5.000 confronti**, più verifiche su campi costanti, punti interi e un caso limite signed16. È una verifica locale fra due rappresentazioni del calcolo, non una misura sul processore ARC. Stima funzionale invariata: circa 10%.

## 1. Argomenti e numero di punti

| Argomento | Uso osservato |
|---|---|
| r0, r1 | ciascuno: shift aritmetico di 4, +1 e troncamento a unsigned16; il prodotto imposta il conteggio del ciclo |
| r2 | passo fra righe della sorgente, in coppie di componenti |
| r3 | tabella di coppie halfword, usata sia in lettura sia in scrittura |
| r4 | base della sorgente con due halfword interleaved per posizione |
| r5 | scala della coordinata X |
| r6 | scala della coordinata Y |
| r7 | offset X in unità Q8 |
| prima parola sullo stack | offset Y in unità Q8 |

Il prologo salva tre registri: l'offset Y viene pertanto letto a stack+12. Il conteggio prodotto è assegnato a `lp_count`; un prodotto zero salta il corpo. Per argomenti di estensione nonnegativi, il numero di punti è:

```text
N = u16((r0 >> 4) + 1) * u16((r1 >> 4) + 1)
```

Il calcolo usa il risultato basso del prodotto. Overflow, argomenti negativi, ampiezza effettiva delle allocazioni e ammissione da parte dei chiamanti restano da verificare. La routine non controlla la capienza della tabella.

## 2. Coordinate e quattro letture per componente

Per ciascuna coppia, la prima halfword alimenta Y e la seconda X. Il codice azzera `aux_macmode` prima del ciclo. Nel modello del prodotto basso a 32 bit, costruisce:

```text
X = ((coordX * scalaX + 0x800) >> 12) + offsetX
Y = ((coordY * scalaY + 0x800) >> 12) + offsetY
fx = X & 255
fy = Y & 255
ix = u32(X) >> 8
iy = (u32(Y) >> 8) & 65535
```

I prodotti e le somme seguono gli avvolgimenti a 32 bit e gli shift signed/unsigned delle istruzioni, preservati nel modello. Le formule sopra sono una forma leggibile per il dominio ordinario senza overflow; lo script esplicita i passaggi a 32 bit.

Gli indirizzi base dei due vicini sulla prima e sulla seconda riga sono costruiti con stride r2. Ogni posizione occupa quattro byte. Il corpo legge:

- componente 0: offset 0 e +4 su ciascuna riga;
- componente 1: offset +2 e +6 su ciascuna riga.

Non ci sono controlli locali che garantiscano la presenza di entrambe le colonne e righe sorgente. Il modello host rifiuta le impronte fuori dall'array per poter verificare il calcolo; questo controllo appartiene al modello e non viene attribuito al firmware.

## 3. Interpolazione con arrotondamento e differenze signed16

Nel dominio senza overflow, per una componente con campioni `a,b` sulla riga superiore e `c,d` su quella inferiore:

```text
h0 = (256*a + s16(b-a)*fx + 128) >> 8
h1 = (256*c + s16(d-c)*fx + 128) >> 8
out = u16((256*h0 + s16(h1-h0)*fy + 128) >> 8)
```

`s16` significa troncamento e interpretazione con segno a 16 bit. La componente 1 usa la stessa struttura: l'istruzione `add3 ... ,0x10` a `0x1FD5CC` aggiunge 128, perché il terzo operando è scalato per 8.

Per campioni compresi fra 0 e 32767, le differenze fra i campioni sono rappresentabili in signed16. Per valori su tutto l'intervallo unsigned16, il risultato può differire molto dalla bilineare ordinaria senza troncamento.

**Caso verificato:** con Y su una riga intera, X a metà fra campioni 0 e 65535, la differenza diventa `s16(65535) = -1`; l'uscita del codice ricostruito è **0**, mentre un'interpolazione ordinaria con arrotondamento darebbe **32768**. Non è una prova di difetto nelle immagini: il dominio reale delle componenti deve ancora essere stabilito dai produttori.

## 4. Modifica della tabella e chiamanti

Le scritture sono a `0x1FD5B6` e `0x1FD604`, sugli stessi quattro byte dai quali erano state lette le coordinate. A `0x1FD608`, r3 viene aggiornato a puntatore precedente+4. Il ciclo ripete l'operazione per il numero di punti preparato.

Collegamenti diretti verificati nelle routine inferiori già note:

| Sito | Destinazione |
|---|---|
| `0x1FE100` | `0x1FD4E4` |
| `0x200478` | `0x1FD4E4`; r7 viene assegnato nel delay slot |

Questa osservazione aggiunge un vincolo al ciclo dei buffer: **prima della chiamata il contenuto può essere una griglia di coordinate; dopo la chiamata gli stessi byte contengono campioni**. Non si presume che tutti i rami dei backend usino la stessa rappresentazione, né che r0/r1 abbiano un ruolo universale in ogni funzione.

Non si attribuiscono alle due componenti nomi RGB, YUV o Bayer, e non si identifica la routine come codificatore JPEG. L'operazione locale è un ricampionamento bilineare con aritmetica e troncamenti specifici.

## Evidenze e verifica del modello

[Script e modello importabile](../Python_Trace_Scripts/s33_trace_grid_interpolation.py), [JSON](../Ghidra_Results/ghidra_reports/grid_interpolation/verified_evidence.json), [GNU](../Ghidra_Results/ghidra_reports/grid_interpolation/gnu_verified.txt). Riproduzione: `python3 Python_Trace_Scripts/s33_trace_grid_interpolation.py`.

Verifica del campione: **16 SHA-256, roundtrip ELF del blocco 00, 3 finestre, 3 collegamenti e 24 istruzioni chiave**. È incluso l'intero helper fino al ritorno.

Verifica del calcolo: l'interprete usa le istruzioni decodificate di una singola iterazione `0x1FD514..608`; ammette solo le operazioni necessarie, fallisce sulle altre e verifica le due sole scritture e l'avanzamento del puntatore. Il confronto con la funzione aritmetica comprende **2.500 casi con campioni fino a 32767 e 2.500 fino a 65535**, cinque campi costanti, 36 punti interi e il caso limite signed16.

Il modello non esegue firmware, loop hardware, interrupt o chiamanti completi e non valida la semantica del silicio. Non prova sicurezza in caso di sovrapposizione, accessi validi per ogni modalità, durata dei buffer o persistenza del JPEG.

Prossimo: ricostruire la generazione della tabella prima della chiamata, il dominio effettivo delle due componenti e la gestione del buffer dopo la sovrascrittura. Restano aperti il lettore del risultato worker e i callback del primo descrittore.


## Continuazione: origine e destinazione dei buffer

Il [rapporto sulla griglia e i tre buffer](S33_Griglia_Tre_Buffer_e_Copia_Finale.md) collega un costruttore precedente all’interpolazione e la successiva copia. Il puntatore alla sorgente dell’interpolatore proviene da payload+0x10 tramite `0x369604`; payload+0 è il buffer di lavoro nei rami selezionati. Dimensioni e durata restano aperte.
