# FE9: chiamanti indicizzati e tabelle originali del payload 1

25 ottobre 2026. Atlante ammesso:
`Risultati/Processor_Registers/20261025T193115Z/REGISTER_MAP.md`.
**1118 voci: 64 posizioni core, 197 AUX, 857 indirizzi MMIO singoli.**
Rispetto alla tappa precedente: 66 nuovi indirizzi, quattro schede arricchite.
Mappa fisica incompleta, nessun accesso hardware, **NON_INSTALLARE**.

## Che cosa prova questa tappa

Nove wrapper originali in `2EE760..2EE9C4` vengono eseguiti con i loro helper
originali e con i dati originali del secondo payload. L'ammissione riguarda
soltanto le selezioni il cui indice è una costante in una sequenza locale di
un chiamante originale. Non dimostra il dominio completo degli indici, la
raggiungibilità globale dei chiamanti o i valori fisici della fotocamera.

- CPU: `outputs/gnu_arc700/20261025T192726Z_57e5a91c/verified_evidence.json`.
- Audit: `outputs/gnu_arc700/20261025T192726Z_57e5a91c_audit.json`.
- Riscontri statici: `caller_index_witnesses.json` nella stessa directory.
- Script riproducibili: `s33_verify_fe9_indexed_callers.py`,
  `s33_audit_fe9_indexed_callers.py`, `s33_integrate_fe9_indexed_callers.py`
  in `Python_Trace_Scripts/`; copie conservate nell'atlante.

12 scenari, 24 esecuzioni, 50 chiamate complete per esecuzione: tre coppie
seed/valore e quattro argomenti canale (`0`, `1`, `2`, `0xFFFFFFFF`). Ogni
scenario ha una prova osservata e una di riferimento con tracce identiche.
Nessun fault; ritorni previsti, stack e registri preservati verificati.

I conteggi seguenti considerano una sola volta gli eventi osservati di ogni
coppia, senza sommare nuovamente l'esecuzione di riferimento:

| Ambito | Eventi | Letture | Scritture | Indirizzi distinti |
|---|---:|---:|---:|---:|
| Selezioni con riscontro locale dell'indice | 1032 | 456 | 576 | 70 |
| Solo indice scelto nel test, escluso dalle ammissioni | 48 | 24 | 24 | 4 |
| Totale | 1080 | 480 | 600 | 74 |

Dei 70 indirizzi qualificati, 66 sono nuovi; i quattro esistenti sono
`FE9013C`, `FE90140`, `FE9813C`, `FE98140`. Il catalogo aggiunge le nuove
prove senza sostituire i loro eventi e campi precedenti. Le altre 787 schede
MMIO precedenti restano identiche.

## Dati originali, senza tabelle inventate

I 32 pool a `2EEA08..2EEA84` puntano a parole nell'intervallo che comincia
a `40CA24` e arriva alla tabella a `40D01C`. Questi dati appartengono al
payload 1, con base candidata `360800` e fine `428600`, distinto dal Main0
(`AD800..35BC00`). Entrambi sono mappati integralmente e confrontati prima e
dopo la CPU con i byte verificati del firmware originale.

L'audit ricostruisce **1008 carichi di parole originali** confrontando ordine,
PC della load e valore restituito nella traccia CPU. Le destinazioni e le
maschere vengono lette dai dati originali, non passate direttamente agli
helper dal test. Ricontrollate anche 398 istruzioni ai PC esatti, il codice
del selettore, i pool, i rami e tutte le operazioni MMIO completate.

I limiti delle tabelle non vengono dedotti dalle distanze fra puntatori
adiacenti. Una parola vicina che sembra un indirizzo non basta ad ammettere
un registro. L'associazione software di base dei due payload non prova una
mappa RAM fisica o la loro residenza simultanea sulla fotocamera.

## Indici qualificati e campioni esclusi

Il censimento dei 16 payload trova 75 candidati BL verso i nove wrapper,
ricontrollati con decoder indipendente e GNU al PC esatto. Di questi, 68
hanno una sequenza locale riconosciuta che imposta direttamente l'indice
costante in `r0`, prima della chiamata o nel suo delay slot.

| Wrapper | Operazione | Indici con riscontro locale provati su entrambi i rami |
|---|---|---|
| `2EE760` | Campo mascherato | 2,4,5,6,7,8,9,10,11,12,13 |
| `2EE7B0` | Set/clear di un bit | 0,1,7,8,15,16 |
| `2EE800` | Campo mascherato | 4,5,6,7 |
| `2EE850` | Campo mascherato | 0,1,2,7,8 |
| `2EE8A0` | Campo mascherato | 0,1,2,4 |
| `2EE8F0` | Split low16/high16 | 0,2,3,5,7,8 |
| `2EE924` | Campo mascherato | Nessuno; indice0 solo campione escluso |
| `2EE974` | Campo mascherato | Nessuno; indice0 solo campione escluso |
| `2EE9C4` | Dispatcher con post-elaborazione | 1,11 |

Gli indirizzi **FE90200, FE90400, FE98200, FE98400** compaiono soltanto nei
due campioni senza riscontro originale dell'indice: esclusi da ammissioni e
arricchimenti, pur avendo eventi CPU corretti. La riuscita dell'esecuzione
non sostituisce il riscontro del chiamante.

La ricerca locale è conservativa: riconosce una costante diretta nel delay
slot o negli otto byte precedenti, senza trasferimenti di controllo e senza
scritture successive a `r0` nei passaggi ammessi. Non è un'analisi completa
del flusso dei valori. Restano da seguire i sette candidati:
`295408`, `295F92`, `2ED642`, `2ED650`, `2ED67E`, `2ED774`, `2EDF9E`.
Alcuni richiedono seguire altre istruzioni aritmetiche o un registro che
contiene già la costante. Gli eventuali ingressi indiretti restano aperti.

## Differenze tra i rami e lettura del wrapper

`2ED448` normalizza zero a zero e qualsiasi nonzero a uno; il codice dei
wrapper usa quel risultato per scegliere il ramo. Non è ancora un nome
fisico per due canali del processore.

Le tabelle non vanno traslate meccanicamente fra i rami. Per esempio, nello
split store all'indice5 la tabella A contiene `FE90178`, mentre B contiene
`FE98188`. La CPU scrive rispettivamente:

- A: low16 a `FE90178`, high16 a `FE9017C`;
- B: low16 a `FE98188`, high16 a `FE9818C`.

Sono due store halfword separati a distanza quattro, non uno store word né
una prova di atomicità hardware. Le schede delle metà indicano esplicitamente
la destinazione principale e la lane low16/high16.

Per `2EE9C4`, l'indice seleziona un valore da tabella, poi il dispatcher usa
il secondo argomento come modo. Nel modo1 legge il primo indirizzo full16,
ma il wrapper applica una AND con una parola della **tabella B anche nel
ramo A**. All'indice11 la maschera finale è `0x7FF`: nei due casi provati con
bit10 presente, il risultato lo conserva. Non si può attribuire al wrapper
un getter limitato ai soli dieci bit bassi sulla base del writer low10.

Sei confronti aggiuntivi verificano l'identità delle **sequenze MMIO**
variando soltanto l'argomento canale da 1 a 2 oppure a `0xFFFFFFFF`, con
seed, valore, indici e modi invariati. Questa equivalenza non riguarda le
tracce complete fra canali diversi e non perturba gli argomenti valore.

## Conservazione e lavoro aperto

Ledger nuovo: 293 file. Parent `20261025T192207Z`: 286 file immutati.
Ricontrollati ledger, chiavi e geometrie di tutti i 38 atlanti precedenti
validati. Restano 50 finestre, 3408 appartenenze, 3376 indirizzi di cella
distinti e 32 ripetizioni; overlap invariati, nessun alias fisico inferito.
AUX invariati: 22 indici con prove guest, 172 siti run-PC. Nessun LR/SR
nuovo in questa tappa.

Prossimo: risolvere i sette chiamanti rimasti e le referenze indirette/tail
ai wrapper `2EE924/974`, continuare i gruppi successivi a `309CD0`, quindi
i domini indicizzati ancora aperti, AUX codice/dati, BCR e matematica DSP.
I valori MMIO iniziali, gli argomenti e lo stack sono fixture: reset,
permessi, W1C/FIFO, IRQ, timing e semantica del silicio restano ignoti.
GNU, sorgenti/build/installazioni e firmware originali sono preservati.
