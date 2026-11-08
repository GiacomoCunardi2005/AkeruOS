# FFB — riferimento numerico indipendente e flusso dei valori DSP

25 ottobre 2026. PASS su campioni offline; NON_INSTALLARE.

La finestra `FFB9F2C..FFB9FC0` riceve 38 halfword dal chiamante originale
`2E29B4`, dopo il calcolo di `303A40`. Prima era verificata la provenienza
dei valori; questa tappa aggiunge un riferimento numerico indipendente
dalle tracce. Non aggiunge registri: atlante invariato a 1176 voci,
`Risultati/Processor_Registers/20261025T201031Z`, ledger 306 invariato.

## Riferimento

L'ingresso del chiamante comprende sei halfword H0..H5 e nove byte B0..B8.
Il modello riceve soltanto questi quindici campi, senza consultare le uscite
osservate. Usa divisione intera esatta:

- X = ceil(H2/H0), Y = ceil(H3/H1).
- Divisori positivi; quoziente troncato verso zero e resto n−q·d, anche
  per numeratori negativi. Non usare il floor di Python per la divisione
  con segno quando il numeratore è negativo.
- Ogni risultato viene ridotto ai 16 bit copiati dal chiamante.

Il dominio accettato dal verificatore è H0/H1 in 1..32767, H2/H3 positivi,
X/Y in 1..32767, H4/H5 unsigned16 e B0..B8 unsigned8. È un dominio di
modellazione; le prove coprono dodici ingressi selezionati, non tutti i
suoi elementi né tutti i parametri leciti Nikon.

| Offset nella struttura locale | Valore previsto |
|---|---|
| 38, 40 | X, Y |
| 50..64, passo 2 | Quozienti di (Bi+1), i=0..7; divisore X per i<4, Y per gli altri |
| 66..80, passo 2 | Resti delle stesse divisioni |
| 82..96, passo 2 | Quozienti: primi quattro numeratori Bi+1; poi B4+1−B8 e B5/B6/B7+1+B8 |
| 98..112, passo 2 | Resti delle stesse divisioni |
| 118, 120 | Quozienti H4/X, H5/Y |
| 122, 124 | Resti H4/X, H5/Y |

Le formule sono state ricostruite dal software e confrontate con le sue
esecuzioni originali. Non attribuiscono significati fisici alle coordinate
o ai coefficienti, né dimostrano in generale la semantica delle librerie
floating o DSP.

## Distinzione DSP

Il chiamante originale scrive byte 1 all'offset 36 prima della chiamata.
Il ramo verificato di `303A40` legge quel flag, esegue il confronto con 1,
azzera r0/r2 a `303B08/303B0A` e salta direttamente a `303B26`, evitando
le letture dei prodotti salvati nello stack a `303B0E/303B10`.

Le due istruzioni originali `muldw` a `303AE8/303AF8` restano eseguite.
Nel modello GNU provvisorio producono X·H0 e Y·H1, scritti come halfword
locali agli offset 42/44. Questi offset sono esclusi da tutte le 38 copie
MMIO originali, verificate una per una.

Quindi i **valori** di quei due prodotti non alimentano le 38 uscite nel
percorso flag=1 verificato. Questo non dimostra che le istruzioni siano
assenti, che non possano avere altri effetti fisici, né che il percorso
flag diverso da 1 sia equivalente. `aux_macmode` viene scritto a zero
all'indice 65; ciò resta un'operazione software osservata in emulazione.

## Prove

- Quattro ingressi storici: 152 confronti delle 38 uscite.
- Otto nuovi ingressi: sedici esecuzioni riferimento/osservatore, 304
  scritture MMIO verificate, otto coppie di tracce identiche, exit 0 e
  nessun fault. Stack e r13..r19 conservati nei fixture.
- Totale 456 confronti sulle uscite. I nuovi casi verificano anche tutti
  i 44 halfword locali scritti dal helper: 352 confronti, inclusi prodotti,
  centri, dimensioni meno uno e uscite copiate.
- Sedici prodotti DSP esplicitamente marcati `provisional=1`, confrontati
  con X·H0/Y·H1. Nessuna promozione a semantica DSP hardware verificata.
- Nuovi casi con rapporti non interi, X/Y=32767, dimensioni 65535,
  byte 0/255 e numeratori negativi con resto negativo.

Riproduzione:

1. `python3 Python_Trace_Scripts/s33_verify_ffb_numeric_reference.py`
2. `python3 Python_Trace_Scripts/s33_audit_ffb_numeric_reference.py outputs/gnu_arc700/20261025T201510Z_5b6c70a4`

Esecuzioni CPU: `outputs/gnu_arc700/20261025T201510Z_5b6c70a4/`.
Audit con ledger: `Risultati/Processor_Register_FFB_Numeric/20261025T201654Z/`.
Il riferimento usa esclusivamente gli ingressi per prevedere gli output;
l'audit ridecodifica i byte originali, controlla offset delle copie e degli
store, eventi MMIO, ramo flag=1, buffer e hash delle fonti.

## Limiti e seguito

La matematica generale rimane non provata: zero, negativi, non finiti,
rapporti fuori dominio e altri chiamanti richiedono evidenze ulteriori.
Nessuna nuova cella della finestra viene ammessa come registro scalare.
Il confronto dei valori non certifica periferiche, reset, permessi, IRQ,
timing, atomicità o comportamento dell'hardware DSP. Originali e GNU
invariati, nessun accesso a hardware, USB, NAND o SD.

La ricerca resta attiva su AUX codice/dati, BCR/SoC, altri gruppi MMIO e
domini dei chiamanti. Per `303A40` distinguere ora la matematica campionata
delle 38 uscite, la dipendenza dei valori dal flag e la semantica fisica DSP.
