# S33 V1.1 — inizializzazione candidata della tabella grafica e forme CaptureMenu

Analisi offline del 27 ottobre 2026. Gli indirizzi sono nella mappa candidata
dei payload V1.1; le finestre del codice e i dati esaminati sono identici ai
byte corrispondenti di `DUMPS/MainCode.dmp`. Il dump non è una fotografia
dello stato RAM durante l'uso della GUI.

## Inizializzazione

La routine a `0x23E704` carica dal letterale a `0x23E730` il valore
`0xEA0660` e passa questo valore e `887` alla funzione `0x2D4F9C` e poi
al setter grafico `0x23B19C`. Il primo setter scrive puntatore e halfword
limite nel proprio contesto `0x36CAC4`; il secondo li scrive nel contesto
grafico `0x36A5E0`. Il lookup `0x23B20C` accede quindi alla voce indicizzata
di tale tabella se quel percorso di inizializzazione ha effettivamente
impostato il contesto e nessun'altra operazione l'ha modificato.

Le chiamate dirette a `0x23E704` a `0x15911A` e `0x15913E` sono presenti
nelle rispettive finestre disassemblate; la seconda è soggetta al controllo
del byte `+1` del contesto a `0x367268`. Questo corregge il limite della
ricerca esplorativa nel precedente [rapporto sui descrittori](S33_GUI_Descrittore_Grafico_20261027.md):
non aveva rilevato questi chiamanti diretti. Non è qui dimostrato quando i
due percorsi siano raggiunti, quale inizializzazione avvenga sulla fotocamera,
o che il contesto rimanga invariato fino al disegno.

## Descrittori delle due liste

La tabella candidata occupa 887 word, da `0xEA0660` a `0xEA143B` inclusi.
Per i record delle liste `0x9801C0` e `0x980268`, i campi grafici hanno
questi ID, nello stesso ordine del record:

| Lista | Triplette dei record |
| --- | --- |
| `0x9801C0` | `606,606,606`; `284,285,284`; `806,807,806` |
| `0x980268` | `606,606,606`; `633,634,633`; `413,414,413`; `222,223,222` |

Tutti gli 11 ID distinti sono minori di 887 e puntano a descrittori non nulli
di 20 byte. I due halfword iniziali valgono 72 e 72, il byte a `+8` vale 1,
il puntatore a `+12` vale `0x3F6740` e quello a `+16` identifica i dati
compressi. Per esempio, ID 222 → descrittore `0xE9D26C` → sorgente
`0xEBE8BD`; ID 223 → `0xE9D280` → `0xEBE9F0`.

Seguendo in Python l'interpretazione statica del ciclo RLE originale, ogni
sorgente ha prodotto 5.184 byte di indici. In cinque coppie, `(222,223)`,
`(284,285)`, `(413,414)`, `(633,634)` e `(806,807)`, la posizione degli
indici non zero è identica: la prima usa solo 0 e 1, la seconda solo 0 e 3.
Anche 606 usa 0 e 1. Questa è una proprietà dei dati decodificati, non una
prova dei colori o del significato degli stati nella GUI.

## Riproducibilità e limiti

Il [verificatore](../Python_Trace_Scripts/s33_verify_gui_graphic_table_init.py)
è passato; il [risultato](../Risultati/GUI_S33/graphic_table_init_20261027T180014Z/evidence.json)
riporta puntatori, dimensioni, hash e indici usati, assieme alle finestre
disassemblate e ai file `.indices`. I PNG nella stessa cartella rappresentano
solo maschere: zero nero, qualsiasi indice non zero bianco. Non sono immagini
renderizzate dalla fotocamera. Il confronto con il dump copre tabella intera,
record, descrittori, byte compressi consumati e finestre di codice; non
certifica stato RAM, palette, trasparenza, clipping o invocazione grafica.

La decodifica iniziale è una reimplementazione host. Successivamente il
[verificatore CPU](../Python_Trace_Scripts/s33_verify_gui_rle_cpu.py) ha
eseguito l'originale `0x23B234` sulle 11 sorgenti originali confrontando gli
indici con la decodifica host: [PASS](../Risultati/GUI_S33/rle_original_cpu_20261027T183202Z/verified_evidence.json),
96.600 istruzioni, stack e guardie dopo i buffer conservati. Usa descrittori,
puntatori e RAM di laboratorio e il simulatore DSP v7 sperimentale per
`MULDW` 72×72; non dimostra il comportamento DSP fisico. REA ha letto e
confrontato sei finestre di codice e letterali dell'inizializzazione e del
decoder ([evidenza](../Risultati/GUI_S33/rea_graphic_init_20261027T182942Z/evidence.json)).
Restano da verificare inizializzazione runtime,
palette, rendering, hardware e associazione osservata tra tasti e schermate.
I candidati restano **NON_INSTALLARE**.
