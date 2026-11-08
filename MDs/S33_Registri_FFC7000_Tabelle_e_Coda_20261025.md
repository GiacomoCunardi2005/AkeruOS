# FFC7000: parametri originali, finestre sparse e coda scalare

25 ottobre 2026. Tappa già validata a disco, ricontrollata alla ripresa dello
studio. Atlante della tappa: [20261025T165109Z](../Risultati/Processor_Registers/20261025T165109Z/REGISTER_MAP.md),
1.031 voci: 64 posizioni core, 197 indici AUX, 770 indirizzi MMIO singoli.
Il seguito è documentato nella [coda scalare](S33_Registri_FFC7000_Coda_Scalare_20261025.md).
Non sono quantità di registri fisici dimostrati.

## Prove e conservazione

[CPU](../outputs/gnu_arc700/20261025T164451Z_dce581eb/verified_evidence.json):
24 scenari/48 run, 1.684 transazioni halfword, 772 letture e 912 scritture.
Le 24 coppie con osservatore spento/acceso hanno tracce identiche.
L'[audit conservato](../Risultati/Processor_Registers/20261025T165109Z/evidence/ffc7000_table_tail_audit.json)
ricostruisce maschere, pool, chiamate e carichi input; comprende 118 istruzioni
ridecodificate, 104 record SR su 12 PC e due equivalenze metamorfiche.
Tutti i 73 input della validazione e il ledger di 273 file sono stati ricontrollati
alla ripresa. Le esecuzioni CPU non sono state ripetute.

Sono aggiunti cinque indirizzi singoli e 13 finestre, con 127 celle complessive.
Totale della tappa: 50 finestre, 3.408 appartenenze di cella, 3.376 indirizzi
distinti. Le 32 ripetizioni e FF74088 anche scalare restano relazioni tra indirizzi
software, senza alias fisici dedotti. I domini generali degli helper restano aperti.

## Basi fissate dai wrapper originali

La tabella originale a 354E50 fornisce quattro tuple di shift e maschere.
Ogni tupla contiene shift 0/8 e maschere per la rispettiva corsia byte; l'audit
verifica la tabella e i successivi carichi dalla copia sullo stack.

| Wrapper | Helper | Basi software | Input per chiamata | Operazione |
|---|---|---|---:|---|
| 309188 | 3090FC | FFC74FC,7504,750C,7514 | 4 byte | Due celle per base; maschere 001F/1F00 |
| 309430 | 3093B4 | FFC75E0,7624,7668,76AC | 33 byte | 17 celle per base; maschere 007F/7F00 |
| 3094E8 | 30945C | FFC76F0,7704 | 9 byte | Cinque celle per base; maschere 00FF/FF00 |

I bit fuori maschera restano quelli del backing. Nei gruppi con numero dispari
di byte, l'ultima cella riceve solo la corsia bassa e conserva la corsia alta.
Invertire i bit ignorati degli input lascia identiche le scritture dei gruppi
pack5 e pack7, a seed invariato. Non sono provati altri chiamanti o basi arbitrarie.

3092A0 copia 33 halfword in FFC7530..75B0, con stride di quattro byte e senza
letture MMIO. Questa è una finestra di trasferimento, non 33 controlli indipendenti.

## Due loop, tutti gli input consumati e una cella saltata

Il wrapper 3093AC porta a 3092DC con base FFC75B8. Il primo loop usa indici
0..9 e consuma i primi dieci byte, riempiendo cinque celle FFC75B8..75C8.
Il secondo usa indici 12..17 ma carica input agli indici j-2: consuma quindi
anche i sei byte rimanenti, nelle tre celle FFC75D0..75D8.

FFC75CC non viene acceduto da questo percorso e non è ammesso dall'esperimento.
Il salto non prova una cella fisica inesistente, un registro mancante o RAM libera.
Le due regioni sono rappresentate come finestre separate.

## Cinque indirizzi singoli

| Entry | Indirizzo | Operazione software |
|---|---|---|
| 3091B4 | FFC751C | Byte 0 in low8, poi byte 1 in high8, con due RMW |
| 3091B4 | FFC7520 | Byte 2 in low8; high8 conservato |
| 309228 | FFC7524 | Store dell'argomento troncato a 16 bit |
| 30923C | FFC7528 | Store dell'argomento troncato a 16 bit |
| 309250 | FFC752C | Low8 dall'argomento 0; poi bit15 impostato se argomento 1 è nonzero, altrimenti cancellato |

Per FFC7524/7528 questa tappa aveva l'etichetta generica `read_write_halfword_di`,
non sostenuta dalle sole scritture osservate. La successiva integrazione della
coda scalare conserva la correzione a `write_halfword_di` e la vecchia etichetta
con la sua motivazione; non viene dedotto un permesso hardware write-only.

Gli eventi dei cinque scalari sono 96; quelli delle finestre sono 1.588.
Nell'atlante sono conservati 26 record SR rappresentativi in cinque run:
12 nuovi siti run/PC, 172 totali e sempre 22 indici AUX distinti.
Gli operandi SR non misurano lo stato fisico dopo il setter.

[Validazione della tappa](../Risultati/Processor_Registers/20261025T165109Z/atlas_validation.json).
Script: [verifica CPU](../Python_Trace_Scripts/s33_verify_ffc7000_table_tail.py),
[audit](../Python_Trace_Scripts/s33_audit_ffc7000_table_tail.py),
[integrazione](../Python_Trace_Scripts/s33_integrate_ffc7000_table_tail.py).

Input, stack, seed e backing MMIO sono fixture. Reset, permessi, effetti
collaterali, IRQ, tempi, atomicità e funzione periferica restano sconosciuti.
Nessuna modifica a GNU o firmware e nessuna operazione hardware. NON_INSTALLARE.
