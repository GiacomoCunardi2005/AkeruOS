# Nikon S33: campi software nel gruppo FFC7000

25 ottobre 2026. Mappa fisica incompleta; obiettivo attivo. GNU, firmware
originali e copie laboratorio invariati; nessun accesso hardware. NON_INSTALLARE.

L’atlante contiene **1.011 voci: 64 posizioni core, 197 indici AUX e 750
indirizzi MMIO singoli**. Questo passo aggiunge 24 indirizzi, senza duplicati.
Le posizioni core comprendono encoding opzionali/riservati/speciali e non
provano altrettanti registri fisici. Le 22 finestre di trasferimento restano
separate: 3.118 appartenenze di cella, 3.086 indirizzi distinti, 32 ripetizioni
tra finestre e il parametro FF74088 condiviso con una finestra. Le due
famiglie MMIO indicizzate conservano domini dei chiamanti irrisolti.

## Selezione delle routine e nuove prove

La navigazione dopo le routine FFC3000 porta a codice di elaborazione RAM,
non automaticamente a un ulteriore blocco MMIO. Una ricerca di costanti nel
Main originale ha invece individuato il gruppo FFC7000 vicino a308438.
Le sole costanti sono indizi di ricerca, non prove di registri. Sono promossi
soltanto i 24 indirizzi successivamente legati a pool, istruzioni e accessi
completati nelle undici routine originali selezionate.

Prova CPU:
`outputs/gnu_arc700/20261025T155216Z_8784a4b0/verified_evidence.json`,
stato PASS_FFC7000_MASKED_FIELDS. Otto scenari,16run,88chiamate osservate,
176incluse le ripetizioni con osservatore spento/acceso. Tutte le otto coppie
di tracce sono identiche byte per byte. Completati **376 accessi halfword:
184 letture e192 scritture**. SP e sentinelle r13..r16 restano conservati.

Argomenti principali:0,1,FFF,1000,1FFF,2000,80018000,FFFFFFFF.
Il secondo argomento usa la stessa sequenza ruotata di tre posizioni.
Seed MMIO:0000,FFFF,A55A,5AA5,F000,E000,8001,7FFE.
Il Main è mappato invariato e il frontend osservatore è esterno a GNU.

## Contratti software dei 24 indirizzi

In questa tabella low12/13 significa argomento&FFF/1FFF; high12/13 significa
(argomento>>16)&FFF/1FFF. I bit esterni al campo da12/13bit sono conservati
dalla halfword letta. Low16 sostituisce tutta la halfword. Sono descrizioni
delle operazioni software, senza nome o funzione periferica assegnati.

| Entry originale | Destinazioni | Valori inseriti, nell’ordine |
|---|---|---|
| `308438` | `FFC7000/04` | (r0-1)&1FFF, poi (r1-1)&1FFF; conserva high3 |
| `308490` | `FFC7008/0C` | low16 e high12 di r0 |
| `3084DC` | `FFC7010` | low12 di r0 |
| `308508` | `FFC7014/18/1C/20` | low16/high12 di r0, poi low16/high13 di r1 |
| `308598` | `FFC7024/28` | low16 e high12 di r0 |
| `3085E4` | `FFC702C` | low12 di r0 |
| `308610` | `FFC7030/34/38/3C` | low16/high12 di r0, poi low16/high13 di r1 |
| `3086A0` | `FFC7050` | store diretto low16 di r0, senza lettura preliminare |
| `3086B4` | `FFC7100/04` | low16 e high12 di r0 |
| `308700` | `FFC7118` | low13 di r0 |
| `30872C` | `FFC7108/0C/10/14` | low16/high12 di r0, poi low16/high13 di r1 |

La sottrazione prima della maschera è significativa: per r0=0 il campo di
FFC7000 diventa1FFF; per r0=1 diventa0. I tre bit superiori del valore letto
restano conservati. Non sono valori di reset o prove che zero sia un parametro
hardware valido. Non si deducono dimensioni geometriche dai nomi dei campi.

Le routine con campi low16, tranne lo store diretto, leggono comunque la
halfword prima di scriverla; il loro AND con FFFF0000 non conserva alcun bit
di quella lettura a16bit. L’osservatore conserva tali letture nel conteggio.
I campi high12 conservano i quattro bit alti della destinazione; high13 ne
conserva tre. Le scritture low16/high12 o low16/high13 restano accessi separati
a16bit, senza prova di atomicità o registro fisico a32bit.

## Audit indipendente

`s33_audit_ffc7000_fields.py` ricava le maschere dalle istruzioni AND e dai
literal pool, le larghezze dai BMSK/EXTW, gli shift e la sottrazione dai byte
originali. Verifica i trasferimenti degli argomenti nei registri temporanei,
indirizzi di destinazione e opcode LDH/STH effettivi. Ricostruisce gli output
dagli argomenti e backing iniziali senza importare i campi del verificatore
come proprio oracolo. Sono riallineate e confrontate **110 istruzioni**.

Controllati anche ordine degli accessi, tuple della traccia CPU, coppie
begin/result dell’osservatore, larghezza2byte, backing finale e gap A5.
Esito PASS_FFC7000_FIELDS_INDEPENDENT_AUDIT. Non sono presenti nuovi SR nei run
selezionati: restano22AUX con risultato guest e146siti run/PC.

## Atlante e conservazione

Risultato: `Risultati/Processor_Registers/20261025T155444Z/REGISTER_MAP.md`,
con JSON,CSV,grafo e `atlas_validation.json`. Ledger SHA-256 di **244file**;
parent `20261025T154626Z`,238file, verificato e immutato.
`coverage_lineage_audit.json` conserva tutte le chiavi dei **29atlanti
precedenti validati**. Nessun nuovo indirizzo coincide con una cella delle
finestre. Manifest finestre,sovrapposizioni e tracce AUX sono byte-identici
al parent.

Prove copiate nell’atlante: `evidence/ffc7000_fields.json`,
`evidence/ffc7000_fields_audit.json` e
`evidence/ffc7000_fields_linear_navigation.txt`. Il listing lineare serve
alla navigazione; gli audit usano i PC effettivi e byte originali.
Script: `Python_Trace_Scripts/s33_verify_ffc7000_fields.py`,
`s33_audit_ffc7000_fields.py`, `s33_integrate_ffc7000_fields.py`.

Firmware SHA-256:
`1d34e990a8f99019ffa53ca5de785399df863e942739a667ceb314ec6ce62a39`;
Main SHA-256:
`06754a1f451f17b3047fe03cdb83fd08af11dac725638818254ef0de26a5ed29`.

Stack, backing e seed sono fixture, non stato di reset o RAM fisica libera.
Le larghezze12/13 dei campi non sono larghezze delle transazioni: ogni accesso
osservato è a16bit. Funzione periferica, permessi, side effect, IRQ, tempi e
vincoli dei chiamanti Nikon restano sconosciuti. Nessun flash,dumper,NAND/vendor,
resetUSB o scritturaSD. Resta aperta anche la matematica dell’helper303A40
nel modello DSP provvisorio.

Prossimo punto concreto: accessor successivi a3087BC e altri gruppi MMIO
individuati nel Main, con confronto al catalogo prima delle ammissioni.
L’intero firmware e l’universo dei registri fisici non sono ancora coperti;
AUX parametrizzati, candidati codice/dati,BCR e implementazione reale del SoC
richiedono ulteriori prove. Nessuna percentuale globale viene dedotta.
