# Dispatch e callback a due flag — 25 ottobre 2026

È ricostruito il contratto software tra AUX10001, AUX10111, AUX10110 e i
relativi slot RAM. L’atlante aggiunge **0x10110** e arriva a **456 voci**:
64 posizioni core, 197 AUX, 195 MMIO. I campi descrivono il software originale;
la mappa fisica rimane incompleta e il goal resta attivo.

[Mappa](../Risultati/Processor_Registers/20261025T092514Z/REGISTER_MAP.md),
[JSON](../Risultati/Processor_Registers/20261025T092514Z/register_map.json),
[grafo](../Risultati/Processor_Registers/20261025T092514Z/graph.html),
[validazione](../Risultati/Processor_Registers/20261025T092514Z/atlas_validation.json).

## Registrazioni verificate con GNU ARC700

La routine originale342868 carica3428B8 dal pool342980 e chiama342E80.
Quest’ultima salva il puntatore nello slot360AE0 nel delay slot del ritorno.
La API3428B0 salva invece il callback utente nel contesto RAM360AD0.

Tre nuovi casi del verificatore `s33_verify_register_dual_callback.py`:

| Caso | Esito | Istruzioni nel profilo |
|---|---|---:|
|Registrazione originale342868|Ritorno completo, slot360AE0=3428B8|28|
|API utente3428B0 con tag11223344|Ritorno completo, contesto360AD0=11223344|22|
|Registrazione e invocazione dal puntatore salvato|Target3428B8 osservato; stop atteso prima del LR10111 a3428BA|19|

I due casi completati controllano SP e sentinelle. Tutti i casi controllano
per intero la copia RAM del payload1: cambia soltanto la parola prevista.
I byte iniziali provengono dal file originale mappato al suo load address
candidato, senza attribuirli a RAM/reset fisico Nikon. Main e input GNU sono
invariati. Fonte CPU:
`outputs/gnu_arc700/20261025T091719Z_2d222191/verified_evidence.json`;
copia in `evidence/register_dual_callback_cpu.json` dell’atlante.

Il terzo caso si arresta con la guardia sul banco AUX da2.048elementi. Non è
una lettura riuscita di10111 e non esegue le operazioni10110 successive.
La copertura guest con risultato resta **21 AUX / 65 siti**. Gli otto casi
sugli epiloghi, i13precedenti casi indiretti e i1.783controlli delle chiamate
sono conservati come prove precedenti, distinti dai tre nuovi casi.

## Dipendenze statiche dei registri

Il verificatore `s33_verify_custom_dispatch_contract.py` controlla byte, opcode,
estrazione dei bit, rami, pool e chiamate nel Main originale V1.1. Il dispatcher
342EB0 usa sette getter che ritornano `(AUX10001 >> bit) & 1`:

| Bit10001 | Slot RAM letto e invocato se il bit è nonzero |
|---:|---|
|0|360AE0: callback3428B8 verificato dalla nuova registrazione|
|1|360ADC: valore runtime non stabilito da questo lavoro|
|2–6|360AD8: callback339CDC verificato nel checkpoint precedente|

Queste sono dipendenze software: nessun numero di IRQ o significato fisico
è attribuito ai bit. Il dispatcher invoca direttamente il puntatore dello
slot; il callback interno3428B8 verifica invece che il callback utente sia
nonzero. Esiste anche un getter adiacente del bit7, conservato come leaf
strutturale senza attribuirgli un ramo del dispatcher analizzato o un ruolo
di bit riservato.

Il callback3428B8 contiene due percorsi:

| Condizione software | Trasformazione e chiamata, statiche |
|---|---|
|10111.bit15 e10110.bit1 nonzero|Rilegge10110, imposta bit1 e riscrive; RAM360AD5=1; callback utente con r0=1 se nonzero|
|10111.bit14 e10110.bit0 nonzero|Rilegge10110, imposta bit0 e riscrive; RAM360AD4=1; callback utente con r0=0 nel delay slot se nonzero|

Il verificatore controlla anche i salti che escludono ciascun percorso, i
controlli NULL e il valore nel delay slot. La fattibilità globale, i valori
hardware e gli effetti dei read/modify/write rimangono ignoti: **non è una
prova W1C, acknowledge, reset o consegna IRQ**. Le scritture dei flag del gestore
sono deduzioni statiche, non operazioni osservate nei tre test CPU.

Prova riproducibile: `evidence/dispatch_contract.json`, disassemblato e script
nell’atlante. Le dipendenze sono riportate nelle tre voci AUX e controllate
anche dopo l’integrazione. Il sottoinsieme CFG ora comprende93indici custom,
437siti LR/SR,99entry,169chiamate dirette e quattro ancore indirette. Non è
una copertura esaustiva del firmware o dei registri fisici.

## Questioni aperte e integrità

Restano nove gruppi di costanti custom non consolidati nel censimento:
10004/10031/10033/10035/10038/1028B e
13807A80/86808020/202C50A1, tutti esadecimali. Rimangono aperte le famiglie
parametriche, la tabella runtime10010, i BCR reali e l’universo MMIO completo.

Nel firmware sono presenti le stringhe `ASIC ID : SD10P200` e
`ASIC ID : SD10P220`, nel payload5 agli indirizzi candidati982FB5/982FC8
(offset contenitore72F06D/72F080). Non bastano a scegliere la variante montata
né a trasferire una mappa di registri da un altro SoC. La raccolta pubblica
precedente è documentata in `S33_Datasheet_Componenti_Raccolta_Pubblica.md`;
non sostituisce una lettura dei BCR o una documentazione del silicio esatto.

Ledger113file, parent107file invariato. Tutte le456voci conservano
`hardware_verified=false`. GNU, configurazioni, sorgenti, build, copie
laboratorio preesistenti e firmware originali invariati. Nessun hardware,
flash, NAND/vendor, reset USB o scrittura SD. **NON_INSTALLARE** invariato.
