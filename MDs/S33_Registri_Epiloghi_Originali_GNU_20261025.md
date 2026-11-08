# Epiloghi originali e qualificazione AUX — 25 ottobre 2026

L’atlante passa da 432 a **448 voci**: 64 posizioni core, 189 indici AUX e
195 indirizzi MMIO. Sono qualificati staticamente i 16 AUX precedentemente
sospesi nelle tre finestre Main. I loro accessi custom non sono stati eseguiti;
le nuove esecuzioni GNU verificano le routine originali di ripristino e ritorno.
La mappa fisica rimane incompleta e il goal resta attivo.

Atlante: [mappa](../Risultati/Processor_Registers/20261024T235314Z/REGISTER_MAP.md),
[JSON](../Risultati/Processor_Registers/20261024T235314Z/register_map.json),
[grafo](../Risultati/Processor_Registers/20261024T235314Z/graph.html),
[audit](../Risultati/Processor_Registers/20261024T235314Z/atlas_validation.json).

## Verifica sulla CPU emulata

Le routine dei moduli custom terminano spesso con un salto agli epiloghi
condivisi a 0x33413C–0x3341E4. Il precedente verificatore li fermava al confine
dei tre moduli; questo impediva di riconoscere il ritorno di alcune funzioni.
Il nuovo verificatore segue soltanto questa regione aggiuntiva, dopo averne
controllato i byte originali e verificato otto entry con GNU ARC700
defined-memoryv2, senza modificare GNU o il firmware.

`s33_verify_register_millicode.py` prepara frame di stack sintetici: una parola
distinta per ogni registro salvato, un indirizzo di ritorno controllato e
valori distinti per i registri da lasciare invariati. Dopo il ritorno verifica
SP, r0/r7/r10 e tutti i registri r13–r26. Nel caso con incremento blink di otto
byte verifica anche la parola di padding non consumata come registro.

| Entry | Registri ripristinati | Byte stack consumati | Istruzioni CPU |
|---|---|---:|---:|
|0x33415C|r13–r22|44|99|
|0x33416C|r13–r20|36|93|
|0x334174|r13–r19|32|90|
|0x334184|r13–r17|24|84|
|0x33418C|r13–r16|20|81|
|0x334194|r13–r15|16|78|
|0x3341A4|r13|8|72|
|0x3341A6|r13, con r12 iniziale8|12|76|

Tutti gli otto casi terminano con exit0 e senza fault: **673 istruzioni**.
La copia Main resta byte-identica. Per esempio, la funzione originale33A778
riserva quattro byte, salva blink e r13 e termina via3341A6 con r12=8: il
consumo di12byte corrisponde alla struttura osservata. Si verifica il codice
di ritorno con frame espliciti, senza dedurre lo stack reale di un task Nikon.

Prove CPU:
`outputs/gnu_arc700/20261024T235009Z_ee8d9dc5/verified_evidence.json`;
copie nell’atlante: `evidence/millicode_return_cpu.json`, disassemblato e script.
Main originale V1.1, SHA256
`06754a1f451f17b3047fe03cdb83fd08af11dac725638818254ef0de26a5ed29`.

## Correzione del CFG

Il precedente riconoscitore classificava come rami gli opcode che iniziavano
con `b`, salvo una lista di operazioni sui bit. Mancava `BXOR`: a33A9B8 il CFG
si fermava con `branch_target_unresolved`. BXOR è classificato LOGICAL nella
fonte GNU `work/binutils-2.45/opcodes/arc-tbl.h`, riga2264. La lista è corretta;
il percorso ora prosegue dopo quell’istruzione. Non è stata modificata alcuna
istruzione firmware per superare il limite del ricostruttore.

Le chiamate ammesse restano169 e le entry95. Il verificatore visita3.080PC e
qualifica **80 indici custom con341 siti LR/SR distinti**, rispetto a64 e231.
I16indici aggiunti sono:

`0x10105`, `0x10106`, `0x10107`, `0x10108`, `0x1010A`, `0x10113`,
`0x10114`, `0x10118`, `0x1027A`, `0x1027B`, `0x1027D`, `0x10283`,
`0x10284`, `0x10285`, `0x10288`, `0x1028C`.

La qualificazione continua a richiedere chiamanti e confini verificati,
un ritorno nel CFG e nessun decode invalido nel CFG qualificante. Restano
esplicite le assunzioni sul ritorno dei callee e sulla fattibilità dei rami.
Il supporto CPU al ritorno è collegato a25voci AUX, comprese voci già presenti.

Il risultato statico è
`Risultati/Processor_Registers/custom_cfg_20261024T235040Z/verified_evidence.json`,
con copia in `evidence/custom_aux_cfg.json`. Le prove precedenti restano
conservate come checkpoint datati. Il decoder delle chiamate è nuovamente
confrontato con1.783risultati di salto nelle tracce GNU già esistenti: PASS.
Questa parte riusa esecuzioni conservate; i nuovi otto casi riguardano gli epiloghi.

## Copertura e limiti

Zero indici non qualificati riguarda soltanto il sottoinsieme prima attraversato
nelle tre finestre: non prova di aver trovato ogni registro. Nel censimento
lineare restano17gruppi di costanti AUX custom non ancora consolidati, compresi
0x1028B,0x10803–0x10C03 nei cinque canali,0x10110,0x10004 e alcuni indici
0x10031–0x10038, oltre a valori ancora da distinguere da dati. Non si espandono
intervalli o domini parametrici per analogia.

Rimangono inoltre cinque stop fuori regione, quattro salti indiretti e due
chiamate indirette nei CFG complessivi; i90CFG con ritorno non equivalgono a
95funzioni dimostrate interamente eseguibili. La tabella runtime della famiglia
10010, le altre famiglie dinamiche, la configurazione/BCR Nikon e l’universo
completo MMIO restano aperti.

Le tracce LR/SR eseguite restano21AUX/65siti. Il banco sintetico GNU resta2048;
nessuna lettura o scrittura custom oltre il banco viene fabbricata. Il test
degli epiloghi non attribuisce valori di reset né significati fisici alle
estensioni. Tutte le448voci mantengono `hardware_verified=false`.

Il ledger finale comprende104file; i101file del parent432voci sono invariati.
GNU, configurazioni, sorgenti, build e copie laboratorio rimangono in sola
lettura. Nessun hardware, flash, comando NAND/vendor, reset USB o scrittura SD.
**NON_INSTALLARE** invariato.
