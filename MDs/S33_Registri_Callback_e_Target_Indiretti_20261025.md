# Callback e target indiretti — 25 ottobre 2026

L’atlante passa da 448 a **455 voci**: 64 posizioni core, 196 AUX e 195 MMIO.
I sette nuovi indici AUX sono supportati da codice originale e ancore indirette
verificate sulla CPU emulata. I valori dei registri custom non sono stati letti
o forniti al modello. La mappa fisica resta incompleta; il goal rimane attivo.

[Atlante](../Risultati/Processor_Registers/20261025T090846Z/REGISTER_MAP.md),
[JSON](../Risultati/Processor_Registers/20261025T090846Z/register_map.json),
[grafo](../Risultati/Processor_Registers/20261025T090846Z/graph.html),
[validazione](../Risultati/Processor_Registers/20261025T090846Z/atlas_validation.json).

## Provenienza dei puntatori

| Origine originale | Puntatore e uso | Riscontro CPU |
|---|---|---|
|339404 → 342E88; pool33975C|339CDC scritto in RAM360AD8 dal return delay slot342E8C|Registrazione completa; invocazione dal puntatore salvato raggiunge il callback e poi la guardia sul primo LR10802|
|Caller prefix33B7F6, pool33BBA0|JL_S.D a342D20 con selettore0 e argomento1=80hex|Target e primo sito LR10036 raggiunti prima dello stop del modello|
|Caller342E34, pool342E74|JL_S.D a342DE4 con selettore0|Target e primo sito LR10037 raggiunti prima dello stop del modello|

La prima invocazione usa un chiamante sintetico che rilegge il puntatore
registrato dal codice originale. Le altre due usano istruzioni originali dei
caller indicati. Nessuna prova dimostra qui avvio globale, IRQ fisico o
raggiungibilità hardware della registrazione.

I dati iniziali della RAM360AD8 provengono dai byte del payload1 V1.1, mappato
all’indirizzo di caricamento candidato. La copia RAM di laboratorio viene
controllata per intero: cambia soltanto la parola del callback prevista.
Questo fornisce provenienza ai dati del test, senza attribuire loro il ruolo
di reset o stato RAM misurato sulla Nikon. I file firmware originali e il Main
eseguito rimangono identici.

## Risultati nell’emulatore

`s33_verify_register_indirect_anchors.py` esegue **13 casi** con l’esistente GNU
ARC700 defined-memoryv2. Quattro casi completano: registrazione originale,
helper con puntatore distinto e ritorni dei due selettori per argomento4.
Gli altri nove terminano con il risultato atteso della guardia `S33_AUX_RANGE`,
prima di una lettura AUX fuori dal banco sintetico. Sono prefissi verificati,
non nove routine completate né nove letture riuscite.

I selettori0–3 raggiungono i seguenti siti originali, con calcolo del target
osservato nelle tracce CPU; il selettore4 torna senza accedere agli AUX.

| Selettore | Setter342D20: primo LR10036 | Clear342DE4: primo LR10037 |
|---:|---|---|
|0|342D36|342DFA|
|1|342D5A|342E06|
|2|342D8A|342E12|
|3|342DBA|342E1E|

Fonte: `outputs/gnu_arc700/20261025T000130Z_05792e7b/verified_evidence.json`,
con copia, script e disassemblati in `evidence/register_indirect_cpu.json` e
file associati dell’atlante. I casi di registrazione completati controllano
anche SP, sentinelle e puntatore scritto. Il banco GNU resta da2.048elementi;
nessun valore custom o periferica è inventato per superare gli stop.

## Nuove voci e campi software

Sono aggiunti `0x10036`, `0x10037`, `0x10803`, `0x10903`, `0x10A03`,
`0x10B03`, `0x10C03`. I CFG del callback339CDC e dei due selettori hanno
chiamanti/registrazioni, confini, byte e ritorni verificati. Le trasformazioni
dei valori AUX rimangono prove statiche:

- 10036: sostituisce il byte selezionato0–3 conservando gli altri byte.
- 10037: il setter imposta e il clear cancella il bit selezionato0–3.
- 10803/10903/10A03/10B03/10C03: nei rami verificati il codice conserva i30bit
 alti e sostituisce i due bassi con1. Le condizioni leggono anche il bit0.

Non si attribuiscono significati fisici a questi bit. I registri dei cinque
canali sono ciascuno giustificati da propri accessi, senza espandere un
intervallo per analogia. Altri cinque indici già presenti ricevono ulteriori
prove esplicite: il sottoinsieme CFG passa da80 a92indici qualificati, con
429siti LR/SR distinti e98entry. Le169chiamate dirette ammesse restano separate
dalle tre ancore indirette.

La copertura delle letture/scritture AUX con risultato nella CPU rimane
**21 indici / 65 siti**: i tentativi fermati dalla guardia non vi sono aggiunti.
Gli otto casi sugli epiloghi e i1.783controlli delle chiamate sono prove
precedenti riutilizzate, distinti dai13casi di questo checkpoint.

Restano dieci gruppi di costanti custom non consolidati nel censimento:
10004/10031/10033/10035/10038/10110/1028B, più
13807A80/86808020/202C50A1, tutti esadecimali. I tre valori enormi si trovano
negli overlay11/13 in contesti strutturati; non sono promossi né dichiarati
definitivamente falsi senza ricostruirne il formato/produttore. Restano aperte
anche famiglie dinamiche, BCR reali e universo MMIO completo.

Il ledger contiene107file; i104file del parent rimangono invariati. Tutte
le455voci mantengono `hardware_verified=false`. GNU, configurazioni, sorgenti,
build e copie laboratorio preesistenti sono invariati. Nessun hardware,
flash, NAND/vendor, reset USB o scrittura SD. **NON_INSTALLARE** invariato.
