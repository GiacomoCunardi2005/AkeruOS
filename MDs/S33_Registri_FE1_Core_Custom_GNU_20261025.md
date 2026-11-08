# Registri FE100xx, core opzionali e AUX0x18 — 25 ottobre 2026

L’atlante passa da 346 a 373 voci: 64 posizioni core, 114 indici AUX e 195 indirizzi
MMIO. Le 27 aggiunte comprendono 26 indirizzi FE100xx e AUX 0x18. La mappa fisica
resta incompleta e il goal rimane attivo. Gli slot core opzionali già censiti
non diventano registri Nikon verificati grazie all’emulazione.

Atlante: [REGISTER_MAP](../Risultati/Processor_Registers/20261024T233127Z/REGISTER_MAP.md),
[JSON](../Risultati/Processor_Registers/20261024T233127Z/register_map.json),
[grafo](../Risultati/Processor_Registers/20261024T233127Z/graph.html),
[audit](../Risultati/Processor_Registers/20261024T233127Z/atlas_validation.json).
Atlante precedente da 346 voci conservato integralmente; 84 file del suo ledger SHA256 verificati.

## CPU emulata e osservatore

Il verificatore `Python_Trace_Scripts/s33_verify_fe1_register_window.py` esegue
sei chiamanti sintetici con GNU ARC700 defined-memoryv2. Il codice eseguito
appartiene al Main originale V1.1, mappato senza patch: SHA256
`06754a1f451f17b3047fe03cdb83fd08af11dac725638818254ef0de26a5ed29`.
Il contenitore firmware ha SHA256
`1d34e990a8f99019ffa53ca5de785399df863e942739a667ceb314ec6ce62a39`.

| Caso | Entry originale | Istruzioni CPU | Scritture MMIO osservate |
|---|---|---:|---:|
| init |0x2931F0|27|2|
| bank80_mode4 |0x293210|49|13|
| bank80_mode8 |0x2932B0|49|13|
| bank40_mode4 |0x2933BC|49|13|
| core46_pack |0x293350|38|0|
| custom_address_pack |0x2931BC|42|0|

Tutti terminano con exit0 senza fault. Il chiamante controlla SP e sentinella
r13; per ogni caso sono controllate tutte le 26 celle e tutti i byte di padding.
Ogni cella parte con un tag distinto; i byte vicini mantengono 0xA5. La copia
Main rimane identica. Finestre disassemblate dagli entry originali e roundtrip
ELF→byte forniscono la provenienza indipendente dal solo testo della traccia.

L’osservatore è un frontend esterno che delega una volta sola gli accessor di
memoria alla libsim esistente. I sei replay conservano tracce guest identiche,
41 scritture completate e nessun tentativo senza risultato. Non è una periferica
emulata: le celle hanno soltanto semantica storage e valori iniziali espliciti.

Prove CPU:
`outputs/gnu_arc700/20261024T232600Z_2fcbbcac/verified_evidence.json`.
Replay:
`Risultati/Processor_Registers/observer_20261024T232601Z/verified_evidence.json`.
Copie dei manifest nell’atlante: `evidence/fe1_register_window.json` e
`evidence/observer_fe1.json`. Script d’integrazione e validazione conservati.

## FE100xx: significato software dei campi

Le routine scrivono halfword con `.di`. Nessun nome hardware assegnato al blocco.
Init scrive FE10000=1 e FE10004=0x1405. Le altre routine usano due banchi con
base FE10040 o FE10080; ogni banco presenta 12 indirizzi distinti.

| Offset dal banco | Provenienza del valore scritto |
|---|---|
|0x00|1, poi0|
|0x04|argomento0, bit15:0|
|0x08|argomento0, bit27:16|
|0x20|argomento1, bit15:0|
|0x28|argomento2, bit15:0|
|0x14|argomento3, bit15:0|
|0x0C|argomento4, bit15:0|
|0x10|argomento5, bit15:0|
|0x18|argomento6, bit15:0|
|0x1C|argomento7, bit15:0|
|0x24|nono argomento sullo stack, bit15:0|
|0x3C|0x14 oppure0x18 secondo la routine scelta|

Argomenti distinti:1234ABCD,1234,2345,3456,4567,5678,6789,789A,89AB
esadecimali. I due banchi, larghezze e campi sono osservazioni sul software;
non provano permission/reset, latch, trigger, DMA, tempi o IRQ fisici.

## Core46/51/55/59 e AUX0x18

La routine293350 impacchetta i primi tre argomenti in r46. Nel caso provato
produce 0x851A82F3. La formula è conservata nella voce core46. Il test verifica soltanto l’impacchettamento, senza dedurre
alcun completamento asincrono dell’estensione.

La routine2931BC legge AUX0x18, sottrae il risultato a due argomenti, scrive
0xEB8BD in r59, forma r51 e restituisce r55. Il chiamante del test fornisce
AUX0x18=0x01000000 e r55=0x55667788; con argomenti 0x01000240/0x01000100
il codice originale produce r51=0xE0400240 e restituisce 0x55667788.
La scrittura SR che prepara AUX0x18 appartiene al chiamante sintetico ed è
esclusa dai record firmware. Nessuna operazione hardware dell’estensione provata.

Le tracce originali consolidate coprono 21 AUX: 20 nei prefissi boot precedenti,
uno nel chiamante isolato. Il verificatore indipendente rilegge 65 siti AUX da
ELF/firmware con byte identici. Per il nuovo caso l’ELF con la sezione Main serve
alla verifica statica; l’ELF del chiamante runtime è registrato separatamente.

## Famiglia AUX10010: provenienza e limite

Il chiamante33C976–33C99C e la leaf342C08–342C2C producono:

`AUX = 0x10010 + u8(memory[0x42CFD2 + 9*u8(memory[r14+156])])`.

Il pool a33CBA0 contiene42A69A; l’istruzione LDB aggiunge2938. ADD3_S con
operandi uguali calcola nove volte il selettore: manuale ARCompact5115-029,
riga 7833. Il delay slot della chiamata modifica r2 e conserva r0.
Le letture della tabella stanno nell’intervallo42CFD2–42D8C9; nessuno dei
16 payload file-backed del manifest copre questi indirizzi candidati. Il record
finale fuori file del manifest è escluso da questo confronto e conservato
come limite della struttura. L’assenza di copertura non prova BSS, zero o RAM libera.

Il dominio software massimo è10010–1010F; non sono derivati nuovi indici
concreti. Occorre ricostruire il produttore della tabella o acquisire stato
runtime con provenienza. Le altre famiglie custom e i 19 indici risolti
staticamente oltre2047 conservano i limiti precedenti; il banco GNU non è ampliato.
Prova riproducibile: `evidence/aux10010_argument_proof.json` con byte, pool,
finestre, semantica primaria e hash degli input.

## Stato e limiti

Gli iniziali 115 candidati MMIO hanno già prove di accesso; l’universo fisico
dei registri non è ancora delimitato. I 717 accessi sensore precedenti restano
separati dalle41 scritture FE1. BCR/configurazione Nikon, implementazioni core
opzionali, famiglie AUX dinamiche e semantica periferiche restano aperti.
Prossimo lavoro: produttori della tabella AUX e altri accessi firmware oltre
il censimento iniziale, mantenendo distinta la raggiungibilità globale.

GNU, configurazioni, sorgenti, build, copie laboratorio e firmware originali
rimangono invariati. Nessun accesso hardware, flash, comando NAND/vendor,
reset USB o scrittura SD. **NON_INSTALLARE** invariato.
