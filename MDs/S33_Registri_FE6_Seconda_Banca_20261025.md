# Seconda famiglia FE6: dominio calcolato e chiamante originale

25 ottobre 2026. Atlante `Risultati/Processor_Registers/20261025T103558Z/`:
687 voci, 64 posizioni core / 197 AUX / 426 MMIO. Mappa fisica incompleta,
obiettivo attivo. Le posizioni core includono codifiche opzionali/riservate,
non64 registri fisici verificati. Nessun registro hardware verificato.

## Risultato e confini

76 nuovi indirizzi halfword sono osservati da sei accessor originali Main:
2C6738,2C679C,2C6834,2C6894,2C68D4,2C6928. I primi cinque accettano i19selettori
34..3Dhex e44..4Chex. Indirizzo: FE64000+16*selettore, offset0,4,8,C.
Gli indirizzi appartengono alle finestre FE64340..FE643DC eFE64440..FE644CC,
solo ai quattro offset citati; non ogni byte o posizione delle finestre.

È coperto il dominio software di questi accessor. Non è un censimento fisico
né una prova che tutti i selettori siano usati dalla fotocamera. BCR,
implementazione del SoC e semantiche hardware rimangono sconosciuti.

| Offset | Comportamento software originale |
|---|---|
| 0 | Scrittore completo: bit0..1 e10..15 composti dagli argomenti, altri bit zero. RMW separato: sostituisce10..15 e conserva0..9 |
| 4 | Setter modifica solo bit8; argomento1 imposta, gli altri valori azzerano. Getter distinto restituisce il mask bit9, value&200hex |
| 8 | Scrive r2 basso16. Routine speciale2C6928 scrive r1 basso16 solo per4A/4Chex |
| C | Bit15 da r1 bit0, bit0..13 da r3, bit14 zero |

La famiglia precedente FE602xx/604xx ha campi bassi differenti: non vengono
trasferite automaticamente le sue definizioni. Setterbit8 e getterbit9
rimangono distinti anche qui. Nessuna deduzione di W1C, IRQ, reset, frequenza,
stato cache, nome fisico o permessi d’accesso.

## Esecuzione CPU

Prova: `outputs/gnu_arc700/20261025T103401Z_a14d3be4/verified_evidence.json`.
Quattro scenari, ciascuno con osservatore esterno disabilitato e abilitato:
otto run, quattro coppie di tracce identiche byte per byte.

- Seed di tutte le celle0 eFFFF:152 chiamate originali e211 accessi per scenario.
  Verificati tutti19selettori e tutti76indirizzi, comprese set/clear, lettura
  mask bit9, RMW dei campi, scritture doppie e le due scritture speciali.
- Negativo seedA55A:64 chiamate, nessun accesso MMIO per gli otto valori
  0,33,3E,43,4D,7FFFFFFF,80000000,FFFFFFFFhex.
- Chiamante originale239F2C:19 invocazioni complete con gli stessi19selettori.
  Quattro letture iniziali fanno calcolare20002hex al produttore modalità
  originale1F0980; dopo il primo giro il getter usa la cache prodotta dal guest.
  114 accessi al secondo banco e4letture a monte:118 eventi.

Totale540 accessi osservati su80indirizzi, di cui76nuovi e4già noti
(FEF0020,FE800BC,FED3000,FED3800). 387 chiamate per i quattro scenari distinti,
774 includendo i replay. I contatori non vengono confusi con registri fisici
o istruzioni ritirate.

Per il wrapper originale, ogni cella offset4 parte da200hex: setterbit8
produce300, getter restituisce200, scrittore compone1803hex all’offset0,
clearbit8 ripristina200. Lo stato iniziale del bit9 è fixture esplicita:
non viene attribuito a un effetto periferico del bit8 o a una temporizzazione.
Le parole grezze A4/8, i gate0, flagRAM e cache iniziale sono anch’essi fixture.
Il wrapper dimostra uso degli offset0/4; gli offset8/C hanno prove dei loro
accessor isolati, non di quel wrapper.

Il chiamante sintetico verifica dopo ogni ritorno SP e r13/r14/r15/r16.
Vengono verificati ordine PC/op/indirizzo/valore, larghezza16, celle finali,
padding A5, cache e flag. Main resta identico al firmware originale.

## Audit e riproduzione

`evidence/fe6_second_bank_audit.json`: PASS. L’audit ridecodifica dal PC
osservato, confronta i byte con il contenitore originale, verifica bounds,
shift4, le due basi, bit8/bit9 e i pool delle scritture speciali. Eventi
confrontati in ordine con la traccia, una riga risultato per accesso.
L’osservatore delega agli accessori GNU esistenti e non modifica il motore.

Ledger149file verificato; parent143file invariati. AUX guest invariati:
22indici,74siti run/PC verificati. GNU configurazioni/installazioni/sorgenti/
build/copie laboratorio e firmware originali preservati. Nessun accesso
hardware, flash, NAND/vendor, reset USB o scrittura SD. NON_INSTALLARE.

Script in `Python_Trace_Scripts/`: `s33_verify_fe6_second_bank.py`,
`s33_audit_fe6_second_bank.py`, `s33_integrate_fe6_second_bank.py`.
Restano gli altri controlli FE6 e le famiglie calcolate FF7/FFB/FFC,
AUX parametrizzati/candidati codice-dati e la configurazione reale/BCR.
