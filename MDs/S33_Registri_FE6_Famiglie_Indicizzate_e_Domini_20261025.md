# FE6: controlli ordinari e formule con indice irrisolto

25 ottobre 2026. Atlante `Risultati/Processor_Registers/20261025T105512Z/`:
735voci,64posizioni core /197AUX /474MMIO, oltre a due famiglie parametriche
separate dai registri concreti. Mappa fisica incompleta, obiettivo attivo.
Le posizioni core includono codifiche opzionali/riservate; nessun registro
hardware verificato.

## Sei nuovi indirizzi concreti nel modello

I rami non negativi0..2 di2C6BA4/2C6BDC/2C6C38/2C6C14 producono sei indirizzi:
FE648C0/FE648C4,FE649C0/FE649C4,FE64AC0/FE64AC4.
Gli accessor modificano bit1/2 all’offset0 quando argomento==1, altrimenti
li azzerano. L’accessor bit0 invece imposta per qualsiasi argomento nonzero.
Il getter all’offset4 restituisce value&10hex, senza normalizzazione.

Questi sono accessi CPU del codice originale con chiamanti sintetici.
Non sono provati uso nei percorsi Nikon reali, nome/implementazione fisica,
reset, permessi d’accesso o effetti delle periferiche.

## Due formule, senza espansione artificiale del catalogo

Sono state aggiunte a `evidence/mmio_parametric_families.json` e al campo
`computed_mmio_families` del JSON principale. Non incrementano il numero
dei registri; il grafo le rappresenta con nodi distinti.

| Entry | Indirizzo software uint32 | Guard |
|---|---|---|
| 2C6B74 | (r0==0 ? FE64680 : FE646D0) +4*r1 | Nessuno: qualunque r0 nonzero sceglie la seconda base |
| 2C6C70 | FE648D0 +256*r0 +4*r1 | signed32(r0)<=2, senza minimo; se maggiore ritorna senza scrittura |

Tutta l’aritmetica indirizzi è modulo2^32. In entrambi i casi il valore
halfword è `((r2==1 ? 0 : 1)<<15) | (r3&FFFhex)`: bit15 invertito rispetto
al predicato r2==1, low12 da r3, bit12..14 zero.

r1 non ha un limite locale. Senza il suo dominio nei chiamanti, enumerare
molti indirizzi e chiamarli registri sarebbe ingiustificato. Le formule
possono anche spostare il target fuori dal cluster MMIO e non definiscono
una banca fisica. Le84scritture di esempio raggiungono18celle modellate,
escluse da questa ammissione concreta.

Il censimento ripetibile cerca BL a ogni halfword ed esatte parole LE/ME
verso le sei entry nei16payload verificati: zero candidati. Questo non
esclude chiamate calcolate, tail branch, altri modi di riferimento o
raggiungibilità globale. Non viene descritto come prova di codice inutilizzato.

## Prova CPU, alias e confini

Prova: `outputs/gnu_arc700/20261025T105341Z_311577c0/verified_evidence.json`.
Sei scenari ripetuti con osservatore disabilitato e abilitato:12run,
sei coppie di tracce identiche byte per byte.183invocazioni nei sei scenari,
366con replay.

- Controlli con seed0/FFFF:114eventi ordinari. Ritorni getter, SP,
  r13/r14/r15/r16, celle finali e paddingA5 verificati.
- Famiglie strutturali:84scritture con indici0/1/FFFFFFFF/40000000hex;
  selezione base zero/nonzero e guard signed provate, compreso il ramo
  positivo3 che non scrive. Le formule sono confrontate indipendentemente
  con ciascun trasferimento. Nessuna cella ammessa come registro da questi esempi.
- Controlli3/7FFFFFFF: nessun accesso MMIO nei casi provati.
- Alias da input80000000/80000001:12eventi sugli stessi indirizzi virtuali
  dei rami0/1 per overflow della moltiplicazione256. Non sono alias fisici.
- InputFFFFFFFF al primo controllo: tentativo di letturaFE647C0 senza
  risultato, stop11 atteso perché la cella non è mappata nel modello.
  Nessun nuovo registro e nessun fault hardware dedotto.

FE64680 era un tentativo non mappato nel precedente test con input negativo.
Qui compare come cella di esempio esplicitamente mappata per2C6B74. Questo
illustra il limite del modello: né il fault precedente né la nuova scrittura
provano l’implementazione fisica. L’ammissione concreta resta sospesa in attesa
di un dominio ordinario indipendente, non di una blacklist permanente.

## Audit e conservazione

`evidence/fe6_indexed_families_audit.json`:PASS. Byte ridecodificati al PC
osservato, confronto con firmware originale, pool delle basi, predicate/shift,
larghezza16 e ordine/valori delle tracce. Le formule degli84esempi vengono
ricalcolate dagli argomenti senza usare la sequenza attesa del verificatore.
Una riga risultato per accesso nei run continui; profiler non usato come
conteggio dimostrato di istruzioni ritirate.

L’osservatore esterno è riusato dal precedente output verificato, con digest
controllato. Non è ricompilato né modificato GNU. Il censimento e il suo script
sono conservati nel progetto, oltre alle copie nel nuovo atlante.

Ledger164file verificato; parent155file invariati. AUX guest invariati:
22indici,74siti run/PC. GNU installazioni/config/sorgenti/build/copielab,
firmware e originali preservati. Nessun hardware, flash, NAND/vendor,
resetUSB o scritturaSD. NON_INSTALLARE invariato.

Script in `Python_Trace_Scripts/`: `s33_census_fe6_indexed_callers.py`,
`s33_verify_fe6_indexed_families.py`, `s33_audit_fe6_indexed_families.py`,
`s33_integrate_fe6_indexed_families.py`.
Restano domini dei riferimenti indiretti/calcolati, altre famiglie FE6/FF7/FFB/
FFC, AUX parametrizzati e configurazione reale/BCR/semantiche fisiche.
