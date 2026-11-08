# FE9 — inizializzatore originale e ingressi indiretti

25 ottobre 2026. PASS offline; mappa fisica incompleta; NON_INSTALLARE.

## Risultato

Atlante: `Risultati/Processor_Registers/20261025T201031Z/REGISTER_MAP.md`.
1176 voci: 64 posizioni core, 197 AUX, 915 MMIO singoli.
52 indirizzi aggiunti e tre schede arricchite; nessuna nuova finestra.
Ledger di 305 file prima dell'aggiunta della precisazione di copertura.
Parent `20261025T200238Z` immutato; 40 atlanti PASS precedenti verificati,
senza perdita di chiavi o geometrie. Tutte le schede precedenti conservate,
salvo arricchimenti append-only delle tre celle indicate sotto. AUX e relative
172 ancore di traccia invariati; restano 50 finestre e due famiglie calcolate.

## Collegamento originale ricostruito

Le parole LE a `303F0C/303F10` valgono `2EE924/2EE974`. Non sono semplici
coincidenze: `303D62` carica il primo puntatore in r14, `303E32` carica il
secondo in r13; `303D4C` esegue rispettivamente 15 e 11 chiamate `jl_s.d`,
preparando r0 con indici costanti e r2 dal canale conservato in r16.

`303EC4` chiama due volte `303D4C`, con r3=0 e r3=1 e questi puntatori
alle strutture originali nel payload 1:

| Canale | Struttura per `2EE924` | Struttura per `2EE974` |
|---|---|---|
| 0 | `41CD1C` | `41CD74` |
| 1 | `41CD48` | `41CD94` |

L'esecuzione parte dall'inizializzatore originale `303EC4`, senza fixture per
queste strutture e senza sostituire routine o tabelle. Sono state verificate
le letture effettive dei byte/halfword di ingresso e le destinazioni dei salti
indiretti nelle tracce CPU. I campi byte usati come flag vengono normalizzati
tramite confronto con 1; i campi halfword sono caricati senza questa conversione.

| Wrapper | Indici originali eseguiti | Nuove celle, passo 4 byte |
|---|---|---|
| `2EE924`, canale 0 | 0..14 | `FE90200..FE90238` |
| `2EE924`, canale 1 | 0..14 | `FE98200..FE98238` |
| `2EE974`, canale 0 | 0..10 | `FE90400..FE90428` |
| `2EE974`, canale 1 | 0..10 | `FE98400..FE98428` |

Il contratto software è RMW halfword con maschera e destinazione dalle tabelle
originali. Questi domini sono quelli dell'inizializzatore verificato, non un
limite provato per ogni chiamante o per l'hardware. Le quattro celle indice 0
prima escluse (`FE90200/FE90400/FE98200/FE98400`) ora hanno evidenza dal
chiamante originale: non vengono ammesse sulla base delle vecchie prove sintetiche.

## Due salti di coda

Sono stati eseguiti integralmente anche:

- `29599C`: copia l'argomento r0 in r2, seleziona indice 6 di `2EE850`,
  imposta r1=0 nel delay slot del salto di coda. Cancella low2 a `FE90144`
  per argomento zero, a `FE98144` per argomento nonzero.
- `295EB4`: seleziona indice 11 di `2EE7B0`; argomento esattamente 1 produce
  flag 0, gli altri valori provati producono flag 1. Il delay slot forza
  r2=1, quindi accede soltanto a `FE98138`, bit 11, maschera `0800`.
  Questo chiamante non prova l'uso dell'indice 11 nel canale A.

Le tre celle erano già presenti e sono state arricchite. Il canale A non
viene aggiunto per simmetria.

## Prove e riproduzione

1. `python3 Python_Trace_Scripts/s33_verify_fe9_tail_callers.py`
   Evidenze CPU: `outputs/gnu_arc700/20261025T200821Z_064bd124/`.
2. `python3 Python_Trace_Scripts/s33_integrate_fe9_indirect_init.py outputs/gnu_arc700/20261025T200821Z_064bd124`
   Audit indipendente e integrazione con controllo della copertura precedente.

Otto scenari combinati, sedici esecuzioni riferimento/osservatore, 864 eventi
MMIO (432 letture/432 scritture), 864 carichi dalle tabelle originali,
416 letture di campi di ingresso e 416 destinazioni di salto indiretto
verificate. Otto coppie di tracce identiche; exit 0, nessun fault; stack e
r13..r19 conservati nei fixture. Audit: 154 istruzioni ridecodificate.

Gli scenari incrociano due seed MMIO e quattro argomenti dei due tail caller:
0, 1, 2, FFFFFFFF. L'inizializzatore usa sempre le stesse strutture originali,
senza perturbarne i valori. Non viene dichiarata un'equivalenza metamorfica.

## Ricerca statica e limiti

La scansione candidata dei 16 payload verifica B/Bcc compatti e B simm21/25
a ogni halfword completo, oltre ai BL riconosciuti da `call_at` quando esiste
una finestra di almeno quattro byte. Il BL compatto nell'ultimo halfword di
ogni payload non è incluso: non dichiarare una ricerca completa di tutti i
trasferimenti di controllo. Esclusi BRcc, BBIT, loop, salti via registri,
puntatori calcolati o codificati e ingressi in mezzo alle routine.

Trovati cinque pattern B verso i nove wrapper: due qualificati nel payload 0
sono i tail caller eseguiti; tre nel payload 1 non hanno qualificazione come
codice e non producono ammissioni. Trovati 75 candidati BL, nessuno ai due
wrapper `2EE924/974` nelle finestre scandite. Quattro pattern di puntatore:
le due parole LE originali qualificate sopra, un pattern LIMM a `303F0E`
sovrapposto alle stesse parole (non prova di un immediato eseguibile), e
un pattern LE a `106CF12` nel payload 11, ancora non qualificato.

Il primo tentativo `200647Z_94b543b4` si è fermato prima delle prove CPU:
il controllo assumeva erroneamente zero pattern di puntatore. L'evidenza
positiva ha guidato l'analisi dell'inizializzatore. Nell'audit sono stati
corretti il routing delle finestre del payload 1 e il caricamento del primo
byte tramite `[r0,0]` prima della riutilizzazione di r13. I risultati CPU
PASS sono stati riusati, senza nuove esecuzioni per correggere l'audit.

Restano sconosciuti raggiungibilità globale, tutti gli indici leciti, nomi e
semantica fisica, reset, permessi, W1C, IRQ, timing e atomicità. Stack,
backing MMIO e seed sono sintetici. Nessun hardware toccato; originali e
GNU invariati. Proseguire su AUX codice/dati, BCR/SoC, DSP e `303A40`,
oltre agli altri gruppi MMIO e vincoli dei chiamanti. Il goal resta attivo.
