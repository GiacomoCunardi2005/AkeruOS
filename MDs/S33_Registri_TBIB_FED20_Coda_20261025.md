# TBIB — coda FED20, indice di bit e getter a bitmap

25 ottobre 2026. PASS offline; mappa fisica incompleta; NON_INSTALLARE.

Atlante: `Risultati/Processor_Registers/20261025T204714Z/REGISTER_MAP.md`.
1203 voci: 64 posizioni core, 200 AUX, 939 MMIO singoli. Tre nuove celle
`FED2054/2058/205C`; `FED2038` arricchita. Nessuna nuova finestra.

## Contratti verificati

| Cella | Routine | Contratto software |
|---|---|---|
| `FED2038` | `10036A4/36D8/370C` | Getter booleani dei bit 2/4/6 |
| `FED2038` | `10036BC/36F0` | Imposta bit 3/5, argomento ignorato |
| `FED2038` | `1003724` | Bit 7: zero cancella, nonzero imposta |
| `FED2054` | `1003758` | Store low16 completo |
| `FED2054` | `100376C/3788` | RMW set/clear del bit selezionato da arg0 |
| `FED2054` | `10037A4` | Getter low8 |
| `FED2054` | `10037BC` | Bitmap del bit selezionato nel byte alto, non booleano |
| `FED2054` | `10037E4` | Getter del byte alto traslato in low8 |
| `FED2058` | `1003804` | Due store halfword completi, prima 0 poi 1 |
| `FED205C` | `1003824` | Preserva bits2..15, sostituisce low2 da arg0 |
| `FED205C` | `100384C` | Getter low2 |
| `FED205C` | `1003864` | Getter bits2..3 traslati in low2 |

Sono contratti del software originale in emulazione, non permessi fisici.
Per esempio il getter bits2..3 di 205C non viene dedotto dalla larghezza del
writer low2: il suo AND con `C` e lo shift di 2 sono verificati separatamente.

## Indice variabile e bitmap

I BSET/BCLR originali in `100377C/3798` ricevono l'indice tramite registro.
Il manuale ARCompact locale, `outputs/gnu_arc700_aux/sources/ARCompact_5115-029.txt`,
pagine stampate 225 e 213, specifica l'uso dei cinque bit bassi dell'indice.
Il modello GNU coincide con questa regola nei casi provati.

L'indice effettivo è arg0&31. Per gli indici effettivi 16..31, il bit modificato
nel registro CPU cade fuori dalla lane halfword successivamente salvata:
il **valore low16** scritto resta uguale al precedente. Lo store MMIO avviene
comunque; non si deduce assenza di effetti fisici da una scrittura dello
stesso valore. L'indice 32 seleziona di nuovo il bit 0 nei test.

Il getter `10037BC` aggiunge 8 all'argomento, genera la maschera BSET,
interseca il valore letto, trasla di 8 e applica EXT B nel delay slot del
ritorno. La formula software verificata è:

`((read16 & (1 << ((arg0 + 8) & 31))) >> 8) & FF`

Con arg0=7 e bit 15 impostato il risultato è `80`, non 1. Nei campioni sono
osservati anche 0, 1, 2 e 4. Non sono stati testati tutti gli indici o tutti
i valori possibili: resta aperto il dominio usato dai chiamanti Nikon.

Non viene dichiarata un'equivalenza globale fra argomenti che condividono
i cinque bit bassi. L'harness varia anche il dato completo scritto a 2054;
le equivalenze della sola istruzione di selezione non implicano identità
della sequenza completa per arg0 e arg0+32.

## Sequenza 0→1

`1003804` scrive 0 a `FED2058`, poi 1. Non esegue RMW e non conserva gli
altri bit del valore iniziale. È una sequenza software osservata: la fixture
non modella reset, impulso elettrico, W1C, clock, IRQ o tempi del dispositivo.
Non viene attribuito alcun significato fisico alla transizione.

## Prove e conservazione

CPU: `outputs/gnu_arc700/20261025T204321Z_139819d0/`.
Audit: `Risultati/Processor_Registers/20261025T204714Z/evidence/tbib_fed20_tail_audit.json`.

Sedici routine originali per scenario. Tre pattern di seed incrociati con
tredici argomenti: 0, 1, 2, 7, 8, 15, 16, 23, 24, 31, 32, 80000000, FFFFFFFF.
Totale 39 scenari, 78 esecuzioni riferimento/osservatore e 39 coppie di tracce
identiche. 897 eventi halfword: 546 letture e 351 scritture. Exit 0, nessun
fault; stack e r13..r19 preservati. Nessun accesso AUX o DSP provvisorio.

L'audit verifica anche 624 carichi dai pool originali, opcode/operandi dei
getter dopo le maschere e nei delay slot, valori di ritorno controllati
dall'harness, ordine degli eventi e tutti i byte esterni alle lane scritte.
I byte TBIB completi e il checksum restano invariati. La guardia OOB della
disassemblazione globale non è stata aggirata o rimossa.

Verificati 43 atlanti PASS precedenti senza perdita di chiavi/geometrie.
Tutte le schede precedenti restano identiche salvo append a FED2038 e i
riferimenti AUX generati; 25 indici AUX con risultati guest, 204 ancore
run/PC, 50 finestre e due famiglie calcolate restano invariati.

Riproduzione:

1. `python3 Python_Trace_Scripts/s33_verify_tbib_fed20_tail.py`
2. `python3 Python_Trace_Scripts/s33_audit_tbib_fed20_tail.py outputs/gnu_arc700/20261025T204321Z_139819d0`

Il runner `s33_tbib_accessor_harness.py` e il publisher
`s33_publish_mmio_accessor_evidence.py` riusano compilatore, runner CPU,
osservatore e verificatori esistenti; sono separati dal modello numerico
specifico di queste routine e mantengono i controlli di conservazione.

## Limiti e seguito

La lettura del manuale conferma una regola ISA, non identifica il SoC o una
periferica Nikon. Seed, backing MMIO, stack e argomenti sono fixture.
Restano non provati boot TBIB completo, raggiungibilità globale, indici
leciti, reset, nomi fisici, permessi, side effect, IRQ, timing e atomicità.

Proseguire dagli altri gruppi TBIB e dai collegamenti indiretti oltre
`1003880`, oltre ad AUX/overlay, BCR/SoC e DSP fisica. Nessun hardware,
USB, NAND o SD toccato; originali e GNU invariati. Goal attivo.
