# FE9 — sette chiamanti e sei nuove celle

25 ottobre 2026. Stato: PASS offline, mappa fisica incompleta, NON_INSTALLARE.

## Risultato

Atlante: `Risultati/Processor_Registers/20261025T200238Z/REGISTER_MAP.md`.
Totale 1124 voci: 64 posizioni core, 197 AUX, 863 MMIO singoli.
Sei nuovi indirizzi, due schede arricchite; nessuna nuova finestra.
Restano invariati geometria delle 50 finestre, famiglie calcolate e 172 siti
AUX ancorati a traccia. Verificati i ledger dei 39 atlanti PASS precedenti:
nessuna chiave o geometria persa.

| Wrapper | Indice locale | Destinazione A | Destinazione B | Maschera low16 | Esito |
|---|---:|---|---|---|---|
| `2EE760` | 0 | `FE90000` | `FE98000` | `1FFF` | Nuove |
| `2EE760` | 1 | `FE90004` | `FE98004` | `1FFF` | Nuove |
| `2EE760` | 3 | `FE90014` | `FE98014` | `0FFF` | Nuove |
| `2EE850` | 6 | `FE90144` | `FE98144` | `0003` | Esistenti arricchite |

Le destinazioni e maschere provengono dalle parole dei payload 0/1 originali;
non da tabelle sintetiche né dalle distanze fra puntatori adiacenti.
Il contratto software osservato è RMW halfword sui campi mascherati.
I nomi fisici delle periferiche e i permessi hardware restano ignoti.

## Chiamanti ricostruiti

Il riconoscitore precedente ammetteva soltanto pochi opcode e una distanza
massima di otto byte. I sette casi mancanti non erano quindi prove di indici
dinamici. Verifica esatta di opcode, operandi, byte e continuità dei segmenti:

| Chiamata BL | Wrapper | Indice | Motivo della precedente esclusione |
|---|---|---:|---|
| `295408` | `2EE760` | 3 | `sub_s r1` fra setup e BL |
| `295F92` | `2EE850` | 6 | `ld r14` lungo prima del BL |
| `2ED642` | `2EE760` | 0 | Costante in r14, poi copia in r0 |
| `2ED650` | `2EE760` | 1 | `sub_s r1` fra setup e BL |
| `2ED67E` | `2EE850` | 6 | Tre percorsi locali con r1=1/2/0 |
| `2ED774` | `2EE8F0` | 0 | Costante in r13, poi copia in r0 |
| `2EDF9E` | `2EE8F0` | 8 | `mov r1,-1` non ammesso dal riconoscitore |

La parola originale a `295F30` vale `2EE850`. Il caricamento in r14 a
`295F8E` precede il BL; `295F98..295F9E` prepara indice 6 e chiama `[r14]`.
Questo resta un candidato indiretto con dipendenza dalla conservazione di r14
attraverso il BL. La conservazione è testata nei fixture dei wrapper; non è
stata eseguita la sequenza originale del chiamante né provata raggiungibilità
globale. Nessuna nuova prova per `2EE924/2EE974`.

## Evidenze e riproduzione

1. `python3 Python_Trace_Scripts/s33_verify_fe9_remaining_callers.py`
   produce i sette riscontri locali e otto selezioni tabellari.
   Esecuzione: `Risultati/Processor_Register_FE9_Remaining/20261025T200040Z/`.
2. `python3 Python_Trace_Scripts/s33_verify_fe9_remaining_cpu.py Risultati/Processor_Register_FE9_Remaining/20261025T200040Z`
   esegue wrapper/helper originali con entrambi i payload mappati invariati.
   Esecuzione: `outputs/gnu_arc700/20261025T200116Z_013aed64/`.
3. `python3 Python_Trace_Scripts/s33_integrate_fe9_remaining.py outputs/gnu_arc700/20261025T200116Z_013aed64`
   ricalcola per bit i risultati, controlla carichi tabella, tracce, buffer e
   conservazione della copertura prima di integrare.

CPU: otto scenari, sedici esecuzioni, 64 eventi MMIO (32 read/32 write),
64 carichi di parola tabellare verificati. Otto coppie di tracce riferimento/
osservatore identiche, exit 0, nessun fault. Stack e r13..r19 preservati nei
fixture. Quattro equivalenze delle sequenze MMIO: cambia soltanto il canale
1→2/FFFFFFFF, con indice, seed, valore, harness e byte originali invariati.
Non si dichiara identità delle tracce CPU complete tra canali diversi.

Il primo candidato `20261025T200214Z` è FAIL_NOT_ADMITTED: il controllo di
conservazione confrontava letteralmente i percorsi AUX rilocati dal builder.
La correzione confronta tutte le proprietà AUX dopo sola rilocazione del
prefisso della cartella; le schede MMIO restano confrontate senza normalizzare
i percorsi. Le prove CPU sono riusate, non ripetute.

## Limiti e seguito

Questi sono riscontri locali e CPU emulata con backing MMIO, seed, stack,
valore e canale sintetici. I sette chiamanti originali non sono stati eseguiti.
Non sono provati tutti gli ingressi nei segmenti, tutti gli indici leciti,
raggiungibilità globale, reset, W1C, IRQ, timing o atomicità fisica.
Originali e GNU invariati; nessun accesso hardware, USB, NAND o SD.

Continuare dai gruppi originali dopo `309CD0`, dagli ingressi indiretti/tail
di `2EE924/2EE974`, da AUX codice/dati, BCR e semantica DSP/`303A40`.
Il goal resta attivo: l'atlante non delimita l'universo fisico dei registri.
