# AUX — tredici routine candidate e riferimenti sovrapposti

25 ottobre 2026. PASS statico delimitato; nessuna nuova ammissione.

Le tredici routine locali sotto riguardano sei indici assenti dall'atlante.
La scansione dei riferimenti ha trovato cinque pattern B/BL, tutti iniziati
dentro istruzioni più lunghe nella fase di decodifica conservata. Nessuno
costituisce quindi un chiamante qualificato in questa ricerca. Le routine
restano candidate: non sono dichiarate dati né globalmente irraggiungibili.

Atlante invariato: `Risultati/Processor_Registers/20261025T202612Z/`,
1179 voci (64 core, 200 AUX, 915 MMIO), ledger 312 verificato e immutato.

## Routine locali

| Indice AUX candidato | Ingressi delle routine |
|---|---|
| `1028B` | `319AAC`, `319AB8`, `319ACC`, `319AE0` |
| `10004` | `342BD0`, `342BE4`, `342BF8` |
| `10031` | `342C88` |
| `10033` | `342CC0` |
| `10035` | `342CF8`, `342D0C` |
| `10038` | `342E4C`, `342E68` |

Ridecodificate 68 istruzioni, con 20 siti LR/SR nelle routine.
Per ogni ingresso sono stati percorsi il CFG locale, i rami interni e i
delay slot di ritorno. I byte di ogni istruzione ridecodificata coincidono
con il payload originale. Ogni routine termina tramite blink e gli accessi
LR/SR espliciti sono coerenti con il rispettivo indice.

La forma locale suggerisce accessori per byte/campi di `1028B`, bit 7 di
`10004`, nibble basso di `10031/10033`, bit 0 di `10035/10038`.
Queste sono descrizioni candidate del codice; non sono risultati numerici
eseguiti né nomi di periferiche. Non si aggiungono i sei indici sulla sola
base della plausibilità di queste sequenze.

## Cinque riferimenti esclusi nella fase di decodifica verificata

| Payload | Pattern candidato | Destinazione | Istruzione contenente il suo inizio |
|---|---|---|---|
| 0 | B a `2F1DD0` | `342BD0` | `asl r1,r0,24` a `2F1DCE` |
| 0 | B a `33550E` | `342D0C` | `mov r1,100000` a `335508` |
| 0 | BL a `34258C` | `342D0C` | `lr r1,[10112]` a `34258A` |
| 0 | BL compatto a `343812` | `342BD0` | `mov_s r0,38FCF0` a `34380E` |
| 3 | BL a `703272` | `342E68` | `stb.di.as` a `703270`, fase non qualificata come codice eseguito |

Alcuni pattern candidati iniziano dentro una istruzione e proseguono nei byte
della successiva: non occorre che l'intera codifica candidata sia contenuta
nella prima istruzione per respingerla come bordo in questa fase. Il controllo
iniziale troppo restrittivo è stato corretto in questo senso.

Il caso del payload 3 non viene trasformato in una dichiarazione globale di
"solo dati". La sovrapposizione nella fase trattenuta e l'assenza di una prova
di ingresso non sono una prova contro ogni possibile ingresso alternativo.

## Copertura

Sedici payload TBM originali verificati con hash:

- B/Bcc compatti e B simm21/25 a ogni halfword completo.
- BL tramite il decoder esistente e controllo esplicito del BL compatto
  nell'ultimo halfword, evitando il precedente buco di due byte.
- Pattern di puntatore word LE e LIMM a halfword LE, a ogni offset byte,
  verso tutti i tredici ingressi: nessuna corrispondenza.

Non sono coperti TBIB, BRcc, BBIT, LP, salti via registri, puntatori calcolati
o codificati, codice esterno, ingressi interni o fasi di istruzione alternative.
Non è dimostrata l'assenza globale di chiamanti o l'assenza fisica dei registri.

Non sono state eseguite le routine: non è stato fornito un dispositivo AUX
sintetico per aggirare il limite del banco GNU. I risultati sono statici.

Riproduzione:

`python3 Python_Trace_Scripts/s33_audit_unanchored_aux_leafs.py`

Prove e ledger: `Risultati/Processor_Register_AUX_Candidates/20261025T203030Z/`.
Il manifest conserva routine, bordi CFG, ritorni/delay slot, candidati B/BL,
istruzioni contenenti gli inizi dei pattern e copertura per payload.

## Seguito

Cercare produttori di puntatori e ingressi indiretti per questi sei indici;
proseguire sugli altri overlay, sugli indici AUX dinamici e sulla lacuna della
disassemblazione globale TBIB, senza alterarne i byte. BCR/SoC e implementazione
fisica restano aperti. Nessun hardware, USB, NAND o SD toccato; GNU e firmware
originali invariati. NON_INSTALLARE; goal attivo.
