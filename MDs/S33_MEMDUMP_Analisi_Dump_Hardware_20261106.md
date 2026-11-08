# Analisi del primo dump RAM su hardware

6 novembre 2026. Analisi di `Risultati/Dump_fotocamera/MEMDUMP_20261106/MEMDUMP.BIN` (17.041.228 byte, SHA-256 `c91888b2…6107`), prodotto dal [firmware v5](S33_MEMDUMP_Versione5_Handle_Esclusivo_20261106.md) sulla fotocamera dell'utente ([primo dump](S33_MEMDUMP_Primo_Dump_Hardware_20261106.md)). Metodo: script Python di lettura e confronto con i 16 payload del firmware V1.1 (`static_common.PS`); nessun accesso alla fotocamera in questa analisi. Il dump non è atomico: copre `[0, 0x0104074C)` e la RAM cambiava durante la scrittura.

## Ipotesi del firmware v5 confermate sull'hardware

- **Resource caricato e firmato:** a `0xE99E00` ci sono `0x4D444B41` e versione `5`; il payload è in RAM.
- **Flag one-shot:** la word del flag subito dopo le stringhe del payload vale `1` (task già reclamato).
- **Task creato come previsto:** in RAM compare il template del task: entry `0xE99EFC` (`memdump_task`), stack `0x8000`, priorità `0x13` (19), nome `MEMDUMP` (`0xE9A204`). Compaiono due copie nei blocchi di controllo del kernel (`0x3FD0C`, `0x3FDC0`) e il template a `0x52A0C`.
- **Identità del task corrente:** `[0x369348] = 0x1800` e `[0x1800+0x1C] = 0x5291C`. Il contesto dell'handle (nel payload) ha `owner = 0x5291C`, `handle = 0x5AA9C`, `phase = 3`: **l'identità del task usata dall'adapter coincide con il campo del kernel**, quindi l'ipotesi `[0x369348]+0x1C` è confermata. `phase = 3` dice che il dump è stato catturato durante la seconda scrittura (a quel punto il diagnostico era dentro l'adapter).
- **Handle esclusivo vivo:** `0x5AA9C` è l'oggetto file tenuto aperto; compare come riferimento in `0x5A874…` e in `0xE9A224` (contesto).
- **Stack di MEMDUMP:** regione `[0x52A28, 0x5AA28)` riempita da `katskats`; al momento del dump erano usati solo **1584 byte su 32768 (4,8%)**. Lo stack da `0x8000` è abbondante.

## Residenza dei payload firmware nella RAM

Confronto byte a byte della RAM con i blocchi originali (indirizzo = base trovata, ricercata con pezzi di 64 byte):

| Payload | Indirizzo RAM | Coincidenza |
|---:|---:|---:|
| 0 (MainCode) | `0x00AD800` | 100,00% (2.810.811/2.810.880) |
| 1 | `0x0360800` | 95,50% (781.886/818.688: dati modificati a runtime) |
| 2 | `0x05FE800` | 100,00% |
| 3 | `0x0669800` | 99,97% |
| 4 | `0x0796800` | 100,00% |
| 5 | `0x0897800` | 100,00% |
| 6 | `0x09A3800` | 100,00% |
| 7 | `0x0C67800` | 100,00% |
| 9 (Resource) | `0x0C8F800` | 99,96% (inclusa la nostra modifica) |
| 10 | `0x0F20800` | 100,00% |

I payload 11–15 non compaiono nell'intervallo dumpato (le loro basi candidate `0x01044800` sono oltre `0x0104074C`); **non dimostra** che non siano residenti altrove. Il payload 8 è troppo corto per questa ricerca.

## Altre osservazioni

- Tabella regioni: `[0x441F94] = 0x01BF9800` (minimo registrato del gestore memoria), flag `0x365625 = 1` e `0x366889 = 1`: coerente con le prove statiche.
- Tabella clock `0x443FF0`: 180 zeri nel dump, coerente con il CSV già esportato (rappresentazione software distinta dal BFN).
- Pattern del test memoria BootNAND ancora visibili a `0x0` (alterato) e `0xC00000`.
- Zeri: 22,8% del file; fascia 4–6 MiB quasi vuota (66–85% zeri).

## Limiti

- Un solo dump, non atomico, 6,4% della RAM configurata.
- Il confronto dei payload usa pezzi da 64 byte come ricerca: basi con pochi voti (3 o 2 su 5) sono verificate poi sul confronto completo ma non sull'intero spazio.
- Non so come e quando la fotocamera ha creato le altre strutture del kernel: sono solo osservate.
- `rea` non è stato usato: il dump è un'immagine grezza di RAM e il suo supporto riguarda ELF ARCompact.

**Prossimo:** mappare lo scheduler (liste di task, priorità, stack) e le tabelle del kernel; estendere l'intervallo con una v6 per vedere gli indirizzi alti. Nessun'altra operazione su hardware senza ambito esplicito.

Mappa dello scheduler e delle tabelle del kernel: [dettaglio](S33_Kernel_Scheduler_e_Tabelle_da_Dump_Hardware_20261106.md).
