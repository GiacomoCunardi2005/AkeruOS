# S33 — CaptureImage: analisi del dispatch e dei percorsi a CapMgr

Modalità: **offline evidence reanalysis**. Firmware di riferimento: V1.1; fotocamera fisica registrata V1.0.

## Risultati derivati dalle evidenze disponibili

La scansione lineare registrata mostra 6 chiamate candidate dirette a `0x1B9EA8` nel blocco 02. La presenza del puntatore `0x65ED6C` nella tabella è confermata dal rapporto precedente; non risultano chiamate dirette `bl` a quell'handler nei dati forniti. Questo è compatibile con dispatch indiretto, ma non lo prova.

| Chiamata CapMgr | Invocazioni vicine di `0x12CAD4` (offset in byte) |
|---|---|
| `0x65f262` | `0x65f268` (+6), `0x65f286` (+36), `0x65f230` (-50) |
| `0x65f378` | `0x65f3ce` (+86), `0x65f2ac` (-204), `0x65f286` (-242) |
| `0x65fc48` | `0x65fc50` (+8), `0x65fc84` (+60), `0x65f68a` (-1470) |
| `0x65fc7e` | `0x65fc84` (+6), `0x65fc50` (-46), `0x65f68a` (-1524) |
| `0x65fcd6` | `0x65fc84` (-82), `0x65fc50` (-134), `0x65f68a` (-1612) |
| `0x65fd92` | `0x65fc84` (-270), `0x65fc50` (-322), `0x65f68a` (-1800) |

**Attenzione:** una chiamata vicina a `0x12CAD4` non è automaticamente un marcatore Start/End. I suoi argomenti, il flusso di controllo e gli eventuali delay slot vanno verificati separatamente.

Sono presenti le parole `0xB80022` e `0xB80023` anche a `0x65FDEC` e `0x65FDF0`; senza il binario non è possibile associare questi letterali a una chiamata specifica.

## Prossimo punto da verificare

1. Classificare i rami contenenti `0x65F378`, `0x65FC48`, `0x65FC7E`, `0x65FCD6`, `0x65FD92`.
2. Recuperare le istruzioni che caricano i letterali in `0x65FDEC` e `0x65FDF0`, con i loro delay slot.
3. Rintracciare il dispatcher che usa l'ID candidato `0x4405` e seleziona la entry `0x65ED6C`.
4. Localizzare i produttori del byte `0x681FF0+0x1D` e ricostruirne il significato.
5. Solo dopo, risalire a evento/input S2 e verificare le differenze fra firmware V1.0/V1.1.

Per estendere l'analisi con nuove verifiche dei binari, eseguire con `--project-root` sul computer che contiene i TBM.

## Limiti

L'analisi offline rielabora l'evidenza caricata, non verifica autonomamente i 16 binari. La modalità locale verifica hash e ottiene nuove finestre `objdump`, ma il disassemblaggio ARC lineare può scambiare dati per istruzioni: serve revisione manuale dei blocchi base/CFG.

Nessun collegamento fisico S2 dimostrato. Nessun firmware eseguito, modificato o flashato. Avanzamento funzionale complessivo invariato: **circa 10%**.

