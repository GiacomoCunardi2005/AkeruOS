# Restore 0x7F9F7C del blocco contesto salvato: census dei chiamanti, gate 0x14504C e consumer identificati — 1 novembre 2026 (iterazione 43)

## Domanda

Punto aperto dell'iterazione 42 ([rapporto](S33_GUI_Cella_Desiderata_Produttore_Save_Restore_20261101.md)): census dei chiamanti `bl` del **restore 0x7F9F7C** (p4) e del contesto 0x7F6ADE/0x7F6AE6, con classificazione dei gate — in particolare se il restore scatta rientrando nel modo di scatto (il candidato naturale era il modo 3 in cui i tre caller `save_then_mode3` collocano la macchina) e quali consumer (0xCE1EC, 0x163D6C con la word ≤400, 0xDEBCC) ricevono i valori salvati da 0xD0478 nel blocco `0x3657C8..0x3657D4`.

## Verificatore ed esiti

- Script: `Python_Trace_Scripts/s33_verify_capture_restore_caller_census.py` (statico byte-esatto + 7 casi CPU con byte firmware originali).
- `python3 Python_Trace_Scripts/s33_verify_capture_restore_caller_census.py` → **PASS_CAPTURE_RESTORE_CALLER_CENSUS 20261101T125629170398Z**; riesecuzione indipendente → **PASS_CAPTURE_RESTORE_CALLER_CENSUS 20261101T125636197637Z** (asserzioni statiche byte-identiche salvo `utc`; i 7 casi CPU identici in nome, fault e conteggio istruzioni: 30/32/11/13/12/113/113).
- [Evidenze](../Risultati/GUI_S33/capture_restore_caller_census_cpu_20261101T125629170398Z/) (`static_evidence.json`, ELF/assembler/linker script/log per caso); [riesecuzione](../Risultati/GUI_S33/capture_restore_caller_census_cpu_20261101T125636197637Z/).
- Regressioni rieseguite tutte PASS: guard setter census **20261101T125645380828Z**, flag mode matrix 14 casi **20261101T125702318965Z**, snapshot record init 4 casi **20261101T125703162581Z**, service raise pending **20261101T125704Z**, desired cell producer **20261101T125710935707Z**.

## Risultato 1 — il restore ha ESATTAMENTE un chiamante, dentro l'handler dell'evento 0x4405 di una finestra con tabella eventi a 0x99AB8C

- Census sul listing GNU: `bl` verso 0x7F9F7C = **solo 0x7F6BB0** (p4); **zero** parole LE 0x7F9F7C in tutti i 16 payload (nessuna jump table o puntatore). Il chiamante è incondizionato (nessun branch fra l'attesa 0x158d04 e la chiamata).
- La funzione contenitore **0x7F6A90 NON ha chiamanti bl**: l'unica parola LE a lei allineata è a **0x99AB98 (p5)** — è un callback registrato. La tabella eventi alla base 0x99AB8C contiene le coppie congelate:

| evento | handler |
|---|---|
| 0x4401 | 0x7F6A50 |
| **0x4405** | **0x7F6A90** |
| 0x4406 | 0x7F7218 |
| 0x440E | 0x7F7438 |
| 0x440C | 0x7F8394 |

e più avanti la coppia (0x2180, 0x7F7F8C): **la stessa finestra gestisce anche l'evento del pulsante logico 2 (0x2180)**. La struttura contiene inoltre i puntatori 0x99AAE8 (array finestre, usato dall'handler per chiudere le sottofinestre via 0x145b08) e 0x7F6824, e il valore 0x4A1C (pool 0x7F6E30) passato a 0x145654/0x1450b8.

## Risultato 2 — il restore è un dispatcher senza branch: 6 valori salvati + una costante

Finestra congelata 0x7F9F7C..0x7F9FBC (19 istruzioni, **nessun branch**, `push_s blink` … `pop_s blink; j_s [blink]`), ordine verificato byte-esatto:

| passo | sorgente | consumer | larghezza |
|---|---|---|---|
| 1 | getter 0xD0520 (0x3657CA, `ldw_s.x` **halfword con estensione di segno**) | 0xCE1EC | 16 bit |
| 2 | getter 0xD04E8 (0x3657D0) | 0x17C5E4(r0, **r1=r2=-1**) | byte |
| 3 | **costante 0x64** (mov_s r0,0x64) | 0x14A900 | — (NON un valore salvato) |
| 4 | getter 0xD0518 (0x3657D4, `ld` **32 bit**) | 0x163D6C | word |
| 5 | getter 0xD04F4 (0x3657CD) | 0x17E124 | byte |
| 6 | getter 0xD0500 (0x3657CE) | 0x17E36C | byte |
| 7 | getter 0xD050C (0x3657CF) | 0xDEBCC | byte |

Correzione di dettaglio verso l'it.42: la catena di restore include anche **0x14A900 chiamato con la costante 100**, non un valore del blocco. Census incrociato: ogni getter ha esattamente un chiamante bl — sei dentro 0x7F9F7C (0x7F9F7E/86/9A/A2/AA/B2), il settimo (0xD04DC, guardia salvata) a 0x7F6AE6 fuori dal restore. **Il restore non tocca 0x3657C8 né 0x3657CC**: la «modalità desiderata» e la guardia salvata NON sono ripristinate da questa funzione.

## Risultato 3 — il gate prima del restore: 0x14504C(a,0x12)==3 azzera 0x89A330, altrimenti copia la guardia salvata; poi modo 3 e attesa

Sequenza congelata 0x7F6AD2..0x7F6AEE (p4):

1. `bl 0x14504C(arg0, 0x12)` → risultato confrontato con 3;
2. **==3**: `stb 0 → [0x89A318]+0x18 = 0x89A330`;
3. **!=3**: `bl 0xD04DC` (guardia salvata 0x3657CC) → `stb → 0x89A330`;
4. `mov r0,3; bl 0xCA404` (0x7F6AEE-0x7F6AF0): l'handler transita al **modo 3**.

Prima della chiamata del restore (0x7F6BB0) l'handler ha già: chiuso le sottofinestre dell'array [0x99AAE8] (conteggio da 0x14504C(arg0,6), chiusura via 0x145b08), azzerato il blocco 0x89A318+0xA..0x19 e 0x89A334, richiesto la risorsa 0x4A1C (0x145654/0x1450b8 con 360), e infine **atteso** `bl.d 0x158d04(r0=0x02600001, r1=8, r2=0)` con pool 0x7F6E34=0x02600001 e 0x7F6E38=0x2710 (10000).

**Risposta alla domanda dell'iterazione 42: il restore NON avviene rientrando nel modo di scatto.** Avviene nell'handler dell'evento **0x4405** di questa finestra, DOPO che l'handler stesso ha transizionato al modo 3 e DOPO un'attesa sul servizio 0x2600001. Il ciclo è: save 0xD0478 all'uscita dal modo di scatto (it.42) → il contesto viene ripristinato quando questa finestra riceve 0x4405 e ha completato la propria procedura di chiusura/attesa. Il significato dell'evento 0x4405 in questa finestra (per analogia con CaptureMenu dove 0x4405 pilota l'aggiornamento dei flag, it.39) resta APERTO; la schedulazione runtime NON è provata.

## Risultato 4 — consumer identificati: le celle runtime che ricevono il contesto salvato

Finestre congelate byte-esatte (testa di ciascun consumer):

| consumer | comportamento verificato |
|---|---|
| 0xCE1EC | `stw_s r13,[0xC8EC52]` (pool 0xCE208, record TBIB p8), poi tail `bl 0xDE664(valore)` → `b 0xC979A` |
| 0x17C5E4 | agisce **solo se il byte == 254 (0xFE)**; altrimenti salta a 0x17C6E8 (via) |
| 0x14A900 | funzione complessa con attese 0x158ce0/0x158cbc/0x158d04 (riceve la costante 100) |
| 0x163D6C | `st r0,[0x3676F8]` (pool 0x163D84), semplice setter word |
| 0x17E124 | `stb r13,[0x367C05]` (pool 0x17E234) + dispatch su r13 ≤ 0x10 (17 vie) |
| 0x17E36C | `stb r14,[0x367C06]` (pool 0x17E368) + validatore indiretto [r15] + dispatch r14 ≤ 0xB |
| 0xDEBCC | validazione `bl 0xDEB70`, poi `stb r1,[0x365BBD]` (pool 0xDEBE4) |

Dopo il restore l'handler controlla:

- **0x7F9B00**: legge il byte **[0x89A330]** (pool 0x7F9B14, la stessa cella scritta dal gate) e ritorna 1 solo se il valore è **1 o 2** (census: tre chiamanti — 0x7F6BB4, 0x7F6BE0, 0x7F9B2A);
- **0xD0800** (9 chiamanti censiti): dietro il gate 0x15AD44 legge il byte **0x3657F4** (pool 0xD0818), tail 0xCA384.

Quindi il byte copiato dal gate (0 o guardia salvata) in 0x89A330 è **riletto dopo il restore** e confrontato con {1,2}: il collegamento tra guardia salvata e percorso post-restore passa per 0x89A330, la cella già vista in it.40/41 come base dei siti calcolati (pool 0x7F86BC/0x7F94E4/0x7F9B14).

## Risultato 5 — CPU con byte originali: gate, controllo 0x89A330 e dispatcher completo

7 casi sul simulatore GNU ARC700 (byte firmware originali per restore, gate, getter cluster 0xD04C8..0xD0534 con i propri pool, finestra 0x7F9B00 con pool; query 0x14504C e consumer sostituiti da stub registratori in copia):

1. `gate_query_eq3`: query=3 → **[0x89A330] azzerato** (fault `0xdead0000`); la cella 0x3657CC resta 0x07 (il getter NON è chiamato — controllo negativo); sentinelle 0x89A32F/0x89A331 intatte; r0=3 in uscita dal gate.
2. `gate_query_ne3`: query=4 → **[0x89A330] = 0x07** (fault `0xdead0007`): la guardia salvata 0x3657CC è copiata dal getter ORIGINALE 0xD04DC (pool 0xD04E4 letto dai byte originali).
3-5. `check_v1/v2/v3`: byte [0x89A330] = 1/2/3 → ritorno 1/1/0 (fault `0xdead0001`/`0xdead0001`/`0xdead0000`; v3 è il controllo negativo). Il getter originale risolve il pool 0x7F9B14=0x89A330 dai byte originali.
6-7. `restore_dispatch_a/b`: restore ORIGINALE + getter ORIGINALI (pool originali nel cluster), 7 consumer stub registratori con log a 0x367000; due set di marker distinti. Verificato in un'unica esecuzione l'ordine esatto dei consumer, i valori per-cell (halfword 0x3657CA=0x1234/0x4321, byte 0x3657D0=0x37/0xC9, **r1=r2=0xFFFFFFFF per 0x17C5E4**, **r0=0x64 per 0x14A900**, word 0x3657D4=0x190/0x22C, byte 0x3657CD/CE/CF=0x11,0x22,0x33 / 0x77,0x88,0x99), fault di successo `0xdeadaa01`.

Scoperta tecnica dei casi 6-7: il getter 0xD0520 carica la halfword con **`ldw_s.x` (estensione di segno)** e il getter 0xD0518 carica la **word a 32 bit** (it.42 aveva verificato 0xD0518 in CPU; la larghezza di 0xD0520 è precisata qui). I marker dei casi mantengono bit15=0 e marcano tutti e 4 i byte della word 0x3657D4, così il valore osservato coincide col marker.

## Audit indipendente

**Agente `restore-audit-44`** (tools.agents.spawn, atteso e integrato; «task con agente explore» inesistente, come documentato nelle iterazioni precedenti). Metodo indipendente: regex proprie sul listing (362.109 branch censiti con target ricalcolato come (PC&~3)+disp per i PC ≡ 2 mod 4), ridisassembly ex-novo con arc-elf32-objdump di 13 finestre estratte dai payload, scan LE a ogni offset dei 16 payload **e dell'intero firmware.bin**, lettura diretta delle evidenze congelate senza eseguire il verificatore.

- **C1–C8 tutti CONFERMATI byte-exact, zero controesempi di sostanza.** Punti salienti: 0x7F9F7C ha 0 parole LE anche nell'intero firmware.bin; 0x7F6A90 ha zero rami di qualsiasi tipo verso di essa e una sola word allineata; i `.orig*.bin` delle evidenze sono byte-identici ai payload (66/30/108/24 byte).
- **Aggiunte dell'audit riverificate in coordinatore**: (1) lettori aggiuntivi del byte 0x89A330 fuori dalle finestre congelate: **0x7F8690 e 0x7F875E** (ldb [pool 0x7F86BC=0x89A330]) il cui valore è passato **direttamente al setter della guardia 0xCA2F4** (0x7F8694, 0x7F8764), e **0x7F947E** (ldb [pool 0x7F94E4=0x89A330], cmp 4, dispatch 5 vie 0..4). Questo è un ponte nuovo tra il gate del restore e la guardia CaptureMenu (it.40/41): il byte copiato dal gate può tornare dentro il setter della guardia. Il gate resta l'unico writer individuato; gli altri 7 pool della base 0x89A318 non hanno store [+0x18] nel raggio di 8 istruzioni (euristica, non esaustiva). (2) 0x14A900 ha un secondo chiamante bl (0x64EF94, p2) fuori dal restore; 0xD0800 ne ha 9, 0x7F9B00 tre — nessun claim di unicità era fatto per queste funzioni.
- **Correzioni di documentazione accolte**: le directory di evidenza non contengono file .trace (l'evidenza CPU è static/verified_evidence.json, .log e harness .s/.ld + .orig*.bin); l'ordine dei consumer è dato dalla sequenza bl statica nei byte originali (verificata ex-novo), mentre i casi CPU dimostrano chi riceve quale argomento; nel listing i target bl con PC ≡ 2 mod 4 vanno ricalcolati come (PC&~3)+disp.
- L'agente ha registrato in autonomia l'esito nel PMB (record_batch 375, riferito dall'agente stesso).

## Fonti precise

Payload4 (base 0x796800): restore 0x7F9F7C..0x7F9FBC (pool nessuno), handler 0x7F6A90 (prologo da 0x7F6A90: contesto r14/r17/r18, 0xD1644, 0x143afc, 0x14504C(a,6/0x12/0xE)), gate 0x7F6AD2..0x7F6AF0 (pool 0x7F6E20=0x89A318), sito chiamante 0x7F6B9E..0x7F6BF2 (pool 0x7F6E2C=0x89A334, 0x7F6E30=0x4A1C, 0x7F6E34=0x02600001, 0x7F6E38=0x2710), getter 0x7F9B00 con pool 0x7F9B14=0x89A330, wrapper 0x7F9B1A (terzo chiamante di 0x7F9B00 a 0x7F9B2A). Payload5 (base 0x897800): tabella eventi 0x99AB8C (coppie congelate), coppia 0x2180→0x7F7F8C a 0x99ABD4/0x99ABD8, strutture 0x99AAE8/0x99AB74/0x99AB78=0x7F6824. Payload0 (base 0xAD800): cluster getter 0xD04C8..0xD0534 (pool 0xD04C8=0x3657CA, 0xD04CC=0x3657D4, 0xD04D0=0x3657C0, 0xD04D4=0x3657CC, 0xD04D8=0xC8E80C, 0xD0530=0x3657C8; corpi 0xD04DC..0xD052E), consumer 0xCE1EC (pool 0xCE208=0xC8EC52), 0x163D6C (0x163D84=0x3676F8), 0x17E124 (0x17E234=0x367C05), 0x17E36C (0x17E368=0x367C06), 0xDEBCC (0xDEBE4=0x365BBD), 0x17C5E4 (gate 0xFE, pool 0x17C718=0xFFFF), 0xD0800 (0xD0818=0x3657F4), 0x14A900.

## Limiti e non-dimostrato

- Statico + 7 casi CPU sintetici; nessun hardware, scatto, rendering, persistenza. Circa 10% invariato; NON_INSTALLARE.
- La schedulazione runtime dell'handler 0x7F6A90 (chi invia l'evento 0x4405 a questa finestra e quando) NON è provata; il collegamento con i 5 caller del save 0xD0478 resta ipotesi coerente (modo 3 comune), non catena dimostrata.
- Le finestre congelate dei consumer sono le teste: corpi oltre la testa (jump table di 0x17E124/0x17E36C, validatore 0xDEB70, tail 0xDE664/0xC979A, funzione 0x14A900) NON decodificati.
- La semantica dell'attesa 0x158d04 con id 0x02600001 e argomento 8 e il pool 0x7F6E38=0x2710 NON decodificata in questa iterazione.
- Il significato di 0x14504C(a, 0x12) e della condizione ==3 resta APERTO; 0x89A318/0x89A330/0x89A334 non hanno produttore runtime censito qui.
- V1.1 campione vs macchina V1.0.

## Prossimo passo (non ripetitivo)

(a) **Ponte 0x89A330 → guardia**: i siti 0x7F8694/0x7F8764 passano il byte [0x89A330] direttamente al setter 0xCA2F4 — decodificare il contesto di questi due siti (gate, condizioni, quando girano rispetto all'handler 0x4405 e all'attesa 0x158d04) per capire se la copia della guardia salvata da parte del gate può rientrare nella guardia CaptureMenu: è il pezzo che collega il restore al ciclo guardia/flag già mappato (it.39–41). (b) In alternativa: chi registra la tabella eventi 0x99AB8C (descrittore da individuare nella struct 0x99AB40 con 0x99AAE8/0x7F6824) e come la finestra entra nel WindowManager — collega il restore ai percorsi GUI (0x2180 → 0x7F7F8C è già nella stessa tabella).
