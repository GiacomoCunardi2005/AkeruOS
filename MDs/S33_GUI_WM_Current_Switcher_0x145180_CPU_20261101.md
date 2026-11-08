# Commutatore finestra corrente 0x145180: writer di [0x366EA4] — statico + 8 casi CPU su byte originali

**Iterazione 18 (ciclo 15) — 1 novembre 2026 — studio offline, NON_INSTALLARE**

## Domanda

Punto aperto (b) dell'iterazione 46 ([S33_GUI_WM_Service_Dispatch_0x169D78_CPU_20261101.md](S33_GUI_WM_Service_Dispatch_0x169D78_CPU_20261101.md), prossimo passo): chi scrive la cella della finestra corrente **[0x366EA4]** (= contesto maestro WindowManager **0x366E94**+0x10, consultata dal resolver di consegna 0x1453F4/0x1453FC tramite pool 0x14579C)? L'audit it.46 (C8c) non aveva trovato nessuno writer statico della cella esatta e ipotizzava store indiretti nel commutatore 0x145180 (`st_s r13,[r0,0x10]` con r0=[pool 0x145350]).

## Riassunto del risultato

- **Risposta**: il writer è il commutatore **0x145180(target, arg)** stesso, via master+0x10/master+0x14 (il pool della cella esatta 0x366EA4 esiste SOLO per i due getter 0x1453F4/0x1453FC). Il commutatore scrive la finestra corrente in **tre siti** e la finestra pending in **tre siti**, con gate di rientranza sul byte busy [0x366EBB] e un ciclo di transizioni concatenate pilotato dai VALORI DI RITORNO delle consegne 0x4403/0x4405.
- Prove: verificatore nuovo `s33_verify_wm_current_switcher_cpu.py` → **PASS_WM_CURRENT_SWITCHER 20261101T152007762890Z** + riesecuzione byte-identica **152018293529Z** (8 casi CPU con finestre ORIGINALI, epilogo millicode ORIGINALE 0x33418C eseguito, nessun taglio); post-audit (LE scan estesi a 0x366EAC/0x366EB8) → **PASS 153605977322Z + riesecuzione identica 153638728092Z**; 6 regressioni PASS; 6 micro-test di banco (tmp/it18_bltest) sui branch 32-bit a displacement positivo grande.
- Punto APERTO it.46(b) CHIUSO. Il commutatore window-manager è ora decodificato per intero: è il pezzo che collega la catena `evento → wrapper → tabella finestre RAM → transizione → eventi lifecycle (0x4401..0x4415) → celle corrente/pending`.

## 1. Contesto maestro 0x366E94 (pool 0x145350) — layout completato

| Campo | Cella | Writer/lettore identificati |
|---|---|---|
| +0x00 | 0x366E94 | puntatore tabella finestre 0 — setter **0x145010** (st [0x366E94], stw [+4]) |
| +0x04 | 0x366E98 | count0 (u16) — setter 0x145010 |
| +0x08 | 0x366E9C | puntatore tabella finestre 1 — setter **0x145018** |
| +0x0C | 0x366EA0 | count1 (s16) — setter 0x145018 |
| +0x10 | 0x366EA4 | **CORRENTE** — commutatore 0x145180 (3 store, §2) |
| +0x14 | 0x366EA8 | **PENDING** — commutatore 0x145180 (3 store, §2) |
| +0x18 | 0x366EAC | **CONTROLLO ATTIVO** — 0x145B9A dentro 0x145B08 (§6, statico) |
| +0x24 | 0x366EB8 | gate coda post-successo (0x145150/0x145158) |
| +0x27 | 0x366EBB | **BUSY** (=[0x366EB0]+0xB, pool 0x145358): gate+set+clear nel commutatore |

LE scan congelati: 0x366E94 → pool {0x145350 (commutatore+0x14507C), 0x145BE4 (funzione B)}; 0x366EA4 → solo pool {0x14579C}; **0x366EA8 → NESSUN pool** (si raggiunge solo via master+0x14); 0x366EAC → solo pool {0x1457D0} (famiglia getter 0x145790/0x1457D4); 0x366EB0 → {0x145358, 0x145BDC}; 0x366EB8 → {0x1457A0}.

## 2. Commutatore 0x145180 — decodifica completa (byte originali)

Finestra 0x145180..0x1453E4 (612 byte, pool 0x145350..0x145378 INTERNI), sha256 `a8dd886d51c9d249694674ef584c5eb8a6c19b604020a4365003d5c41031bd87`.

- **Store CORRENTE [master+0x10]**: `0x1452EE st_s r13,[r0,0x10]` (current := target, subito dopo la consegna 0x4401); `0x145306 st_s r1,[r0,0x10]` con r1=[master+0x14] (current := pending, dopo la consegna 0x4415 al pending); `0x145338 st_s r15,[r0,0x10]` con r15 = vecchia corrente (via 0x14530A) oppure il nodo PENDING (delay slot 0x1452F2) — NON il "chain-next" (il prossimo nodo della catena diventa il target del loop-back; precisazione audit).
- **Store PENDING [master+0x14]**: `0x145234 st_s r1,[r0,0x14]` (pending := current, dopo 0x4414 alla vecchia finestra); `0x14534C st_s r14,[r0,0x14]` (pending := vecchia corrente); `0x14538A st_s r13,[r0,0x14]` (pending := target).
- **Gate d'ingresso** (tutti provati in CPU, byte originali): target==0 → return 0 (0x14518C beq.d, delay mov r16,r1); flag[nodo] bit0 → return 0 (0x145192-0x145198); **[master+0x27]≠0 (busy) → return 0** (0x14519C-0x1451A4: il commutatore è non-rientrante, il busy che setta a 0x1451AC e che azzera a 0x145396 è lo stesso byte che consulta all'ingresso; i gate d'ingresso escono SENZA toccare il busy).
- **check 0x14503C(ptr,off) = [ptr+off]** (foglia, `e080 04f4 e07f 00d8 3860 e07f 0080`): il commutatore testa i bit 0/7/8/9/0xA/0xC della prima word del descrittore finestra [nodo+0].
- **ATTENZIONE delay slot** (correzione alla lettura ingenua, confermata dall'audit): il `beq_s` a 0x1452AA usa le flag del `btst bit9` a 0x1452A4 (0x1452A6/0x1452A8 sono load e non toccano le flag): la consegna (pending, 0x4406, target) a 0x1452AE avviene SOLO se il PENDING ha bit9 SET; la (pending, 0x4402, 0) a 0x1452D2 solo se il pending ha bit8 SET (cmp a 0x1452C8, beq a 0x1452CA). Inoltre la consegna 0x4406 alla vecchia finestra (0x145260) segue bit9(OLD) ANCHE quando 0x4404 è saltato per bit7(OLD) (visibile nel caso return_pending); solo 0x4404 a OLD è gate su bit7(OLD) dopo bit9(OLD).
- **Abort 0x4404**: se la consegna 0x4404 alla vecchia finestra ritorna -1 → `cmp r0,-1` a 0x14525A → return 0 SENZA scrivere la corrente (caso negativo CPU abort_4404).
- **Coda post-successo** (0x1453A4..): flag[target] bit0xA(0x400)==0 → **post A 0x17BF60(target, 0x4409, 0x4409)** [pool 0x145798=0x4409]; bit0xA=1 ∧ bit0xC(0x1000)=1 → post B 0x17BE80; bit0xA=1 ∧ bit0xC=0 → **gate [master+0x24]**: 1 → 0x145150 (consegna diretta 0x4409 via 0x169D78), 0 → 0x145158 (post in coda via 0x169EB4, con ricorsione su [nodo+8] se bit0).
- **Ritorno**: 1 via 0x1453DC/0x14538C, 0 via 0x14539A/0x145208; epilogo condiviso `b.d 0x33418C` + delay `add sp,sp,8`; millicode 0x334120 catena di push (0x334128 = push r16,r15,r14,r13) e 0x33418C = pop r16,r15,r14,r13 + `ld.ab r13,[sp,r13]` + `ld.ab blink,[sp,r12]` — **eseguito ORIGINALE in tutti i casi** (nessun trampolino).

## 3. Ciclo di transizione e redirect

- **Wrapper 0x1453E4(idx, arg)** (solo chiamante bl del commutatore, a 0x1453EC): r3=arg; **r0 = 0x14507C(idx)** = tabella1[idx] (u32, stride 4, base [0x366E9C], count (s16)[0x366EA0]); poi 0x145180(finestra, arg).
- **Risolutore di catena 0x14510C(packed, nodo, &next, &nextarg)** (2 soli chiamanti: 0x1451FC, 0x14531C — entrambi nel commutatore):
  - packed == -1 (la consegna non redirige): nodo==0 → next=0, ret 0; altrimenti se flag[nodo] bit9==0 → **next=nodo, nextarg=0**, ret 0; se bit9==1 → next=0, ret 0.
  - packed != -1: **idx=(s16)packed** → 0x14507C(idx) → next=tabella1[idx]; nextarg = packed>>16; ret 0 se risolta, ret 1 se risolve a 0 ("procedi senza redirect").
  - Nel commutatore `packed` è il **RISULTATO della consegna 0x4403** (0x1451FC) o **0x4405** (0x14531C): i gestori degli eventi lifecycle possono REDIRIGERE la transizione verso un'altra finestra (indice/arg packed), e il commutatore riparte dal capo (loop 0x1451B4/0x145202) — caso CPU chain_redirect esegue la catena T1→(0x4405 redirige)→T2 con corrente riscritta tre volte (T1, P, T2).
- Ordine lifecycle osservato nei casi: 0x4403 (target, arg=corrente) → [redirect-loop] → 0x4414 (vecchia, arg=target) → pending:=corrente → 0x4404/0x4406/0x4402 (vecchia) → (pending, 0x4406/0x4402) se flag pending → **0x4401 (target, arg utente) → current:=target** → **0x4405 (target, arg=precedente)** → catena → 0x4406/0x4402 (target) → current:=catena → loop → … → post 0x4409.

## 4. Censimenti (listing globale Risultati/Disassemblati/Firmware1.1.asm)

Regex bl/bl.d/bl_s/bl_s.d; i BLcc condizionali sono esclusi (l'audit li ha verificati a zero occorrenze verso i nove target con decoder proprio).

| Target | Chiamanti bl | Note |
|---|---|---|
| 0x145180 commutatore | **1** (0x1453EC) | solo via wrapper |
| 0x1453E4 wrapper | **580** | distribuzione per payload in evidenza; è il collo di imbuto delle transizioni GUI |
| 0x14510C risolutore catena | **2** (0x1451FC, 0x14531C) | entrambi nel commutatore |
| 0x14507C resolve idx | 43 | |
| 0x14505C record resolver | 1 (0x16A040) | area servizio default 0x16A6E4 (it.46) |
| 0x145020 resolve tabella0 | 1 (0x14570) | |
| 0x145010/0x145018 setter tabelle | **0** (bl) | installate solo via chiamate indirette/jl (APERTO) |
| 0x145B08 switcher controllo attivo | 673 | §6 |

## 5. Casi CPU (8, byte originali, GNU ARC700 sim)

Dispatcher 0x169D78, insert coda 0x169EB4 e post API 0x17BF60/0x17BE80 sostituiti da stub registratori (valori di ritorno = fixture); contesto maestro a 0x366E94 con sentinelle; descrittori finestra sintetici in RAM (flag word a +0). Ogni caso fault 0xDEADB00k al successo, 0xDEADC000+i per controllo fallito; log (evento, nodo, arg, stub) a 0x367000.

| Caso | Config | Esito atteso e verificato |
|---|---|---|
| null_target | target=0 | ret 0, nessuna consegna, nessuna scrittura |
| invalid_target | flag[T1] bit0 | ret 0, busy non toccato, corrente intatta |
| busy_gate | [0x366EBB]=1 | ret 0, nessuna consegna, busy resta 1 |
| open_first | corrente=0, pending=0 | 0x4403/0x4401(arg)/0x4405 a T1, post A 0x4409; **current:=T1 (0x1452EE)**, pending:=T1 (0x14538A), busy azzerato |
| abort_4404 | 0x4404 → -1 | ret 0, **corrente MAI scritta**, busy azzerato, pending intatto |
| close_ok | flag[OLD] bit9 | 0x4403→T1, 0x4404/0x4406→OLD, 0x4401/0x4405→T1, post A; **current:=T1**, **pending:=OLD (0x14534C)** |
| return_pending | target==pending, bit9(T1), gate=1, bit0xA(T1) | 0x4406→OLD, **0x4415→pending**, **current:=pending (0x145306)**, 0x4409 diretto via 0x145150 (gate 1) |
| chain_redirect | 0x4405 di T1 redirige a T2 (packed idx) | 11 consegne: doppia iterazione, **current:=T1 (0x1452EE), :=P (0x145338), :=T2 (0x1452EE)**, pending:=T2 (0x14538A), post A |

Istruzioni eseguite per caso nei `cpu_cases` dell'evidenza; sentinelle intatte in tutti i casi (incluso [0x366EAC] controllo attivo: il commutatore NON lo tocca).

## 6. Trovata secondaria (statica): writer del controllo attivo [0x366EAC]

Funzione **0x145B08(nodo, arg, modo)** (673 chiamanti bl): legge [master+0x18] (pool 0x145BE4), consegna **0x4408** (pool 0x145BF0) al controllo attivo corrente e poi lo cambia con `0x145B9A st_s r13,[r0,0x18]`. È il commutatore del controllo attivo già osservato in it.39-40 (cella 0x366EAC letta da 0x1457D4, 79 chiamanti). Nessuna prova CPU qui: claim statico byte-verificato (byte `20 12 00 da 13 d0 a6 a0` a 0x145B94; pool 0x145BE4=0x366E94, 0x145BF0=0x4408).

## 7. Lezione di banco: branch 32-bit a displacement positivo grande

Micro-test (tmp/it18_bltest, 6 casi, byte originali): il sim GNU esegue CORRETTAMENTE `bl.d`/`b` 32-bit con displacement POSITIVO grande a entrambi gli allineamenti (0x1451F0→0x169D78 d=0x24B88; 0x14522A→0x169D78; 0x1453AC→0x17BF60; 0x14514C→0x334194 d=0x1EE048; 0x14510E→0x33412C; 0x145182→0x334128 d=0x1CA3B0). La divergenza it.44 vale SOLO per i displacement NEGATIVI grandi (wrap mod 8192). Conseguenza: questa volta NESSUN taglio/trampolino è servito; l'intero commutatore torna attraverso l'epilogo millicode originale. Seconda lezione: le finestre originali contigue in ELF lasciano GAP riempiti di zero tra sezioni: una `b` originale esclusa dalla finestra e caduta nel gap decodifica come branch su sé stesso (loop infinito, visto su 0x14514C prima di estendere la finestra a 0x145150).

## 8. Audit indipendente (agente `switcher-audit-18`, integrato)

Metodo proprio: ridisassembly ex-novo dei 16 payload (sha256 manifest riverificati), decoder bl/bl_s indipendente validato su 354.607 righe (0 discrepanze; bl_s = s11 a bit[10:0]×4, bl 32-bit SIMM25/SIMM21), scanner LE/taint proprio (raggio 40 istruzioni dai pool, solo basi da literal pcl), emulatore indipendente del commutatore ricostruito dal solo disassembly (con delay slot e loop-back, r14 NON ricaricato nel loop). Esiti:
- **C1 CONFERMATO** byte-esatto (3+3 store + busy set/clear; precisazione r15 a 0x145338 accolta e applicata sopra).
- **C2 NESSUN CONTROESEMPIO** nei limiti dichiarati: unici store che raggiungono 0x366EA4/0x366EA8 = i 3+3 siti del commutatore; gli altri writer del contesto maestro toccano solo +0/+4/+8/+C, 0x366EB4..0x366EBA e gate 0x366EB8; il riferimento extra di pool 0x145350 a 0x14542A (funzione 0x145424) scrive solo [0x366EB5].
- **C3 CONFRONTATO**: census identici su tre metodi (mio decoder, listing globale, valori congelati): 1/580/2/43/1/1/0/0/673; primi indirizzi identici; zero BLcc.
- **C4/C5/C6 CONFERMATI** byte-esatti (pool, semantica delay-slot 0x1452AA/0x1452CA, finestre .bin identiche in entrambe le directory di evidenza).
- **C7 CONFERMATO 8/8**: l'emulatore indipendente riproduce log, stati finali e ritorni di tutti i casi; conteggi istruzioni identici fra le due run (103/112/116/463/327/618/404/1093 — replay deterministico). Nota dell'audit: il SUO primo modello aveva tre polarità sbagliate (0x4403 anche con bit7(OLD)=0; 0x4406 a OLD senza gate bit7; OLD non ricaricato) — il verificatore le aveva tutte corrette.
- **C8 limiti** confermati (§ Limiti). Quattro precisazioni testuali applicate: (1) r15 a 0x145338 = OLD o pending; (2) 0x4406 a OLD segue bit9(OLD) anche con 0x4404 saltato; (3) LE scan 0x366EAC (pool {0x1457D0}) e 0x366EB8 (pool {0x1457A0}) aggiunti alle asserzioni congelate del verificatore; (4) esclusione BLcc dichiarata. L'audit ha registrato il proprio esito in PMB (outbox 380).

## 9. Comandi/esiti

```
python3 Python_Trace_Scripts/s33_verify_wm_current_switcher_cpu.py
  → PASS_WM_CURRENT_SWITCHER 20261101T152007762890Z
  → riesecuzione identica 152018293529Z (verified_evidence.json identici salvo utc)
  → post-audit (LE scan 0x366EAC/0x366EB8 aggiunti): PASS 153605977322Z
    + riesecuzione identica 153638728092Z
Regressioni (tutte PASS):
  s33_verify_capture_guard_setter_census.py       → 152032313705Z
  s33_verify_capture_flag_mode_matrix_cpu.py      → 152046174641Z (14 casi)
  s33_verify_snapshot_capture_record_init_cpu.py  → 152049234353Z (4 casi)
  s33_verify_service_raise_pending.py             → 152052Z
  s33_verify_wm_service_dispatch_cpu.py          → 152059567278Z (it.46)
  s33_verify_event_router_producers_cpu.py        → 152103470517Z (it.45)
Micro-test di banco: tmp/it18_bltest/run1..run4 (6 casi branch positivi grandi, tutti fault attesi)
```

Correzioni di banco durante lo sviluppo (documentate, asserzioni non indebolite): pool 0x145798 mancante → r1=0 nel post (aggiunta finestra .origp798); polarità del ramo post letta al contrario (bit0xA=0 → post A); beq 0x1452AA su flag del btst bit9 del pending (non su un cmp); delay slot dello stub che clobberava r0 prima del confronto nodo; controllo sp via r26/gp (r6 clobberato dagli stub); sesta sezione .stack mancante (sim map_attach size zero).

## Fonti precise

- Payload0 (base 0x0AD800): commutatore 0x145180..0x1453E4 (pool interni 0x145350..0x145378); helper 0x14503C..0x14505C, 0x14507C..0x145098, 0x14510C..0x145150; attivatori 0x145150..0x145180; pool post 0x145798=0x4409, 0x14579C=0x366EA4; wrapper 0x1453E4..0x1453F2; millicode 0x334120..0x33413C (push) e 0x33418C..0x3341E4 (pop); funzione B 0x145B08..0x145B9E con pool 0x145BDC/0x145BE4/0x145BE8/0x145BEC/0x145BF0.
- Evidenze: `Risultati/GUI_S33/wm_current_switcher_cpu_20261101T152007762890Z/` (8× .s/.ld/.elf/.bin + verified_evidence.json con census, pool, LE scan, distribuzione dei 580 chiamanti) e riesecuzione `..._152018293529Z/`.

## Limiti

- Statico + 8 casi CPU con fixture: stub per dispatcher/coda/post API (consegne e valori di ritorno imposti dal banco); nessun hardware, boot, rendering, scatto o persistenza; NON_INSTALLARE; circa 10% invariato.
- I descrittori finestra sono nodi RAM sintetici; il significato FISICO dei bit di flag (0/7/8/9/0xA/0xC) è inferito dai rami del commutatore, non da documenti Nikon.
- I gestori reali di 0x4403/0x4405 (che nel firmware decidono i redirect) NON sono eseguiti: la SEMANTICA dei valori di ritorno (packed=-1 vs indice) è provata nel commutatore/risolutore, non nei servizi 0x16A05C/0x16A188.
- Chi popola le tabelle finestre a runtime (0x145010/0x145018 non hanno chiamanti bl: chiamate indirette jl statisticamente invisibili) resta APERTO; la schedulazione dei 580 chiamanti del wrapper NON è provata.
- Il claim su 0x145B08/[0x366EAC] è solo statico (byte+pool+census), senza CPU: function boundary 0x145B08..0x145B9E da verificare in una sessione dedicata.
- V1.1 campione vs macchina V1.0.

## Prossimo passo (non ripetitivo)

(a) **Consumatore del registro notifiche p1 0x3E8BB8..0x3E8DC8** (punto aperto it.46(a), ancora intatto): cercare il percorritore della tabella {handler,evento} — candidati ora più precisi: gli installer 0x145010/0x145018 (setter di [0x366E94]/[0x366E9C] — le due tabelle RAM) e il record resolver 0x14505C chiamato solo da 0x16A040 (servizio default 0x16A6E4); un inizializzatore che copia il registro p1 in RAM collegherebbe il ciclo completo consegna→notifica. (b) In alternativa: CPU del commutatore del controllo attivo 0x145B08 (673 chiamanti, writer di [0x366EAC]) per chiudere il terzo campo del contesto maestro con lo stesso metodo. Il punto writer-corrente è CHIUSO: non rieseguire il verificatore né l'audit di questi claim.
