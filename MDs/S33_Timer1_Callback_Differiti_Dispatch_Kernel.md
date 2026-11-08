# TIMER1 e callback differiti: consumatore runtime della tabella slot 0x4437F4 e dispatch kernel — 22 ottobre 2026 (iterazione 29)

**Tappa:** R0/R3 (runtime/task). **Esito:** PUNTO (b) DELL'ITERAZIONE 23 CHIUSO STATICAMENTE (passaggio (a) del prossimo passo dell'iterazione 27). Verificatore `Python_Trace_Scripts/s33_verify_kernel_timer1_deferred.py` **PASS post-audit** (evidenza `Risultati/Runtime_Kernel/Timer1_Deferred/20261022T020135Z`, `latest.json`; le cartelle 0154xx–015530Z sono calibrazioni della stessa sessione). Circa 10% invariato, NON_INSTALLARE.

## Domanda

Chi consuma a runtime la tabella slot 0x4437F4 del servizio callback differiti `0x145F28` (punto aperto dell'iterazione 23: "consumatore runtime della tabella slot 0x4437F4/interrupt TIMER1", chi fa scadere gli slot e chiama gli handler, incluso `0x235AF8`/`0x235AE4` della famiglia iris).

## Risultato byte-exact (payload0, base 0x0AD800)

Il consumatore è il corpo tick **0x146104**, registrato come handler del **codice vettore kernel 7** e invocato dal dispatcher delle eccezioni/interrupt del kernel.

1. **Armaggiamento e registrazione (post `0x145F28`)**: quando il contatore servizio `[0x366EBC]+8` è 0, il post arma TIMER1 una sola volta: `sr 0x1000000,[limit1]` (0x145F64), `sr 0,[count1]` (0x145F6C), `sr 2,[control1]` (0x145F74), quindi **registra l'handler: `0x231428(7, 0x146104, 0)`** — handler letto dal pool 0x14623C (byte `04 61 14 00`), `mov r0,7` a 0x145F7E, `bl.d 0x231428` a 0x145F80 con delay `mov r2,0`. Poi `sr (0x1000000−scala),[count1]` (0x145F90) e `sr 3,[control1]` (0x145F94).
2. **Scala tick**: `[0x366EBC]+0xC` = `freq_getter()/divisore` con `freq_getter = 0x231420 → 0x12ca28(0)`: legge halfword MMIO **0x0FE800F8** (pool 0x12CA38, byte `f8 00 e8 0f`), bit7 seleziona 12/13, tail-call al lettore di tabella frequenze 0x17A000 (base tabella in payload1, pool 0x17A018). **Il divisore è selezionato dal byte modo `[0x366EBC]+9` (precisazione dell'audit)**: 0 → 10000 (pool 0x146238), 1 → 100000 (pool 0x146244), altro → 1000 (`mov r1,1000` a 0x145FFA). Il valore "/"10000" dell'iterazione 23 vale solo per il modo predefinito.
3. **`0x231428 = register_vector(code, handler, arg)`**: tabella entry a kernel **[0x369348]+0x238** (`ld.as [r1,142]`), stride 12 {handler+0, ?+4, arg+8}, bound contro kernel+0x22C (`ld.as [r1,139]`) e kernel+0x230 (`ld.as [r1,140]`), sezione critica 0x1786E8/0x179354, **ritorna l'handler precedente**. Census payload0 (forme bl/bl.d/bl_s/bl_s.d): **esattamente due chiamanti**: 0x145F80 (TIMER1/7) e 0x29F6A0 (servizio TIMER0, `mov r1,0x29f740`, codice r14). L'unica altra word LE 0x231428 in payload0 (0x16D510, tabella dati) non è referenziata da alcun pool → coincidenza.
4. **Dispatch kernel**: 16 stub di vettore 0x0B2F74..0x0B3052 assegnano `r1 = 0..0xF` (delay slot del `b.d 0xb3054`) e saltano all'entry comune 0x0B3054 (salvataggio contesto completo, IRQ-vs-trap via `aux_irq_lv12`/`status32_l1/l2`, **`mov_s r4,r1` a 0x0B30B8**). Il dispatch 0x0B3150..0x0B31A8 calcola `idx = causa − [kernel+0x22C]`, `entry = [kernel+0x238] + idx*12` (`ld [r3,-8]`/`ld [r3,4]`, `add1_s`+`add2` = ×3 word), poi **`jl_s.d [entry+0]` con `r0 = [entry+8]`** (l'argomento registrato). Il wiring hardware vettore↔intvec ARC700 resta aperto (inferenza comportamentale: il codice 7 è TIMER1 perché l'arm di limit1/count1/control1 circonda la registrazione).
5. **Tick body `0x146104`** (sezione critica 0x14610A→0x1461D8):
   - se `[0x366EBC]+8 ≤ 0` → `sr 2,[control1]` (0x1461D0) e ritorno: tabella vuota = interrupt disabilitato;
   - re-arm: `count1 = count1 + 0x1000000 − scala` (clamp `mov.nc` a 0xFFFFFB, pool 0x146250), `sr 3,[control1]` (0x146134) **prima** di `sr count1` (0x14613C);
   - **loop 1** (lp_count 10, stride 20, base immediata `mov_s r12,0x4437f4` a 0x146148 — byte `cf 74 44 00 f4 37`): per ogni slot attivo (flags≠0): se `scala < [slot+0xC]` → `[slot+0xC] −= scala`; alla scadenza `flags |= 0x10` (bit4 = callback pendente); **periodici (bit7)** ricaricano `[slot+0xC] = [slot+8]`; **one-shot** aggiungono bit3, decrementano il contatore servizio e se arriva a 0 disabilitano TIMER1 (`sr 2,[control1]` a 0x146184);
   - **loop 2** (0x14619A..0x1461CC, ordine indice 0..9): bit4 → handler **`[slot+0x10]` chiamato con `jl_s [r0]`** (0x1461C0/0x1461C2), bit4 pulito (`and 239`); bit3 → flags azzerati (slot liberato). **Gli handler differiti girano DENTRO la sezione critica** (unica exit 0x179354 a 0x1461D8, dopo entrambi i loop): inclusi gli handler iris 0x235AF8/0x235AE4.
6. **Layout slot REFINED (corregge l'iterazione 23)**: `+0` flags {bit0 attivo, bit3 rilascio one-shot, bit4 scadenza, bit7 periodico}, `+4` seriale, **`+8` valore di ricarica/iniziale** (non "scadenza" generica: il post scrive lo stesso valore a +8 e +0xC a 0x146006/0x146008; i periodici ricaricano da +8), `+0xC` conto alla rovescia vivo, `+0x10` handler.
7. **Census TIMER1 in payload0** (lr+sr, listato lineare): control1 = {0x145F74, 0x145F94, 0x1460A0, 0x146134, 0x146184, 0x1461D0, 0x1F0BA0, 0x29F6DC}; count1 = {0x145F6C, 0x145F90, 0x146126, 0x14613C, 0x1F0BAC, 0x1F0BD2}; limit1 = {0x145F64}. Fuori dal cluster post solo: **0x1F0B74** (init timer kernel: legge control1, può riprogrammare count1 una volta al boot, arma TIMER0 come tick dello scheduler) e il blocco **0x29F6BC..0x29F6F6** (init servizio TIMER0: scrive control0; disabilita TIMER1 con `sr 0,[control1]` a **0x29F6DC** — precisazione audit: a 0x29F6C4 si scrive control0, NON control1).
8. **Cancel `0x14605C`** (confermato): trova lo slot per seriale, azzera flags, `count−−`, e a 0 → `sr 2,[control1]` a 0x1460A0.

Il punto (b) dell'iterazione 23 è chiuso: **la risposta è "TIMER1 interrupt → dispatcher eccezioni kernel (vettore 7) → tick 0x146104 → jl_s [slot+0x10]"**. Un servizio gemello identico esiste su TIMER0 (handler 0x29F740, codice r14 dal census 0x29F6A0), con propria init che disabilita TIMER1.

## TBIB

Il TBIB (payload di boot) ha un dispatcher/register_vector gemello a 0x1013D64/0x1013E30 su kernel [0x104126C] (stessi offset ld.as 142/139/140, stride 12) — kernel separato della fase di boot, non ricontrollato in questa iterazione.

## Revisione indipendente

Agente `timer1-slot-audit-29` (spawn riuscito, task/agenti disponibili): **claim 1–7 CONFERMATI** con due precisazioni accolte (divisore scala dipendente dal byte modo [0x366EBC]+9; a 0x29F6C4 si scrive control0, la disabilitazione TIMER1 è a 0x29F6DC). Precisazioni minori annotate: stub vettore con passo 14 byte; 0x17A000 è il lettore della tabella frequenze (base in payload1), non la tabella. Verificatore aggiornato e rieseguito PASS.

## Comandi ed esiti

- `python3 Python_Trace_Scripts/s33_verify_kernel_timer1_deferred.py` → **PASS** (20261022T020135Z post-audit; 20261022T015530Z pre-audit). 16 finestre GNU ARC700 allineate + 8 pool raw LE + byte immediata `mov_s r12,0x4437f4` + census (control1/count1/limit1/chiamanti 0x231428/pool 0x146104) + modello funzionale del tick (casi A–E: scadenze multiple, periodico, tabella vuota, decremento solo a scadenza, uguaglianza scala==remaining → scadenza).

## Limiti

- Statico, solo payload0; nessuna esecuzione, nessun hardware. Il modello funzionale non prova la semantica della CPU né il timing reale.
- **"Vettore 7 = TIMER1" è inferenza comportamentale** (arm di limit1/count1/control1 attorno alla registrazione e uso degli stessi registri nel corpo); il wiring intvec ARC700 non è provato.
- Valore runtime della scala dipende da MMIO 0x0FE800F8 e dalla tabella frequenze payload1: quanto vale un tick in secondi NON è derivato.
- Chiamate calcolate a 0x231428 (jl [reg]) non escludibili staticamente; il census esclude solo i bl.
- TBIB twin dispatcher non riverificato sui byte in questa iterazione.
- Aggiornare l'iterazione 23: "scadenza a slot+8" era impreciso (è il valore di ricarica; il conto vivo è a +0xC).

## Prossimo passo non ripetitivo

Resta aperto il punto (b) dell'iterazione 27: **chi scrive a runtime la coppia di stato 64-bit** da cui nascono i bit 16/21/15 delle richieste iris (chiamanti del consumatore 0x16F86C: 0x16E3FA, 0x16EC74, 0x16F90A — in particolare 0x16F8EC scrive la coppia complementare "forzando tutti"). Alternativa offline utile: il gemello TIMER0 (handler 0x29F740, servizio con propri slot/contatori) per mappare il tick dello scheduler Nikon — rilevante per il futuro task cooperante R3.
