# AutoSceneLiveView: handler di chiusura 0x4405 (0x65959C) — decodifica e prove CPU

**Iterazione 30 (Vibe offline), 1° novembre 2026.** Firmware Nikon COOLPIX
S33 V1.1, GNU ARC700 little endian, studio offline. `NON_INSTALLARE`,
nessun hardware/USB/SD; progresso funzionale invariato (~10%).

## Domanda

Punto aperto it.28: decodificare e provare in CPU l'handler **0x4405
(0x65959C, chiusura)** della finestra AutoSceneLiveView — il writer più
ricco dello stato finestra `[ctx+4]` (valori 0 e 2) e consumatore naturale
del contesto predisposto dall'apertura 0x659554 (it.28) — per chiudere il
ciclo **apertura → stato → chiusura** della finestra.

## Verificatore ed evidenze

- Verificatore nuovo: `Python_Trace_Scripts/s33_verify_aslv_close_handler_cpu.py`
- Evidenze: `Risultati/GUI_S33/aslv_close_handler_cpu_20261101T182145395518Z/`
  e riesecuzione identica `..._20261101T182349872845Z/`
  (`verified_evidence.json` byte-identici salvo `utc`).
- **PASS_ASLV_CLOSE_HANDLER_4405**: 13/13 casi CPU su byte ORIGINALI
  (fault marker `0xDEADB001..0xDEADB00D`), statica (registro p3, 28 pool,
  LE scan, census bl su tutti i blocchi, 12 opcode freeze, inventario
  finestre con SHA-256) + riesecuzione deterministica.

## Struttura decodificata (byte originali, finestra 0x65959C..0x659EF0)

Ingresso `0x65959C(r0=node, r1=arg, r2=arg2)`; `push_s blink`,
millicode `bl 0x33411C` (push r19..r13 per fall-through fino a
`j_s [blink]` a 0x334138), frame `fp`; `r13=node, r16=r1, r18=r2`.
Ritorno: `r0=0` via **epilogo condiviso 0x65953C** (dentro il wrapper:
`mov sp,fp; ld.ab fp,[sp,4]; b 0x334174`).

1. **Preambolo**: `0xD2554(node)` (==1 → `0xD2544`+`0xD3E6C(1)`);
   `0x26C4E8`; gate `0x14504C(node,0x12)==0x55` → `[0x442734]:=0`
   (= 0x442644+0xF0) **e** `[[0x3669EC]+0xF0]:=0` (doppia indirezione);
   `0xCE6F4(1); 0xD10A8(0); 0x143AFC(0)`.
2. **Timer 64-bit**: celle `[0x682020]/[0x682024]` (pool 0x659924) =
   **ctx+0xC4/ctx+0xC8** (NON +0x64: correzione di lettura). Entrambe
   zero → skip. Altrimenti `now = 0x145D1C(0)`; `elapsed = now − t0`
   (64 bit, sub+sbc); `elapsed ≥ 0x16E360` (1.500.000) → salto diretto;
   else `0x145C3C(0x16E360 − elapsed)`. **In entrambi i rami poi
   `0x143AFC(0xC)`** (0x659634 è il fall-through di 0x659630, non
   un'alternativa).
3. **Teardown** (0x65963A..0x659672): `0x1439D4(1); 0x131790(ret)`;
   poi `[ctx+4]:=0` (**word**, `st_s` a 0x65964A — writer n. 1),
   `[ctx+0x39]:=0`, `[ctx+0x2C]:=0`, `[ctx+0x1C]:=0`, `[ctx+0x26]:=0`,
   `[ctx+0x1D]:=0`, `[ctx+0x1E]:=1`, `[ctx+0x1F]:=0`, `[ctx+0x23]:=0`,
   `[ctx+0x28]:=0` con **`stw_s` (halfword 16 bit**, non word);
   `[ctx+8]`/`[ctx+9]`/`[ctx+0x18]` NON toccati; `0x15AD44()!=0` →
   `[ctx+0x38]:=0`.
4. **Chiusura risorsa CaptureMenu**: `0x145B08(node, 0x4800, 0)`
   (`mov r1,9; asl_s r1,r1,0xb` = 9<<11 = **0x4800**, l'ID risorsa
   CaptureMenu di it.39/23, non 0x1200); `0x8101FC(0)`;
   `0x145654(node,0x480C)` via `bl.d` delay slot; `0xD148C(ret,0,0)`.
5. **Modo/guardia** (getter ORIGINALI `0xCAD30` → byte 0xC8E80C via
   ld.as pool 0xCAAC4; `0xCA310` → 0x365751):
   - modo==0x2C ∧ guard==7 → catena A: `0xCE1EC(0), 0x1316F8(2),
     0x191B58(0), 0x1421AC(0), 0x130E5C(0), 0x192708(0)`;
   - modo==0x2C ∧ guard≠7 → catena B: `0xCC410(0x11), 0xCE1EC,
     0xCC410(0x13), 0x131740, 0x1316F8, 0xD1154, 0x1421AC, 0x1421C8`
     (loop `cmp r0,0`), coda `0x191B58(0), 0x130E5C(0), 0x192708(0)`;
   - poi (modo==0x2C → `0xD0924()` gate su blocco lungo con
     `0x15A5C8/0x201830/0xD08C8/0xCFDEC` e query coda `0x3101`) e il
     blocco comune `0x2019C0(0), 0xCC410(9), 0x126F8C, 0x126F80,
     0xCF0C4(x,1), 0xCFE18, 0x1435FC(x)`.
6. **Blocco comune**: `0xCFDD0(0); 0x12845C()` (==1 → `0x12EF48` →
   purge `0x17BF60(0,0x80,0x307F)` se `[ctx+0x18]≠0x100`);
   `0xCEB0C(1)`; **`0xCAD38(1)`** (setter CaptureMenu-state: scrive
   `[0x365753]:=1`, claim statico it.23 — qui chiamata provata, setter
   stubbato); `0xDE1F4(0xC8)`; **celle notifica**:
   `0xCF554()` n. 1 ==1 → `[0x366AF1]==1` → post `0x169EB4(node,0x80,0)`
   + `0x169EB4(node,0x100,0)`; else `[0x366AF0]==1` → post
   `(node,0x80,0)` e, se `cfg[1]==0` (lettore ORIGINALE 0x16F920),
   anche `(node,0x81,0)`; poi **entrambe le celle :=0**.
   `0xCF554()` n. 2 è chiamata **SEMPRE** (`bne_s` a 0x659846 →
   **0x659890**, non 0x6598C4; n. 2 ≠1 → salto diretto a 0x6598C4
   senza query). n. 2 ==1 → `0xCE6A0()`; **se `CE6A0()==0`** →
   query `0x17BE18(0,0x80,0x80)` e `0x17BE18(0,0x100,0x100)`; una
   delle due ≠0 → `0x12CAD4(0x00B80035)` (pool 0x659958).
7. **Tre destini di `[ctx+0x18]`** (0x6598C4, word salvata
   dall'apertura):
   - **==0x100 → COMPLETAMENTO**: `0x14504C(node,0x12)` (≠6 →
     `0xCAFBC`+`0xCaff8(3)`); `[ctx+0x24]:=1`; post `(node,0x80,0)` +
     `(node,0x100,0)`; `0x65CFA0`; `0x14503C(node,0)` → `bclr` bit 0xA →
     `0x1450C8(node,0,flags)`; ritorno 0, **stato resta 0**.
   - **==0x101 → RIAPERTURA DIFFERITA**: `[ctx+0x18]:=0x100`;
     `0xCAFBC(ctx); 0xCaff8(3); 0x65CFA0; 0x65AC58(node,r1,r2)`
     (ri-dispatch con gli argomenti ORIGINALI); rilegge
     `[ctx+0x18]`: ==0 → ritorno 0; query coda
     `0x17BE18(0,0x100,0x100)` ≠0 → ritorno 0 (stato 0);
     `cfg[2]≠0` oppure `cfg[1]≠0` (lettori ORIGINALI 0x16F920) →
     ritorno 0; altrimenti `[ctx+0x18]:=0; 0x661780(0)`;
     **`[ctx+4]:=2`** (`st_s` a 0x6599C2 — writer n. 2);
     `0x65B060(node)`; purge `0x17BF60(0,0x80,0x307F)`; ritorno 0.
   - **altro valore → PERCORSO PUNTATORE**: `0x660C34(valore)`;
     `[ret+0xF0]>0` → seconda `0x660C34` con **r0 = il byte letto** e
     `0xAD90C(r0=ritorno della seconda 660C34, r1=0x110)`; catena modi
     {0x6F,0x70,0x6E,0x7A,0x7B,0x7C}→`0x15A5C8`; modo 0x15 → query
     coda 0x100/0x80 e blocco D0CA4; `0x14504C` triplo + zoom
     `0x14A884/0x14A1F8 (vs 100)/0x14941C/0x14949C(0x65E430)/
     0x65E430`; `0x158D04(0x02600001,8,0,2000)`; attesa/timer
     `0x14905C(node,8,100,…)` e `0x14905C(node,0xB,0xFA,…)`;
     `CB634()≠4` (beq a 0x659E2E) → `0x177484(0)` → `0x149DF4(0)` +
     `0x1314B8(0)`; coda `0x14503C/0x1450C8/0x145150`; gate
     `0x12845C/0xD1A00/0x15AD44/0x175394`; **`0x809DF4(1,1)`**; ritorno 0.
     Nessuna scrittura di `[ctx+0x18]`/`[ctx+0x24]`/celle notifica
     su questo percorso (con fixture usate).

## Casi CPU (finestre ORIGINALI: `.mili` 0x334100..0x3341E4, `.guard`
0xCA2F4..0xCA31A (solo getter eseguito), `.modeget` 0xCAD30..0xCAD38 +
`.modepool` 0xCAAC4 (word 0xC8E80C), `.cfgread` 0x16F920 + pool
0x16FA34, `.wrap` 0x6593A0..0x659554 (epilogo), `.h4405`
0x65959C..0x659EF0)

| # | caso | verifica chiave |
|---|------|-----------------|
| 1 | close_m2c_g7_arg100 | catena A, completamento, stato 0, `[ctx+0x24]:=1` |
| 2 | close_m2c_gN_arg100 | catena B (guard 3), `0x15AD44` ret 1 → `[ctx+0x38]:=0` |
| 3 | close_entry55 | `0x14504C` ret 0x55 → `[0x442734]:=0` e `[[0x3669EC]+0xF0]:=0` |
| 4 | close_timer_rem | `0x145C3C(1499000)` POI `0x143AFC(0xC)` |
| 5 | close_timer_exp | elapsed ≥ soglia → solo `0x143AFC(0xC)` |
| 6 | close_arg101_deferred | **`[ctx+4]:=2`**, `[ctx+0x18]:=0`, purge |
| 7 | close_arg101_qblocked | query coda ret 1 → NESSUN writer n. 2 |
| 8 | close_arg101_cfg1 | cfg[1]=1 fixture (lettore ORIGINALE) → bloccato |
| 9 | close_arg101_cfg2 | cfg[2]=1 fixture → bloccato |
| 10 | close_notify_f1 | celle notifica → post 0x80+0x100, entrambe azzerate |
| 11 | close_notify_f0 | post 0x80 e cfg[1]==0 → 0x81; celle azzerate |
| 12 | close_notify_q80 | query ret 1 → `0x12CAD4(0x00B80035)` |
| 13 | close_ptr | percorso puntatore completo fino a `0x809DF4(1,1)`, 84 chiamate |

Log di chiamate atteso per intero (sid, r0, r1, r2 per ogni stub) +
sentinella «nessuna chiamata extra» + return 0 + assert di memoria per
ogni caso.

## Fonti, indirizzi e pool

Registro p3 0x783B08 (record 0x4405 → 0x65959C, campo handler
0x783B14 — unica LE dell'indirizzo in tutti i payload; census bl = 0
chiamanti, callback puro). Pool (tutti verificati nel dump):
0x65991C=0x442644, 0x659920=0x3669EC, 0x659924=0x682020,
0x659928=0x16E360, 0x65992C=0x681F5C, 0x659930=0x681F94,
0x659934=0x681F78, 0x659938=0x480C, 0x65993C=0xCAD30,
0x659940=0x142834, 0x659944=0x192CB4, 0x659948=0x3101,
0x65994C=0x307F, 0x659950=0x366AF1, 0x659954=0x366AF0,
0x659958=0x00B80035, 0x659CCC=0x681F5C, 0x659CD0=0x307F,
0x659CD4=0x47BBB8, 0x659CD8=0x47BBB4, 0x659CDC=0x00B0000D,
0x659CE0=0x47BB3C, 0x659CE4=0x02600001, 0x659CE8=0x4111,
0x659EE4=0x442644, 0x659EE8=0x3669EC, 0x659EEC=0x65E430,
0xCAAC4=0xC8E80C, 0x16FA34=0x446808, 0xCA30C=0x365751.
LE scan: 0x65959C esatta (solo p3); 0x366AF1 e 0x00B80035 esatte;
0x366AF0/0x682020/0x3669EC/0x442644/0x16E360 = subset (i pool
dell'handler sono tra gli hit; celle condivise da altri pool nel
firmware, liste complete in `verified_evidence.json`).

## Comandi eseguiti

```
python3 Python_Trace_Scripts/s33_verify_aslv_close_handler_cpu.py
  → PASS_ASLV_CLOSE_HANDLER_4405 20261101T182145395518Z
python3 Python_Trace_Scripts/s33_verify_aslv_close_handler_cpu.py   (riesecuzione)
  → PASS_ASLV_CLOSE_HANDLER_4405 20261101T182349872845Z (identica)
```

## Fixture e assunzioni

Contesto 0x681F5C fixture 0xD0 byte (sentinelle 0xA5): `[ctx+4]` word
stato pre-chiusura 6, `[ctx+8]=0xFF`/`[ctx+9]=0x5A` (avanzi
dell'apertura), `[ctx+0x18]` per caso, timer a `[ctx+0xC4/0xC8]`,
byte alti di `[ctx+0x28]` a 0 (scrittura halfword). Guardia 0x365751,
modo 0xC8E80C, tabella cfg 0x446808 (byte 4·id), celle 0x366AF0/0x366AF1,
puntatore gate 0x3669EC→0x368000 (target 0x3680F0), celle gate
0x442734/0x3680F0, `0x365753` sentinella. ~91 stub (corpi da 10 byte:
`push_s blink; mov_s r12,sid; mov r3,0x600; jl_s [r3]`, common logger
a 0x600 che registra `{sid,r0,r1,r2}` e ritorna `pop_s blink; j_s
[blink]`; due coppie di stub a 4 byte di distanza con sezione condivisa
`mov_s+b_s` + coda). Getter modo/guardia/cfg ORIGINALI eseguiti.
Ritorni degli stub imposti per caso (rettab). Assunzione: significato
runtime degli stati {0,2}, cfg[1]/[2], valori 0x100/0x101 di
`[ctx+0x18]` NON identificato funzionalmente.

## Controlli negativi

- Query coda / cfg[1] / cfg[2] bloccano il writer n. 2 (casi 7-9):
  stato resta 0, `[ctx+0x18]` resta 0x100, NESSUNA chiamata a
  0x661780/0x65B060/0x17BF60 dopo il gate.
- Gate 0x55: le due celle vengono azzerate SOLO con ritorno 0x55
  (casi 1/2 con ritorno 0: sentinelle intatte).
- `[ctx+8]/[ctx+9]/[ctx+0x38]/0x365753` intatti nei casi senza gate
  (prova che il teardown non tocca le celle dell'apertura e che il
  setter CaptureMenu-state è stubbato).
- Timer: celle a zero → NESSUNA chiamata timer (casi 1-3, 6-13);
  elapsed < soglia → 0x145C3C con il residuo ESATTO.
- Assert «nessuna chiamata oltre il conteggio atteso» in ogni caso.

## Lezioni di banco (nuove)

1. **`stw_s` è una store HALFWORD (16 bit)**: fixture word su celle
   scritte con `stw_s` → assert a 32 bit ingannevoli (accaduto su
   `[ctx+0x28]`).
2. Il common logger NON deve scrivere «mirror» in celle fisse vicino
   all'area log: lo slot di una voce è `LOG+16·k+4` e collide con
   mirror/retcell mal posizionati (accaduto con k=33 e k=34).
3. `bl.d` con delay slot `ld r0,pool`: lo stub riceve il valore del
   pool come **r0** (a0), non come argomento successivo (accaduto su
   0x14949C/0x65E430 e 0x145654/0x480C).
4. I rami `bne_s`/`beq_s` a 16 bit usano base `(pc & ~3) + (s9 << 1)`
   (SLEIGH ARCompact.sinc righe 347-348): GNU objdump concorda su
   tutti i 105 rami compatti della finestra; la formula è utile per
   rileggere i target senza ambiguità.
5. Le celle timer della finestra sono a `ctx+0xC4/+0xC8` (0x682020 =
   0x681F5C+0xC4): differenza aritmetica da controllare a macchina,
   non a occhio (errore +0x60 sfuggito a più letture).

## Limiti e non dimostrato

- Statica + 13 casi CPU con fixture: nessun hardware, boot, rendering,
  scatto, persistenza; NON_INSTALLARE; ~10% invariato.
- ~91 callee sono STUB (inclusi 0x14504C, 0x169EB4, 0x17BE18, 0x17BF60,
  0x14905C, 0x158D04, 0x65AC58, 0x65B060, 0x809DF4): il loro
  comportamento reale non è provato qui; 0xCAD38 scrive 0x365753 solo
  come claim statico it.23.
- Writer di celle ctx oltre ai due di `[ctx+4]` (revisione
  close-review-30, statici, NON eseguiti nei casi): `[ctx+0x2B]:=1`
  a 0x659BFA (blocco modo 0x15, base ctx+0x1C via ld.as pool
  0x659934, offset 0xF); `[ctx+0x30]:=[ctx+0x34]:=0` a
  0x659D2A/0x659D2C (percorso puntatore dopo `CD5AC()==1`);
  **secondo writer delle celle gate** a 0x659D54..0x659D5E
  (pool 0x659EE4/0x659EE8: `[0x442734]:=0` e
  `[[0x3669EC]+0xF0]:=0` di nuovo, nello stesso percorso) —
  «!=0x55 nessuna scrittura» vale solo per il gate d'ingresso.
- Produttori RUNTIME di `[ctx+0x18]` (chi lo porta a 0x100/0x101/puntatore:
  candidati il risultato packed delle consegne WindowManager e
  0x65AC58), di cfg[1]/[2], delle celle 0x366AF0/0x366AF1/0x442734/
  0x3669EC e del timer [0x682020]: APERTI.
- Significato funzionale di stato 2, dei valori 0x100/0x101 e del
  percorso puntatore: strutturale, non identificato. Il percorso
  puntatore con mode 0x2C/0x7E/0x15 e i blocchi lunghi (0x15A5C8,
  D0CA4, 0x65BA94, celle [ctx+0x30/0x34], 0x12CAD4) NON eseguiti nei
  casi (target stub rimossi: raggiungerli esegue garbage e fallisce il
  probe — documentato nel verificatore).
- Concorrenza, schedulazione, ordine runtime degli eventi 0x4405
  rispetto a 0x4401/0x4406 NON provati. V1.1 vs V1.0 non confrontato.

## Collegamenti con le iterazioni precedenti

- it.28 (apertura 0x659554): `[ctx+0x18]` viene scritto dall'apertura
  con r2; questo handler lo legge come discriminante di chiusura →
  il ciclo apertura→chiusura è ora chiuso su entrambe le estremità.
- it.25 (handler slot): la pressione 0x700 apre CaptureMenu arg 4;
  qui la chiusura di AutoSceneLiveView chiama `0x145B08(node,0x4800,0)`
  (risorsa CaptureMenu) e `0xCAD38(1)` (stato CaptureMenu) → ponte
  contestuali verso la famiglia 0x4800/0x4801.
- it.23 (reattori p1): `[0x365753]:=1` è la condizione che il reattore
  0x20EAF4 (evento 0x700) legge per aprire CaptureMenu con ARG 0 →
  la chiusura PRIMA lo stato, poi la prossima pressione lo consuma.
- Writer di `[ctx+4]`: it.28 ne censì 13 statici in 9 funzioni; qui i
  due più ricci (0 e 2) sono eseguiti e oracolizzati.

## Agente e MCP

**Agente `close-review-30`** (tools.agents.spawn, atteso e integrato):
revisione statica ex-novo con objdump 2.45 proprio, carve allineati
0x65959C/0x65995C (il pool 0x65991C..0x65995B desincronizza il flusso
lineare), EA ld.as ricalcolata (PC&~3)+4·imm validata sul getter
0xCAD30→0xCAAC4, census bl/b con formula (A&~3)+disp validata 4/4.
Esito: **C1..C10 CONFERMATI**; correzioni integrate nel rapporto:
(a) secondo writer delle celle gate a 0x659D54..0x659D5E (percorso
puntatore, pool 0x659EE4/0x659EE8); (b) writer `[ctx+0x2B]:=1` a
0x659BFA (blocco modo 0x15) e `[ctx+0x30]/[ctx+0x34]` a 0x659D2A/C —
omessi dalla mia mappa statica; (c) precisazione C7: le query avvengono
solo con CF554#2==1 ∧ `CE6A0()==0` (≠1 → salto diretto senza query);
(d) argomenti della seconda 0x660C34 (r0 = byte letto da
[ret+0xF0]) e di 0xAD90C (r0 = ritorno della seconda 660C34, r1=0x110);
(e) record p3: id 0x4405 a 0x783B10, handler 0x65959C a 0x783B14
(0x783B08 è l'inizio tabella, record 0x4401). CONTROESEMPI (a) e (c)
richiesti: NESSUNO — gli unici writer statici di `[ctx+4]` nella
finestra sono 0x65964A e 0x6599C2; nessuna via di ritorno senza
teardown. Census LE propri: 0x659890→0 hit, 0x6599C2→0 hit,
0x682020→2 hit (pool 0x659924 + 0xB1D084 nel blocco 6, coerente con
il mio subset). Appunti in /tmp/rev30 (sessione); PMB outbox 392.

Server MCP: `mcp_pmb_nikon` (prepare iniziale + record_batch finale,
outbox 391). REA non presente tra i connettori. Strumenti: bash/python3,
objdump GNU ARC700, Runner sim (SHA firmware verificato dal Runner),
tools.agents. Nessun hardware/USB/SD; nessun file del repository
modificato dall'agente (lavoro in /tmp/rev30).

## Prossimo passo (non ripetitivo)

(a) **Produttore di `[ctx+0x18]`=0x101/0x100**: chi scrive la cella oltre
all'apertura (candidati: il risultato packed 0x4405 del WindowManager
it.18 — `(idx,arg16)` — che potrebbe transitare via 0x65AC58; e
0x661780/0x65B060 lato ricezione). È il pezzo che rende la scelta
completamento/differita prevedibile per la coda AkeruOS.
(b) Alternativa: eseguire in CPU il blocco lungo modo 0x2C
(0xD0924-gate) con i suoi 0x15A5C8/0x201830/CFDEC e la query 0x3101,
che collega la chiusura al percorso CaptureMenu arg 4 di it.25.
(c) Alternativa: writer 0x65B212/0x65B2EA (handler 0x100, stati 2/6
legati a [0x47BBC8]) per completare la mappa degli stati finestra.
