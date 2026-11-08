# AutoSceneLiveView — Writer append 0x4110/0x4111 provati in CPU (iterazione 41)

Data: 1° novembre 2026. Verificatore: `Python_Trace_Scripts/s33_verify_aslv_append_writers_cpu.py`.
Esito: **PASS_ASLV_APPEND_WRITERS_CPU 20261101T202252150931Z**, riesecuzione
byte-identica **20261101T202318161207Z**, 14/14 casi CPU su byte originali,
regressioni 4/4 PASS. Chiude il punto it.39(a) del rapporto
[S33_GUI_AutoSceneLiveView_Ring_Writer_65C720_CPU_20261101.md](S33_GUI_AutoSceneLiveView_Ring_Writer_65C720_CPU_20261101.md).
NON_INSTALLARE; circa 10% invariato.

## Domanda

I due writer residui del sottosistema gate, decodificati solo staticamente in
it.37, eseguono davvero l'APPEND di 9/0xA al ring `[0x47BBB8+4*gate]` SENZA
resettare il gate `[0x47BBC8]`, con guardia `word[0x47BBB4+4*gate] != 0xA`?
Possono far crescere il gate oltre 1 tra un 0x65C720 e l'altro, come ipotizzato
in it.39? E cosa fanno esattamente i loro tail?

## Identificazione dei writer (nuovo, prima non documentato)

Il registro p3 della finestra AutoSceneLiveView (block 03, base 0x669800,
coppie `(evento, handler)`) associa:

| Indirizzo | Evento | Handler |
|---|---|---|
| 0x783C10/14 | 0x4110 | **0x65CC40** |
| 0x783C18/1C | 0x4111 | **0x65CCC8** |
| 0x783C40/44 | 0 (terminatore) | 0x20E814 |
| 0x783B58/5C, 0x783B68/6C | 0x380, 0x400 | 0x65B3A8 |

Census LE su tutti i 16 blocchi: 0x65CC40 compare SOLO a 0x783C14 (allineata),
0x65CCC8 SOLO a 0x783C1C. Census bl (objdump GNU ARC700 su tutti i blocchi):
**0x65CC40 nessun chiamante**; **0x65CCC8 un solo chiamante diretto: bl a
0x65B53A**, dentro la funzione 0x65B3A8 = handler degli eventi 0x380/0x400.
Questa funzione, poco prima della chiamata (0x65B512..0x65B526), legge il gate
`[ring+0x10]`, legge `word[0x47BBB4+4*gate]` e lo **DECREMENTA** se vale 0xA:
è il primo consumatore/decrementatore del gate trovato nel firmware (punto
aperto per la prossima iterazione).

## Decodifica (byte originali, block 2, finestra 0x65CC18..0x65CD54)

Pool: 0x65CC20=0x3181, 0x65CC24=0x47BBB8 (ring), 0x65CC28=0x47BBB4 (tabella
guardia), 0x65CC2C=0x681F5C (ctx), 0x65CC30=0x3669EC, 0x65CC34=0x442644,
0x65CC38=0x1388, 0x65CC3C=0x307F.

Prologo comune: `push_s blink; bl 0x33412C` (millicode push r15,r14,r13),
`st.aw fp,[sp,-4]; mov fp,sp`. Registri: r13/r14=node/ev, r14/r13=ev/node,
r15=arg (0x4110 salva node in r13; 0x4111 in r14).

Gate d'ingresso: `r0=0x135A84(node,ev,arg); btst r0,1`; bit1 → skip. Se
bit1=0: `r0=6; bl 0x65BE24; r0=0; bl 0xDECD4; bl 0xDD094; r0=1; bl 0x149DF4`.

Corpo append (identico nei due handler, valore 9 in r2 per 0x4110, 0xA in r3
per 0x4111):

```
r1 = 0x47BBB8;  r0/r2 = ldb [ring+0x10]  (gate 0x47BBC8)
gate==0 -> beq enqueue incondizionato a slot 0
gate>0  -> ble successivo MORTO (byte zero-esteso, lezione it.37)
          r3 = word[0x47BBB4 + 4*gate] (add2 scala x4)
          == 0xA -> NESSUN append (guardia)
enqueue: st 9/0xA,[ring+4*gate]; gate := gate+1
```

Tail 0x4110 (0x65CC96..0x65CCC6): `bl 0x65DAD0; bl 0x145150(node); r0=9;
bl 0x177030; r0=0; bl 0x145D1C`; quindi con ctx=0x681F5C:
`[ctx+0x10] := ret(0x145D1C); [ctx+0x14] := 0x47BBB8; [ctx+0xD] := 1`;
infine `r0=0; r1=0x4110; r2=arg; bl 0x20E814(0, 0x4110, arg)` e `b 0x659588`.

Tail 0x4111 (0x65CD1E..0x65CD50): `bl 0x65DAD0; bl 0x145150(node); r0=0;
bl 0x145D1C` (NESSUN 0x177030); ctx identico; poi
`bl 0x20E814(node, 0x4111, arg)` con **r0=NODE**; poi SEMPRE `bl 0x14941C` e,
se ritorna 0, `bl 0x177460`; `b 0x659588` a 0x65CD50 (allineata).

Differenze chiave dimostrate in CPU:

- 0x4110 accoda **9**, 0x4111 accoda **0xA**; la guardia confronta **0xA in
  entrambi** (quindi 9 ripetibili consecutivamente, 0xA mai due volte: casi
  `w4110_append_gate2`, `dbl_4111_twice`, `dbl_9_then_A`).
- `0x177030(9)` è chiamato SOLO da 0x4110; `0x14941C/0x177460` SOLO da 0x4111.
- `0x20E814` riceve **r0=0** dal tail di 0x4110 ma **r0=node** da 0x4111.
- Skip bit1: 0x4110 consegna solo `20E814(0,0x4110,arg)`; 0x4111 solo
  `14941C(2,...)`/`177460`, senza ring/ctx/20E814.
- Gate=0: append incondizionato a slot 0 e gate→1 (append SENZA reset).
- Gate=0xFF: append a 0x47BFB4, byte gate **wrap 0x00**, registro r0 resta
  0x100 (caso `w4110_gate_ff`); guardia attiva anche a 0xFF blocca 0xA
  (caso `w4111_gate_ff_guard`).
- `[ctx+0xC]` NON è mai toccato da questi writer (a differenza di 0x65C720).

## Banco e protocollo di frame (originale)

Finestre byte-originali caricate agli indirizzi originali: `.h41`
(2, 0x65CC18..0x65CD54, sha256 53588bea…cadc), `.epi` (2, 0x659588..0x659594,
mov sp,fp; ld.ab fp; b 0x334194), `.mili` (0, 0x334100..0x3341E4: push
0x33412C e pop 0x334194). I due handler chiamano il millicode reale e il
ritorno passa per l'epilogo condiviso e il pop millicode completi
(ld r15/r14, ld.ab r13, ld.ab blink, j_s [blink]) con bilancio frame
provato: il valore di ritorno del caso arriva al banco.

**Lezione di banco (corretta in corsa dall'audit):** la `b` 32-bit finale di
0x4110 a 0x65CCC2 (PC≡2 mod 4, displacement −14136) era stata trattata come
«wrap del sim a 0x65D588» (ipotesi dalla lezione it.44), con un trampolino
`syncret` collocato lì (`mov r12,0x659588; j_s [r12]`). La revisione
indipendente ha impugnato la claim e la traccia empirica del motore pinnato
(sha256 7d6ccd1b…) la smentisce: `0x65ccc2 b 0x659588 - pc <- 0x659588` — la `b`
esegue CORRETTAMENTE; idem quella allineata di 0x4111 (0x65CD50). Il
trampolino a 0x65D588 è codice morto precauzionale, mai eseguito; la lezione
it.44 NON si riproduce in questi siti con questo motore (divergenza da
chiarire in futuro, le evidenze it.44 non vengono qui revocate). La validità
del banco è indipendente da questo punto.

## Casi CPU (14, tutti PASS x2)

| # | caso | esenziale |
|---|---|---|
| 0 | w4110_append_gate1 | gate1, ring[0]=0xD → ring[1]=9, gate=2, ctx+0x10=ret(145D1C)=0x600D |
| 1 | w4110_guard_lastA | ring[0]=0xA → nessun append, gate=1, tail comunque eseguito (65DAD0 riceve gate vecchio) |
| 2 | w4110_gate0 | gate=0 → 9 a slot 0, gate=1, nessuna lettura guardia |
| 3 | w4110_append_gate2 | ring[1]=9 → 9 a slot 2, gate=3 (9 consecutivi ammessi) |
| 4 | w4110_bit1_skip | 135A84 bit1 → solo 20E814(0,0x4110,arg); ring/ctx sentinella |
| 5 | w4110_gate_ff | word 0x33 → 9 a 0x47BFB4, gate 0xFF→0x00, r0=0x100 al 65DAD0 |
| 6 | w4111_append_gate1 | ring[0]=5 → 0xA a slot 1, gate=2, coda 14941C/177460 |
| 7 | w4111_guard_lastA | ring[0]=0xA → bloccato, gate=1 |
| 8 | w4111_gate0 | 0xA a slot 0, gate=1; 65DAD0 riceve r0=EA=0x47BBB8 |
| 9 | w4111_bit1_skip | solo 14941C(2,…)/177460, NESSUN 20E814 |
| 10 | w4111_q14941c_ne0 | 14941C=0x55 → nessun 177460, ritorno 0x55 |
| 11 | w4111_gate_ff_guard | word 0xA a 0x47BFB0 → bloccato, gate resta 0xFF |
| 12 | dbl_4111_twice | 1ª chiamata appende 0xA (gate 1→2); 2ª bloccata dalla guardia (ring[1]==0xA) |
| 13 | dbl_9_then_A | 0x4110 poi 0x4111: 9 a slot1, 0xA a slot2, gate 1→2→3 |

Negativi e sentinelle in ogni caso: slot −1 (0x47BBB4) mai scritto, ctx+0xC
sentinella, conteggio chiamate esatto, "nessuna chiamata extra" (voce di log
successiva con sid 0), valori di ritorno al banco (RETCELL/RETCELL2).
Stub a sequenza (RETSEQ) per 135A84/14941C/145D1C; ~12 callee stub; logger a
16 byte per chiamata.

## Conseguenze sul sottosistema gate

1. La famiglia dei writer è ora CHIUSA in CPU: 0x65C720 (it.39) resetta gate
   e [ctx+0xC] e scrive SEMPRE slot 0; 0x4110/0x4111 APPENDONO senza reset e
   possono far crescere il gate oltre 1 tra un 0x65C720 e l'altro — l'ipotesi
   espressa in it.39 è ora provata (casi dbl).
2. Il ciclo post-0x65C720 diventa: 0x65C720 scrive il motivo a slot 0, lascia
   gate=1 e accoda l'evento 0x4111/0x4110; l'handler dell'evento appende
   0xA/9 a slot 1 (gate→2). Il lettore h100 consuma
   `word[0x47BBB4+4*gate]` = ultima voce.
3. L'invariante «nessun 0xA consecutivo» è una proprietà del firmware
   (guardia), non del banco.
4. L'handler 0x4110 NON riceve mai il node nel forward finale (r0=0): diverso
   da tutti gli altri handler ASLV studiati, che consegnano (node,ev,arg).

## Comandi ed esiti

- `python3 Python_Trace_Scripts/s33_verify_aslv_append_writers_cpu.py` →
  PASS_ASLV_APPEND_WRITERS_CPU **20261101T202252150931Z**; riesecuzione
  **20261101T202318161207Z** identica (confronto JSON ex-utc: True).
- Regressioni post-PASS (eseguite direttamente, log /tmp/reg41_*):
  aslv_helper_d098 PASS 202347Z, aslv_b060_arg18_clear PASS 202407Z,
  service_raise_pending PASS 202426Z, snapshot_capture_record_init PASS
  202430Z.
- Evidenze: [run 1](../Risultati/GUI_S33/aslv_append_writers_cpu_20261101T202252150931Z/),
  [run 2](../Risultati/GUI_S33/aslv_append_writers_cpu_20261101T202318161207Z/),
  [run finale script corretto](../Risultati/GUI_S33/aslv_append_writers_cpu_20261101T203730763689Z/).

## Revisione indipendente e traccia del wrap

Agente **aw-review-41** (revisione statica ex-novo: disassembly propri di
tutti i 16 blocchi, census LE32/halfword, sha256 ricalcolati, sorgenti del
sim letti): **C1–C8 CONFERMATI** con indirizzi byte-esatti, inclusi il
decremento del gate a 0x65B524/0x65B526 dentro 0x65B3A8, la classificazione
di TUTTI gli utenti del ring/gate nel block 2 (writer solo quelli noti:
0x65C720, apertura 0x4401→0x659554 con gate:=0 a 0x659576, i due handler
it.41, decremento 0x65B526; residuo 0x65C922 `ld_s` senza store, quasi
certamente dati) e l'assenza di collisioni del syncret. Due note APERTA:
(1) i commenti objdump per `ld.as` non sono conclusivi ma le distanze tornano
con i pool reali 0x65B388/0x65B390; (2) la claim del wrap del sim non era
chiudibile staticamente → risolta EMPIRICAMENTE con la traccia sopra
(smentita). Revisione: [Risultati/GUI_S33/aslv_append_writers_agent_review_aw41_20261101.md](../Risultati/GUI_S33/aslv_append_writers_agent_review_aw41_20261101.md),
tracce: [Risultati/GUI_S33/aslv_append_writers_wrap_trace_20261101T20261101T203728Z/](../Risultati/GUI_S33/aslv_append_writers_wrap_trace_20261101T20261101T203728Z/) (`wrap_trace_summary.json` + due .trace).

## Limiti e non dimostrato

Statica + 14 casi CPU sintetici; nessun hardware/boot/rendering/scatto;
NON_INSTALLARE; circa 10% invariato. Ring, gate, ctx, registro p3 e i valori
di ritorno degli stub sono fixture del banco (RAM runtime nel gap di load
0x428600..0x5FE800, non verificabile dal dump). Chi genera a runtime gli
eventi 0x4110/0x4111 (la coda di servizio interrogata da 0x65C720) e la
schedulazione non sono provati. Il trampolino syncret a 0x65D588 è codice di
banco, non firmware. Il significato dei valori 9/0xA resta interpretazione.
0x65B3A8 (handler 0x380/0x400, lettore/decrementatore del gate + chiamante
diretto di 0x65CCC8) è solo individuato staticamente, non eseguito.

## Fonti

- Verificatore: [s33_verify_aslv_append_writers_cpu.py](../Python_Trace_Scripts/s33_verify_aslv_append_writers_cpu.py)
- Evidenze congelate: `verified_evidence.json` delle due run (windows sha256,
  census LE/bl, freeze hex, 14 casi con fault 0xDEADB001..0x0E)
- Precedenti: it.39 (ring writer), it.37 (h100, sottosistema gate), it.44
  (lezione b 32-bit PC≡2 mod 4), it.30/it.25 (epilogo condiviso, registro p3)
- Revisione indipendente: vedi checkpoint (agente aw-review-41)
