# Registro notifiche p1: consumatore identificato (forwarder 0x20E814 → walker 0x169F60 con tabella 0x3E8BB4), layout {evento,handler} CORRETTO (sfasamento it.46), tabella nodi WindowManager 0x3F5900 (197 voci, node[2]=CaptureMenu), writer di [0x366EA4] dentro il commutatore 0x145180 — 1 novembre 2026 (iterazione 47 / ciclo 14)

## Domanda

Punti aperti (a) e (b) dell'iterazione 46 ([S33_GUI_WM_Service_Dispatch_0x169D78_CPU_20261101.md](S33_GUI_WM_Service_Dispatch_0x169D78_CPU_20261101.md), prossimo passo):

- (a) chi percorre il registro notifiche di payload1 e con che semantica;
  più in generale: come gli ID tipo 0x87/0x5E passati a `0x1453E4` risolvono
  le finestre;
- (b) chi scrive la cella finestra corrente [0x366EA4] (audit C8c it.46:
  «NESSUN writer statico»).

## Verificatore

`Python_Trace_Scripts/s33_verify_registry_consumer_cpu.py` →
**PASS_REGISTRY_CONSUMER 20261101T144258994696Z**; riesecuzione identica
**20261101T144310342926Z** (evidenze identiche al confronto ricorsivo,
solo `utc` differisce). Prove:
`Risultati/GUI_S33/registry_consumer_cpu_20261101T144258994696Z/` e
`..._20261101T144310342926Z/` (13× .s/.ld/.elf + sezioni .bin
byte-identiche ai payload verificati + verified_evidence.json +
p0_listing.lst completo per i census bl).

Regressioni tutte PASS dopo il nuovo verificatore: guard setter census
**144323894185Z**, flag matrix 14 casi **144339603828Z**, snapshot record
init 4 casi **144342668571Z**, service raise pending **144343Z**, event
router producers **144350191891Z**.

Correzioni di banco durante lo sviluppo (documentate, asserzioni rafforzate
e non indebolite): mappa selezionata 0x4008→0x20F9C4 e 0x400B→0x20F98C
(due trascrizioni errate del coordinatore, corrette dal verificatore
stesso); node[4]=0x783D54 (lettura colonna errata); census bl di 0x20E814
esteso da 10 a 39 siti (il primo census manuale era troncato da un
`| head` di shell — LEZIONE); `p0_listing` scritta dopo l'istanziazione
del Runner (che rifiuta directory esistenti); trampolino del caso
node_init_acc a 4 byte senza nop (la pool word 0x23D280 segue
immediatamente il taglio a 0x23D27C).

## Risultato 1 — consumatore del registro p1 (chiude (a)) e CORREZIONE del layout

- **Il percorritore è 0x169F60**, lo stesso scanner {evento,handler}
  già provato in it.45 per le tabelle finestra:
  `0x169F60(excl_array, tabella, arg0, evento, arg2)`:
  - se `excl_array != 0`: cammina un array **u16** (stride 2, terminatore
    0); se l'evento è presente → **nessun dispatch** (lista di
    esclusione, come l'array 0x99ACAC di it.45);
  - cammina `tabella` con stride 8: `[entry] == evento` → break;
    `[entry] == 0` → break (terminatore); handler = `[entry+4]`; se 0 →
    return 0; altrimenti `handler(arg0, evento, arg2)` via `jl_s.d [r3]`.
- **Il registro è passato esplicitamente dall'inoltratore 0x20E814**
  (finestra 0x20E814..0x20E83E, prologo millicode 0x33412C, epilogo
  tagliato a 0x20E83E): `0x20E814(nodo, evento, arg)` carica
  **pool 0x20E844 = 0x3E8BB4** e chiama
  `0x169F60(0, 0x3E8BB4, nodo, evento, arg)`.
- **CORREZIONE it.46**: il registro NON è `{handler, evento}` con inizio
  0x3E8BB8: è **`{u32 evento, u32 handler}` con la tabella che inizia a
  0x3E8BB4** (il valore 0x7CE4 a 0x3E8BB4 è il PRIMO EVENTO, non una
  intestazione). 66 record, terminatore (0,0) a **0x3E8DC4**, tutti gli
  handler in codice p0. La mappa it.46 era sfasata di un record:
  | Evento | it.46 (errato) | Corretto (CPU) |
  |---|---|---|
  | 0x4410 | 0x20E900 | **0x20E848** |
  | 0x4005 | 0x20FDA4 | **0x20F294** |
  | 0x4006 | 0x20F294 | **0x20F414** |
  | 0x400B | 0x20F934 | **0x20F98C** |
  | 0x4001 | 0x144F30 | **0x20EF00** |
  | 0x4002 | — | **0x20F080** |
  | 0x4008 | 0x20F9B0 | **0x20F9C4** |
  | 0x410A | 0x20F414 | **0x20FF9C** |
  | 0x4001→0x144F30 | — | corretto: **0x3101→0x144F30** |
  Nota: 0x7D10→0x20FDA4 e 0x4111→0x210080 coincidevano già. Il reattore
  0x20F294 decodificato in it.46 è il reattore di **0x4005**, non di
  0x4006 (il gate 0x1453FC()==0x82 resta valido come lettura di quel
  reattore).
- Mappa completa nel verified_evidence.json (`registry.map`, 66 voci);
  sha256 del blocco 0x3E8BB4..0x3E8DC8 = `5e7a4614e8ba0aaaaecba1b8ca43
  075e3c58948e549bfbb14a5591ae89a4244f`. Eventi presenti: tasti
  0x80/0x180/0x200/0x280/0x281/0x300/0x301/0x480/0x481/0x500/0x501/
  0x600/0x700/0x780/0x900/0x2180/0x2280/0x2380, ponte 0x3081/0x3101/
  0x3181/0x3201/0x3281/0x3301/0x3B81, sistema 0x4000..0x4124/0x4410/
  0x7C40..0x7D10/0x7CE4.
- **LE scan a QUALSIASI allineamento su tutti i 16 payload**: 0x3E8BB4
  appare SOLO nella pool 0x20E844; 0x3E8BB8 da NESSUNA parte. L'it.46
  non aveva trovato il consumatore perché la LE era 4 byte prima del
  confine dichiarato.

## Risultato 2 — 0x20E814 è il callback eventi condiviso delle finestre

- **39 chiamanti bl** in p0 (census completo su listing ex-novo:
  0x134D80, 0x135116, 0x13523C, 0x135254, 0x1353E8, 0x135500, 0x135528,
  0x20F76A, 0x20F83E, 0x20F872, 0x224794, 0x224B00, 0x2AB324, 0x2C9FDE,
  0x2C9FFC, 0x2CA018, 0x2CA034, 0x2CA8E0, 0x2CADC4, 0x2CCBAA, 0x2CE27A,
  0x2CE2F4, 0x2CE3B6, 0x2CE3EA, 0x2CECC4, 0x2D0C24, 0x2D333C, 0x2D3358,
  0x2D3376, 0x2D389C, 0x2D38B8, 0x2D3BE8, 0x2D3DE0, 0x2D40F4, 0x2D4124,
  0x2D4270, 0x2D47FE, 0x2D494A, 0x2D497A) e **182 parole LE 4-allineate**
  in dati descrittori: p1: 20, p3: 7, p5: 135 (tra cui 0x99ACA8, subito
  dopo la tabella della finestra ponte 0x99AB8C), p7: 20; NESSUNA in
  p0/p2/p4. Interpretazione: campo callback di decine di descrittori di
  finestra; i reattori del registro stesso (0x20F76A, 0x20F83E, 0x20F872)
  lo richiamano per inoltrare sotto-eventi.

## Risultato 3 — tabella nodi WindowManager 0x3F5900 (nuovo)

- **0x23D278**: `ld_s r0,[pool 0x23D280]=0x3F5900; mov r1,0xC5 (197)`;
  tail-`b` a **0x145018**, che scrive
  `[0x366E94+8] := 0x3F5900` e `[0x366E94+0xC] := 197`
  (pool 0x145350 = 0x366E94).
- **0x14507C(idx)** (9 chiamanti bl: 0x144594, 0x145138, 0x1453E8,
  0x169EA4, 0x169F48, 0x16A2F4, 0x20EFD4, 0x224838, 0x2B5A84):
  `0 ≤ idx < count` → ritorna `[[0x366E94+8] + 4·idx]`, altrimenti 0
  (`add2_s` = scala 4; `ldw_s.x` count halfword con segno, 197 positivo).
- **La tabella 0x3F5900 (197 voci u32, payload1)** contiene i descrittori
  di finestra: node[0]=0, **node[1]=0x7833CC (CaptureLiveview)**,
  **node[2]=0x9802AC (CaptureMenu: l'«ID 2» di it.39-45 è l'INDICE
  in questa tabella)**, node[4]=0x783D54, node[0x12]=0x4073D0,
  **node[0x5E]=0x98E134**, **node[0x7E]=0x99AB6C (la finestra ponte con
  tabella 0x99AB8C)**, **node[0x87]=0x783AE8**; 196/197 non zero, tutte
  le voci 0 o in range descrittori plausibili. sha256 del blocco:
  `d0a83c52f49fb0e9b06a1af3f920d6257bcdbf031299337792814b2048829647`.
- **Conseguenze per i percorsi già studiati**: `0x1453E4(idx, arg)` =
  `0x145180(node[idx], arg)` (notify per indice); il deliver 0x169E1C
  per evento 0x440F chiama `0x1453E4(r15&0xFFFF, r15>>16)`; 0x169E9C /
  0x169F40 risolvono `node[idx]` via 0x14507C prima di consegnare/infilare
  l'evento. Le notifiche «0x87/0x5E/0x7E» di it.42/43 e il ritorno
  impostazioni (descrittori 0x783AE8/0x98E134, it.30) sono ora INDICI
  spiegati. Il contesto maestro 0x366E94..0x366EB4 è **zero nell'immagine
  payload1**: +8/+0xC sono inizializzati a runtime da 0x145018.

## Risultato 4 — writer di [0x366EA4]/[0x366EA8] (chiude (b), corregge C8c it.46; integrazione audit: 6 store, non 3)

Dentro il commutatore **0x145180** (pool 0x145350 = 0x366E94) — i tre
provati in CPU sono in grassetto, i tre aggiunti dall'audit
`registry-audit-16` e riverificati byte-esatto in coordinatore sono in
corsivo:

- **0x1452EE** `st_s r13,[r0,0x10]` → **[0x366EA4] := r13** (finestra
  corrente := nodo), immediatamente dopo la consegna di 0x4401 al nuovo
  nodo (0x1452E0);
- **0x145306** `st_s r1,[r0,0x10]` con r1=[0x366EA8] → **corrente :=
  pendente** (via di ripristino dopo 0x4415);
- **0x14538A** `st_s r13,[r0,0x14]` → **[0x366EA8] := r13** (pendente);
- *0x145234* `st_s r1,[r0,0x14]` con r1=[0x366EA4] → *pendente :=
  corrente* (dopo la consegna di 0x4414 a 0x14522A)*;
- *0x145338* `st_s r15,[r0,0x10]` → *corrente := bit7 della prima word
  del nodo corrente* (r15 = 0/1, da `lsr r0,r0,7; bmsk r15,r0,0` a
  0x1451C8; dopo la consegna di 0x4402 a 0x145330)*;
- *0x14534C* `st_s r14,[r0,0x14]` → *pendente := r14 = corrente in
  ingresso* (r14 caricato a 0x1451B0 da [ctx+0x10])*.

Writer del campo adiacente **attivo [0x366EAC]**: **0x145B9A**
`st_s r13,[r0,0x18]` con r0=[pool 0x145BE4]=0x366E94 (nella funzione
0x145B08, già letta in it.46 per [+0x10]/[+0x18]/[+0x20]). I pool con
literal diretti delle celle (0x14579C=0x366EA4, 0x1457D0=0x366EAC) sono
usati solo da LETTORI (0x1453F4/0x1453FC/0x145790/0x1457D6);
[0x366EA8] non ha NESSUNA LE in alcun payload.

LE di 0x366E94 in tutti i payload (qualsiasi allineamento): solo pool
0x145350 e 0x145BE4. L'audit it.46 C8c «NESSUN writer statico» era
falso: gli store esistono, con base dal pool 0x145350 anziché con
l'indirizzo di cella diretto.

## Casi CPU (13, byte originali; fault 0xDEAD0001..0xDEAD000D)

1. `fwd_4006`: 0x20E814(0x99AB6C, 0x4006, 0x77) [finestra + prologo
   0x33412C originali] → stub a 0x169F60 riceve (0, 0x3E8BB4, 0x99AB6C,
   0x4006, 0x77).
2. `walk_4006`: 0x169F60(0, 0x3E8BB4, 0x1234, 0x4006, 0x77) [walker
   originale + REGISTRO REALE] → stub a **0x20F414** riceve
   (0x1234, 0x4006, 0x77).
3. `walk_4005` → stub a **0x20F294**.
4. `walk_4410` → stub a **0x20E848** (correzione della mappa).
5. `walk_2180` → stub a **0x20E940** (slot pulsante 2).
6. `walk_miss`: evento assente → terminatore, r0==0, nessun dispatch.
7. `walk_excl_blk`: esclusione u16 {0x4006,0} → nessun dispatch, r0==0.
8. `walk_excl_pas`: esclusione u16 {0x9999,0} → dispatch a 0x20F414.
9. `node_init_acc`: 0x23D278 originale (pool reale) → 0x145018 originale
   scrive [0x366E9C]=0x3F5900 / [0x366EA0]=0xC5 → 0x14507C(2) originale
   sulla TABELLA NODI REALE ritorna **0x9802AC (CaptureMenu)**.
10. `node_bounds`: count sintetico 5: 0x14507C(4) → 0x783D54 (node[4]
    reale); 0x14507C(5) → 0 (limite).
11. `cur_write`: finestra 0x1452EA..0x1452F0 → [0x366EA4]:=0x99AB6C,
    pendente intatto.
12. `pend_write`: finestra 0x145386..0x14538C → [0x366EA8]:=0x7833CC,
    corrente intatta.
13. `pend_to_cur`: finestra 0x145302..0x145308 → corrente:=pendente.

Metodo di banco consolidato (it.44-46): taglio prima delle `b` 32-bit
divergenti, trampolino hand-encoded `w=d+1` a 32 bit (senza nop quando
una pool word segue il taglio), stub agli INDIRIZZI ORIGINALI,
roundtrip byte verificato su ogni ELF, fault come unica via d'uscita.

## Comandi/esiti

```
python3 Python_Trace_Scripts/s33_verify_registry_consumer_cpu.py
  → PASS_REGISTRY_CONSUMER 20261101T144258994696Z (+ identica 144310342926Z)
python3 Python_Trace_Scripts/s33_verify_capture_guard_setter_census.py   → PASS 144323894185Z
python3 Python_Trace_Scripts/s33_verify_capture_flag_mode_matrix_cpu.py  → PASS 144339603828Z
python3 Python_Trace_Scripts/s33_verify_snapshot_capture_record_init_cpu.py → PASS 144342668571Z
python3 Python_Trace_Scripts/s33_verify_service_raise_pending.py         → PASS 144343Z
python3 Python_Trace_Scripts/s33_verify_event_router_producers_cpu.py    → PASS 144350191891Z
```

## Fonti precise

- Payload0 (base 0x0AD800): forwarder 0x20E814..0x20E83E (pool
  0x20E844=0x3E8BB4), walker 0x169F60..0x169FB0, prologhi millicode
  0x33412C..0x33413A / 0x334130..0x33413A, accessor 0x14507C..0x145098,
  init 0x145018..0x145020, pool 0x145350=0x366E94, init nodo
  0x23D278..0x23D27C (pool 0x23D280=0x3F5900), store commutatore
  0x1452EA..0x1452F0 / 0x145302..0x145308 / 0x145386..0x14538C,
  deliver 0x169E1C (0x440F→0x1453E4), 0x169E9C/0x169F40.
- Payload1 (base 0x360800): registro 0x3E8BB4..0x3E8DC8 (66+terminatore),
  tabella nodi 0x3F5900..0x3F5C14 (197), contesto maestro
  0x366E94..0x366EB4 (immagine zero).
- LE 0x20E814 nei descrittori: p1 20 (0x3EB464..), p3 7 (0x783528..),
  p5 135 (0x9805DC.., incl. 0x99ACA8), p7 20 (0xC6A998..).

## Limiti

- Statico + 13 casi CPU sintetici (stub per 0x169F60 nel caso forwarder;
  continuazione del forwarder dopo il ritorno non eseguita; commutatore
  NON eseguito come intero): nessun hardware, boot, rendering, scatto o
  persistenza; NON_INSTALLARE; circa 10% invariato.
- La schedulazione runtime (chi registra 0x20E814 nei descrittori, quando
  0x145018 viene chiamato rispetto al boot) NON provata; i valori
  immagine payload1 sono lo stato iniziale, non un boot dimostrato.
- Il reattore 0x20F414 (0x4006 corretto) NON è stato ancora decodificato
  né eseguito in CPU; idem gli altri reattori della mappa corretta; il
  gate 0x1453FC()==0x82 resta una lettura del reattore 0x20F294 (0x4005).
- Census bl: copre i soli target decodificati dal commento GNU
  (`;0x......`); chiamate indirette jl statisticamente invisibili; 39
  chiamanti includono siti in regioni che potrebbero essere dati
  decodificati come codice (fonte di falsi positivi documentata in
  it.46 audit C8) — ogni sito della lista è comunque nel range codice p0.
- V1.1 campione vs macchina V1.0; non trasferire indirizzi fra versioni.

## Prossimo passo (non ripetitivo)

(a) **Decodificare il reattore 0x20F414 (0x4006 corretto)** e i reattori
    dei quattro slot pulsante nella mappa del registro (0x700→0x20EAF4,
    0x2180→0x20E940, più i 0x480/0x500/0x600/0x780/0x900): ora che la
    mappa evento→reattore è CPU-provata, si può chiudere il collegamento
    snapshot→coda→dispatcher→router→finestra→callback 0x20E814→registro→
    reattore per gli slot logici, verificando in CPU con byte originali.
(b) Alternativa: il percorritore della tabella nodi lato WindowManager
    (chi itera node[] durante il boot/registrazione, es. la funzione
    0x145818 che legge [+0x18] e [+0x28]) e il significato dei campi
    del contesto maestro +0/+4 (array con accessor 0x145020, nessun
    inizializzatore bl trovato).
