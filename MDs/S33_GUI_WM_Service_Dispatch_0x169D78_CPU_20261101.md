# Dispatcher di servizio WindowManager 0x169D78 decodificato e CPU-provato: switch su EVENTO (correzione it.45), hook [[0x367808]], mappa eventi 0x4401-0x4409→funzioni di servizio, contesto maestro 0x366E94, registri notifiche {handler,evento} p1/p3 — 1 novembre 2026 (iterazione 46 / ciclo 14)

## Domanda

Punto aperto (a) dell'iterazione 45 ([S33_GUI_Event_Router_Produttori_Ponte_CPU_20261101.md](S33_GUI_Event_Router_Produttori_Ponte_CPU_20261101.md)):
chi consegna 0x4006 alle finestre e come instrada 0x169D78 gli eventi —
trasformando «0x4006: meccanismo di consegna APERTO» in una catena dimostrata.

## Verificatore

`Python_Trace_Scripts/s33_verify_wm_service_dispatch_cpu.py` → **PASS_WM_SERVICE_DISPATCH 20261101T142841334814Z**; riesecuzione identica **20261101T142847767747Z** (tutte le sezioni dell'evidenza identiche, solo `utc` differisce). Prove: `Risultati/GUI_S33/wm_service_dispatch_cpu_20261101T142841334814Z/` (+ riesecuzione `..._20261101T142847767747Z/`). Regressioni tutte PASS dopo il nuovo verificatore: guard setter census 142853042095Z, flag matrix 142905347284Z, snapshot record init 142905847979Z, service raise pending 142906Z, event router producers 142911035356Z.

## Risultato 1 — 0x169D78 decodificato per intero e CPU-provato (8 casi, byte originali)

Finestra originale 0x169D78..0x169E18 (160 byte, sha256 in evidenza), taglio
prima della `b` 32-bit finale a 0x169E18 con trampolino `b` a 32 bit + nop
(metodo it.44/45; la codifica è `w = (target-(cut&~3))+1`, byte `w,0,0,0,nop`).
Pool originali 0x16A128..0x16A174 e prologo 0x334120..0x33413A inclusi come
byte; stub agli INDIRIZZI ORIGINALI delle 11 funzioni di servizio.

```
0x169D78(node, event, arg)   [r14=node, r13=event, r16=arg]
  node==0 ∧ event==0 -> return 0
  hook: r3 = [[0x16A12C]=0x367808]; se ≠0: hook(node);
        se ritorna 0x55AA5AA5 -> EVENTO INGOIATO (return 0)
  event==0x5403 -> 0x16A8BC; 0x5402 -> 0x16A7A4; 0x5401 -> 0x16A834
                   (cmp_s diretti, pool 0x16A15C/0x16A154/0x16A158)
  event∈[0x4401..0x4409]: k=event-0x4401 (bhi k>8 -> default);
        byte = tabella 0x169DDC[k] (05 07 19 19 09 0B 0F 11 0D 00);
        STUB = 0x169DDC + 2*byte   [add1_s GNU = scalatura ×2, CPU-provata]
        servizio = pool[(STUB&~3)+0x354]   (pool 0x16A138+4k')
  qualunque altro evento -> 0x16A6E4 (consegna di default, pool 0x16A160)
  servizio riceve (node, event, arg) INVARIATI (log CPU dei tre registri)
```

Mappa eventi CPU-provata (casi svc4406/svc5401/svc4401/svc4403/svc4409/svc_other/svc_hook/svc_null, fault 0xDEADB001..0xDEADB008):

| Evento | Servizio | Prova |
|---|---|---|
| 0x4401 | 0x16A05C | CPU |
| 0x4402 | 0x16A0BC | statica (×2, byte 0x07) |
| 0x4403 | **default 0x16A6E4** | CPU (byte 0x19 → stub default) |
| 0x4404 | **default 0x16A6E4** | statica (byte 0x19) |
| 0x4405 | 0x16A188 | statica (byte 0x09) |
| 0x4406 | 0x16A1FC | CPU |
| 0x4407 | 0x16A66C | statica (byte 0x0F) |
| 0x4408 | 0x16A6A8 | statica (byte 0x11) |
| 0x4409 | 0x16A29C | CPU |
| 0x5401 | 0x16A834 | CPU |
| altro | 0x16A6E4 | CPU |

**CORREZIONE dell'it.45**: il rapporto precedente scriveva «nodo≤8 → jump
table 0x169DDC … nodo>8 → pool 0x16A160». È falso: lo switch è sull'EVENTO
(r13 = r1), byte 0x169DC2-0x169DDA (`sub r0,r13,0x4401; cmp 8; bhi`), e la
jump table è indicizzata da evento-0x4401. La docstring del verificatore
it.45 contiene lo stesso errore («default (node > 8)»); il verificatore
resta PASS perché le sue asserzioni riguardavano finestre/census/LE, non
questo instradamento.

**LEZIONI DI BANCO (nuove)**:
1. `add1_s` (0x7C14) nel disassembler GNU di questo toolchain scala l'operando ×2: la mappa byte→stub è consistente 9/9 SOLO con la scalatura ×2, e i casi CPU svc4401/svc4403/svc4406/svc4409 la confermano. L'etichetta GNU è fuorviante (come il `b` 32-bit dell'it.44).
2. LIMM_16 ARC700: la costante di un'istruzione 16-bit si legge all'indirizzo 4-allineato successivo con HALFWORD SCAMBIATI (byte `aa 55 a5 5a` a 0x169DA0 = costante 0x55AA5AA5; `00 00 03 54` = 0x5403). Il listing GNU mostra la costante già decodificata.
3. Il trampolino di taglio è un `b` a 32 BIT (`w,00,00,00` + nop), NON un b_s a 16 bit: la codifica a 16 bit viene letta dal sim come metà di una word 32-bit spuria e va in loop (banco v6, timeout — corretto).

## Risultato 2 — produttore di 0x4006 TROVATO (audit indipendente + riverifica byte)

L'audit indipendente (agente `router-audit-14`, revisione C1-C8 del
verificatore it.45 con decoder BL proprio) ha CONFUTATO il claim forte
dell'it.45 «0x4006 NESSUN produttore»: esistono produttori che costruiscono
l'evento con `mov_s r1,N; bset_s r1,r1,0xe` (evento = N|0x4000), invisibili
alla classificazione a pool/costante. Riverificati byte-esatto in questa
sessione:

- **0xCB950**: `mov_s r1,0x6; bset_s r1,r1,0xe; mov_s r2,0xff; bl 0x169EB4` → posta **0x4006** con desc=0 (finestra corrente), arg 0xFF; subito dopo risolve il nodo corrente con 0x1453F4 e consegna **0x4114** (pool 0xCB99C) via 0x169D78 (cluster CaptureMenu, it.39-44).
- **0x20F972**: `mov_s r0,0; mov_s r1,0x6; bset_s r1,r1,0xe; mov_s r2,r13; bl 0x169EB4` → 0x4006 con arg contatore r13∈[0,0x63] (funzione 0x20F9xx, cluster dei reattori di notifica, v. Risultato 3).
- Altri produttori bset segnalati dall'audit (da riverificare singolarmente in un banco futuro): 0x16E6A0, 0x653E30 (via 0x169EB4), 0x65BA36 (via 0x169F00); 0x4001 ×4 (0xC6392, 0x6633AA, 0xCB6BE, 0xC6378 tail-b), 0x4002 ×29, 0x4003 (0xC5FB2), 0x4005 (0x1358B4 tail-b).

Il claim letterale it.45 «nessun produttore a costante/pool» resta vero; la
consegna di 0x4006 NON è più APERTA: il percorso è **produttore bset →
0x169EB4(desc=0) → coda 0x17BC7C → ciclo 0x15AF1C → 0x169E1C → risoluzione
finestra corrente → router → tabella → handler** (ponte D 0x7F877C per la
finestra CaptureMenu; it.45 caso dispatch3181 ha già provato in CPU lo stadio
finale per 0x3181, stesso meccanismo di scansione tabella).

## Risultato 3 — registri notifiche {handler, evento} (nuovo, statico congelato)

- **payload1 dati inizializzati 0x3E8BB8..0x3E8DC8**: 66 record da 8 byte
  {u32 handler, u32 evento}, handler tutti in codice p0 (0x144xxx..0x210xxx).
  Selezionati (byte-esatti nel verificatore): 0x4001→0x144F30, 0x4002→0x20EF00,
  0x4005→0x20FDA4, **0x4006→0x20F294**, 0x400B→0x20F934, 0x4100→0x20F9C4,
  0x4410→0x20E900, 0x4112→0x20FC24, 0x410A→0x20F414, 0x4124→0x210364; più
  eventi tasto 0x80..0x900, sistema 0x7C40..0x7D10, 0x4111, 0x4120..0x4123.
  **NESSUNA parola LE punta ai confini 0x3E8BB8/0x3E8DC8 in nessun payload:
  il consumatore del registro NON è identificato (APERTO).**
- **payload3 tabelle statiche**: 0x7834C0 {handler,evento}: 0x3281→0x653E38,
  0x3301→0x653F18, 0x4005→0x653FF4, **0x4006→0x654024**, 0x4002→0x6540A4,
  0x4008→0x654228; 0x783BE0 {evento,handler}: 0x3281→0x65BFDC,
  **0x3B81→0x65C08C**, 0x3301→0x65C178, 0x4001→0x65C928,
  **0x4006→0x65CA60**, 0x4005→0x65CA04, 0x4111→0x65CCC8, 0x4002→0x65CD54.
- LE scan completo del valore 0x4006 congelato: 8 voci tabelle p5
  (0x98E7E0, 0x99AC8C, 0x99BBDC, 0x99C5D8, 0x99C8AC, 0x99D4DC, 0x9A0688,
  0x9A3034), 1 record p1 (0x3E8D84), 2 p3 (0x7834EC, 0x783C00), hit
  disallineati p0 0x28A44B (off3) e p6 0xB37F22 (off2); **nessuna word
  4-allineata nei payload di codice p0/p2/p4**.

## Risultato 4 — contesto maestro WindowManager 0x366E94

Pool 0x145350 = **0x366E94**: +0x10 = finestra corrente (cella 0x366EA4,
scritta/letta dal commutatore 0x145180), +0x14 = finestra bersaglio/pending
(0x366EA8), +0x18 = controllo attivo (0x366EAC, già osservato in it.39-40).
Pool lifecycle del commutatore: 0x145354=0x4409, 0x14535C=0x4403,
0x145360=0x4414, 0x145364=0x4404, 0x145368=0x4406, 0x14536C=0x4402,
0x145370=0x4401, 0x145374=0x4415, 0x145378=0x4405. Il commutatore 0x145180
consegna 0x4401..0x4409/0x4414/0x4415 durante le transizioni di finestra —
ossia gli eventi che 0x169D78 instrada alle funzioni di servizio della
Risultato 1 (chiusura del cerchio produttore→dispatcher).

## Audit indipendente (agente router-audit-14, integrato)

Revisione C1-C8 del verificatore it.45 con metodo proprio (decoder BL/bl_s
ex-novo validato su siti noti, census propri, LE scan propri, parser ELF32
proprio sugli ELF congelati; nessuna riesecuzione del verificatore, nessun
hardware). Esiti: **C1 CONFERMATO** (nodo 0x99AB6C, callback 0x7F6824 LE
unica a 0x99AB78), **C2 CONFERMATO** (router: fuori [128,0x307F] → 0x169F60
con pool unici 0x7F6A48/0x7F6A4C; 0x7F6824 zero chiamanti bl), **C3
CONFERMATO** (0x169F60 lista di esclusione + scan tabella), **C4 PARZIALE**
(census e produttori ponte confermati; claim forte su 0x4006 CONFUTATO con i
produttori bset — v. Risultato 2), **C5 PARZIALE** (confermato l'unico
chiamante 0x15AF42 e il resolver [[0x366EA4]]; confermata la correzione:
lo switch è sull'EVENTO), **C6 CONFERMATO** (coda: indici read+0/write+2 non
scalati, 128 voci, stride 12, census insert/push-front/extract), **C7
CONFERMATO** (sezioni originali dei 3 dir di prove byte-identiche al
firmware; fault attesi; JSON identici a parte utc), **C8 controesempi**:
(a) produttori bset/asl-built (0x4006 ×5, 0x4001 ×4, 0x4002 ×29, 0x4003,
0x4005, 0x7C00/0x7D00) e 37/365 chiamanti con r1 non classificabile
staticamente; (b) 7 LE di 0x169EB4 = pool a puntatore singolo per `jl_s [rN]`
eventi 0x80/0x100/0x580/0x7CF6, non jump-table: il census bl non cambia;
(c) secondo lettore di [[0x366EA4]] a 0x1453FC (riverificato: ld pool
0x14579C, cmp, se ≠0 `bl 0x14504C` con r1=4), NESSUN writer statico della
cella (APERTO, coerente con punto aperto (c) dell'it.45); (d) 19 tail-call
`b` alle API di post (nessun evento ponte) e zero LE sulle consegne indirette.
Nota dell'audit: 3916/362.109 commenti `;0x` GNU bl divergono dal suo decoder
in regioni dati decodificate come codice (collisione V con payload10); per
ogni sito dei census i decode coincidono. L'audit ha registrato l'esito in
PMB (record_batch, outbox 378).

## Comandi/esiti

`python3 Python_Trace_Scripts/s33_verify_wm_service_dispatch_cpu.py` →
**PASS_WM_SERVICE_DISPATCH 20261101T142841334814Z**, riesecuzione identica
**142847767747Z**. Correzioni di banco durante lo sviluppo (documentate,
asserzioni invariate): lunghezza finestra 160; mkdir prove nel finally;
fette cmp LIMM_16 a 6 byte; predicato LE «word 4-allineata»; confini registro
p1 0x3E8DC8; trampolino `b` a 32 bit (16 bit → loop, banco v6); assert PC
sonda allentato al range della sonda (il fault avviene all'ldb, non
all'inizio sezione).

## Fonti precise

- Payload0 (base 0x0AD800): 0x169D78..0x169E18 (dispatcher), byte table
  0x169DDC, stub ld_s 0x169DE6..0x169E0E (passo 4), pool 0x16A12C..0x16A170
  (servizi e hook), prologo 0x334120..0x33413A; commutatore 0x145180 e pool
  0x145350..0x145378; resolver 0x1453F4 e secondo lettore 0x1453FC (pool
  0x14579C=0x366EA4); produttori 0xCB950, 0x20F972; reattori registro p1
  0x20F294/0x20F934/0x20F98C/0x20FDA4.
- Payload1 (dati inizializzati): registro 0x3E8BB8..0x3E8DC8 (66 record).
- Payload3: tabelle 0x7834C0, 0x783BE0.
- Payload5: 8 voci tabelle 0x4006 (congelate it.45).
- Evidenze: `Risultati/GUI_S33/wm_service_dispatch_cpu_20261101T142841334814Z/`
  (8× .s/.ld/.elf/.bin + verified_evidence.json), riesecuzione
  `..._20261101T142847767747Z/`.

## Limiti

- Statico + 8 casi CPU sintetici: nessun hardware, boot, rendering, scatto o
  persistenza; NON_INSTALLARE; circa 10% invariato.
- Il registro {handler,evento} p1 NON ha consumatore identificato (nessuna LE
  ai confini): come e da chi viene percorso resta APERTO; i reattori (es.
  0x20F294) NON sono stati eseguiti.
- Nessun writer statico di [0x366EA4] trovato (audit C8c): l'ipotesi
  «scrittura tramite puntatori calcolati/struct» resta da provare.
- I produttori bset 0x16E6A0/0x653E30/0x65BA36 e i tail-b sono statici
  (listing), non eseguiti in CPU; idem 0x4001×4/0x4002×29.
- Il census non copre eventi costruiti in registro a runtime da dati, né le
  chiamate indirette jl statisticamente invisibili.
- La schedulazione runtime (chi posta 0x4006 rispetto a 0x4405/0x158d04)
  NON è provata.
- Il default 0x16A6E4 (filtro classi tasto su contesto 0x367800, resolver
  0x145790, invoker 0x16A028) è stato solo letto staticamente qui; it.45 lo
  aveva congelato come finestra W_16A6E4.

## Prossimo passo (non ripetitivo)

(a) **Consumatore del registro notifiche p1 0x3E8BB8..0x3E8DC8**: cercare il
percorritore della tabella {handler,evento} (candidati: inizializzatori che
copiano la tabella in array RAM [0x366E94+8/+0xC] — vedi 0x14507C(idx) che
indicizza [base+2*idx] — oppure chiamanti indiretti jl_s con base calcolata);
contestualmente provare in CPU il reattore 0x20F294 con evento 0x4006 e
modalità 0x82/altre per vedere se inoltra alla finestra corrente.
(b) Writer di [0x366EA4] (punto aperto it.45c, confermato dall'audit):
cercare store indiretti nel commutatore 0x145180 (st_s r13,[r0,0x10] con
r0=[0x145350]) — probabilmente risolvibile con il census dei lettori di
pool 0x145350.

## ERRATA (1° novembre 2026, iterazione successiva)

Il punto (a) è CHIUSO e due claim di questo rapporto sono corretti da
[S33_GUI_Registro_Notifiche_Consumatore_CPU_20261101.md](S33_GUI_Registro_Notifiche_Consumatore_CPU_20261101.md)
(sessione interrotta, PASS_REGISTRY_CONSUMER 20261101T144258994696Z) e da
[S33_GUI_Router_0x169F60_p5_Default_Catena_Esclusioni_CPU_20261101.md](S33_GUI_Router_0x169F60_p5_Default_Catena_Esclusioni_CPU_20261101.md)
(replica indipendente PASS_WM_NOTIFY_REGISTRY 20261101T155229008610Z):

1. **Il consumatore del registro p1 è identificato**: il router
   0x169F60, chiamato dal wrapper 0x20E814 con tabella 0x3E8BB4. La LE
   mancante dei confini 0x3E8BB8/0x3E8DC8 era dovuta alla base errata:
   la tabella inizia a **0x3E8BB4** (4 byte prima).
2. **L'accoppiamento {handler, evento} era slittato di un record**:
   la mappa corretta è 0x4410→0x20E848, 0x4005→0x20F294,
   **0x4006→0x20F414** (non 0x20F294), 0x400B→0x20F98C,
   0x4008→0x20F9C4, 0x4001→0x20EF00, 0x410A→0x20FF9C. Il «reattore
   0x20F294 con evento 0x4006» suggerito sopra avrebbe quindi usato
   l'handler SBAGLIATO: 0x20F294 è il reattore di 0x4005.
