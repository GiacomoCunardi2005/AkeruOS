# Framework service-request: vettori di interrupt, tabelle di classe e dispatcher nidificato dell'id 0x3002

**Iterazione 36 — 22 ottobre 2026 — studio statico offline (V1.1).**
Ramo: Runtime/Kernel → Obiettivo/iris. Chiude il prossimo passo (a) dell'iterazione 34: il **dispatcher dell'id 0x3002**, cioè chi invoca a runtime 0x241E5C (il consumatore di [0x392AC0+0x1C] = 0x140704, il committente dei bit iris id-1/2/4).

- Script: `Python_Trace_Scripts/s33_verify_service_request_framework.py`
- Prove: `Risultati/Runtime_Kernel/Service_Request_Framework/latest.json` (evidenza **20261022T031030Z post-audit**; 030248Z/030233Z = PASS pre-audit della stessa sessione; 025910Z–030204Z = calibrazioni fallite della prima stesura, conservate)
- Verificatore: sha firmware + blocchi manifest, 36 pool LE dai byte raw, parse delle 7 tabelle statiche da payload1, census bl con 15 target, scansioni negative LE/limm-ME, 19 finestre GNU ARC700 allineate, modello funzionale completo della catena.

## 1. Scoperta principale

Il firmware ha un **framework service-request a due livelli, guidato da interrupt**:

1. **Tabelle di registrazione statiche in payload1** (non BSS): ogni tabella ha record da 8 byte `{id hh, bitB b, bitA b, fn dw}` (regola `add3` = terzo operando ×8, byte-provata nell'interpolazione) e header `{+0 ptr mask pending, +4 ptr mask enable, +8 count hh}`.
2. **Walker per classe**: funzioni quasi-identiche (cluster 0x2640E0–0x265D74) che percorrono una tabella, chiamano `jl [fn]` dei record con bit di enable E pending entrambi settati e poi **riscrivono 1<<bit sulla halfword pending** (clear W1C del bit servito).
3. **I walker sono vettori di interrupt**: l'init 0x16D3F0 li installa nel dispatch eccezioni kernel (iterazione 29) tramite `0x231428(code, handler, 0)` — con **chiamate indirette** `jl_s.d [r13]`, r13 = pool 0x16d510.
4. **API servizi**: 0x16D898(id, fn) = registra, 0x16D7E8(id, …, 0xFF) = abilita, 0x16D840 = disabilita, 0x16D5BC = router per classe (id & 0xFF00), 0x16D4D8(id) = alza la richiesta (set del bit pending).

## 2. La tabella 0x424500 e il ciclo dell'id 0x3002

**Tabella 0x424500 (payload1, statica)** — la famiglia iris 0x2422xx:

| campo | valore |
|---|---|
| +0 | ptr → **0xFED3818** (halfword pending classe A) |
| +4 | ptr → **0xFED3814** (halfword enable classe A) |
| +8 | count classe A = 7 |
| +12 | record A, stride 8: ids 0x3007/0x3006/0x3005/0x3001/**0x3002**/0x3003/0x3004, bitB=bitA=6/5/4/3/**2**/1/0, fn=0 |
| +140 | ptr → 0xFED3834 (pending classe B) |
| +144 | ptr → 0xFED3830 (enable classe B) |
| +148 | count classe B = 8; record da +152: ids 0x4001..0x4008, bit 7..0 |

**Tabella 0x424B18 (payload1)** — la classe generica 0x6xx: pending **0xFEF0074**, enable **0xFEF0028**, count 16, record ids 0x0610..0x0601 con bitB=bitA=15..0. Le altre classi (router 0x16D5BC, `id & 0xFF00`): 0x4xx→0x424A00 (0xFEF0050/0xFEF0080, 16 record), 0x5xx→0x424A8C (0xFEF0328/0xFEF0068, 6), 0x6xx→0x424B18, **0x8xx→0x424BA4**, 0x9xx→0x424C30 (0xFEF0040/0xFEF002C, 14), **0xAxx→0x424CBC**; **NESSUNA classe 0x7xx** (un id 0x07xx cade nel default d'errore — correzione dell'audit, §7). L'array delle sei tabelle è a 0x3F6CC8.

**Il ciclo completo dell'id 0x3002** (tutti i passaggi byte-exact):

1. **0x242414(id, fn) = register**: cerca l'id in 0x424500 (classe A per `(id & 0x3000) == 0x3000`, classe B per bit14) e memorizza fn a entry+16. Chiamanti: 0x16D9B6 (router 0x16D898, caso 0x3000), 0x1A083E, 0x241E98 (init della famiglia 0x16A) + tail `b.d` 0x23914E.
2. **0x2422e8(id) = ready**: set del bit `(id&0x1F)-1` nella word +0 (classe 0x3xxx) o +2 (0x4xxx) della struct 0x36A6CC; **alla prima registrazione della famiglia** (entrambe le word a zero) registra anche il dispatcher nidificato: `0x16D898(0x610, 0x242488)` → record 0x610 della tabella 0x424B18 (bit 15/15) — e lo abilita con `0x16D7E8(0x610, 0xFF)` → `0x16D5BC` set del bit 15 di 0xFEF0028. Poi `0x242224(id, 1)`.
3. **0x242224(id, flag) = request setter**: classe A → set del bit pending [entry+14] in 0xFED3818 + set/clear del bit enable [entry+15] in 0xFED3814 secondo flag; classe B → solo enable 0xFED3830.
4. **0x242380(id) = unregister**: clear del bit ready; se entrambe le word tornano a zero → `0x16D840(0x610, 0xFF)` + `0x242224(id, 0)`. Chiamanti: 0x15AA14 (dentro MCUCTRL_Task!), 0x16D754, 0x2391A0.

**Quindi la catena runtime che invoca 0x241E5C** (e tramite essa 0x140704):

```
interrupt vettore 6 (kernel dispatch 0x0B3150, iterazione 29)
  → 0x264250  walker tabella 0x424B18 (enable 0xFEF0028 bit15, pending 0xFEF0074 bit15)
      → jl [0x242488]  (callback id 0x610)
          → 0x242488  dispatcher nidificato tabella 0x424500
              classe A: enable 0xFED3814 bit2, pending 0xFED3818 bit2 → jl [0x241E5C] (id 0x3002)
                  → 0x241E5C: v = 0x169870(), SET evento 0x3200002 bit1, jl_s.d [0x392AC0+0x1C] = 0x140704
```

Il trigger del lato 0x6xx (bit 15 di 0xFEF0074) è **hardware o software** (`0x16D4D8(0x610)`; census dei chiamanti del raise generico: {0x16F0F6, 0x2331B4, 0x238B56}). L'arming del lato 0x3002 avviene già all'init (0x241E94 → 0x2422e8(0x3002) → 0x242224(0x3002,1): pending bit2 di 0xFED3818 e enable bit2 di 0xFED3814 settati). Il `jl [r0]` del walker e del dispatcher salvano/ripristinano r1..r6 e, dopo la chiamata, **riscrivono 1<<bitB sulla halfword pending** (semantica W1C: il walker di init 0x263F08 scrive 0xFFFF su tutti i pending; il codice aggiorna la copia locale con `bclr` ed esce quando la pending locale è zero).

## 3. L'init del framework: 0x16D3F0 (chiamato da 0xC5D80)

```
sr 0xfff8,[aux_irq_lev]                       ← abilita interrupt
bl 0x263E24    ← azzera ~18 halfword maschera 0xFEF0xxx
bl 0x263F08    ← scrive 0xFFFF a 0xFEF0050/0xFEF0328/0xFEF0074/0xFEF003C/0xFEF0040/0xFEF0044 (clear W1C)
8 × jl_s.d [r13]  (r13 = pool 0x16d510 = 0x231428 = register_vector):
    vector 4 ← 0x2640E0 (tabella 0x424A00)     vector 5 ← 0x264198 (0x424A8C)
    vector 6 ← 0x264250 (0x424B18, classe 0x6xx)  vector 9 ← 0x264308 (0x424C30)
    vector 2 ← 0x16DAF0                        vector 7 ← 0x2643C0
    vector 8 ← 0x2643E0                       vector 0xA ← 0x264498
trampolini j+limm-ME in RAM bassa (builder 0x16D3D8, opcode j = word pool 0x16D508, basi 0x400 e 0x1400, 8+7 handler 0x265xxx)
flag init [0x367884] = 1
```

0xC5D80 è nello stesso padre che a 0xC5D88 chiama il setup iris 0x140568: il framework viene installato immediatamente prima della catena iris.

## 4. Census e precisazioni

- **PRECISAZIONE all'iterazione 29**: il census bl di 0x231428 = {0x145F80 (TIMER1), 0x29F6A0 (TIMER0)} resta valido per le chiamate dirette, ma le **8 chiamate di 0x16D3F0 sono indirette** (`jl_s.d [r13]`) e a quel census erano invisibili. Il quadro corretto: i vettori 2/4/5/6/7/8/9/0xA sono installati dall'init del framework, e i vettori 0 (TIMER0, iterazione 29) e 7 (TIMER1) hanno installatori aggiuntivi.
- **Vector 7 ha DUE installatori statici**: 0x16D3F0 → 0x2643C0 (walker 0x7xx) e l'arming TIMER1 0x145F80 → 0x146104 (iterazione 29). La precedenza runtime dipende dall'ordine di esecuzione (open point).
- 0x242488 e 0x264250 sono **pointer-only**: zero branch di qualsiasi forma; esistono solo come parole di pool (0x2424a0, 0x16d518).
- Census bl: 0x242224 = {0x242370, 0x242402}; 0x2422E8 = {0x16D74C, 0x1A084E, 0x239188, 0x241EA2}; 0x16D3F0 = {0xC5D80}; 0x16D4D8 = {0x16F0F6, 0x2331B4, 0x238B56}; conteggi: 0x16D898 = 43, 0x16D7E8 = 44, 0x16D840 = 49, 0x16D5BC = 2.
- Le scansioni negative inchiodano i riferimenti: 0x424B18 LE solo {0x16d6d4, 0x16db2c} + limm-ME {0x26426a, 0x264286}; 0x424500 LE solo {0x24225c, 0x242294, 0x2424a4} e zero limm-ME; 0x264250 LE solo pool 0x16d518; 0x231428 LE solo pool 0x16d510.

## 5. Limiti

Statico, nessun hardware/runtime, NON_INSTALLARE, circa 10% invariato. Le halfword 0xFED3xxx/0xFEF0xxx sono MMIO: la semantica W1C del pending è inferenza forte dal pattern (init scrive 0xFFFF = clear-all; il servizio riscrive il bit e azzera la copia locale), non prova elettrica. **Chi alza a runtime** il bit 15 di 0xFEF0074 (hardware del SoC o 0x16D4D8 con id specifici) e il bit 2 di 0xFED3818 non è chiuso: i tre chiamanti di 0x16D4D8 e il blocco MMIO 0xFED3xxx restano da attribuire. La mappa vector→linea hardware è inferenza comportamentale (intvec ARC700 APERTO, come in iterazione 29). La precedenza vector 7 (0x2643C0 vs 0x146104) è order-dependent. I trampolini in RAM bassa (0x400/0x1400) sono descritti, i loro target 0x265xxx non decodificati. V1.1 campione vs macchina V1.0.

## 6. Continuazione

- (a) **Chi alza il pending di 0x3002/0x610 a runtime**: decodificare i tre chiamanti di 0x16D4D8 ({0x16F0F6, 0x2331B4, 0x238B56}) per gli id passati, e cercare scrittori diretti di 0xFED3818/0xFEF0074 (il sito LE 0x1A14A8 = 0xFED3818 è un inizio); attribuire l'evento fisico che pilota il vettore 6.
- (b) In alternativa: il gemello TIMER0/scheduler tick (punto (b) dell'iterazione 29, aperto), ora con la mappa dei vettori del framework nota.

Il punto consumatori-registrazioni/dispatcher-id-0x3002 è **CHIUSO**: non rieseguire i census già fatti.

## 7. Revisione indipendente (agente svc-framework-audit-36, tools.agents.spawn, configurazione ereditata)

L'agente ha riverificato i 12 claim con ELF/finestre proprie in /tmp (sha del firmware e dei blocchi 0/1 ricombacianti col manifest; nessuna scrittura nel progetto). Esito: **claim 1–10 e 12 CONFERMATI** (il 12 come inferenza statica, così etichettato), **claim 11 CONTRADDETTO in parte e corretto**: nel router 0x16D5BC **non esiste la classe 0x0700**; la mappatura corretta delle classi basse è 0x0400→0x424A00, 0x0500→0x424A8C, 0x0600→0x424B18, **0x0800→0x424BA4**, 0x0900→0x424C30, **0x0A00→0x424CBC** (confermata anche dai record: 0x08xx in 0x424BA4, 0x0Axx in 0x424CBC); un id 0x07xx cade nel default d'errore. Il `cmp 0x7000` del router è la classe ALTA 0x7000 (→0x24D388/0x24D3F0). Docstring del verificatore, questo §2 e MDs/AGENTS.md corretti; verificatore rieseguito **PASS 20261022T031030Z post-audit** (nessuna asserzione cambiata: le finestre asserite sul router erano solo i casi 0x3000/0x600, già corretti).

Precisazioni ACCOLTE e integrate:
- **(claim 5)** il set del bit ready in 0x36A6CC è saltato per gli id di confine 0x3000/0x4000; gli id di nessuna classe tornano l'errore di pool 0x242498 senza toccare 0x36A6CC né chiamare 0x242224.
- **(claim 6/7)** il clear W1C del pending avviene ANCHE a fn nullo: un bit pending senza handler viene consumato e perso; il walker esce in anticipo quando la copia locale del pending si azzera (scansione non garantita su tutti i 16 record).
- **(claim 8)** l'azzeramento maschere 0x263E24 conta esattamente 18 sth.di (sei su indirizzi dispari …03); il builder dei trampolini è richiamato 8+8 volte con destinazioni 0x418..0x450 e 0x1418..0x1450; l'installazione del vettore 6 e il flag [0x367884]=1 riverificati byte-exact.
- **(claim 9)** scansione LE: 0x231428 compare SOLO al pool 0x16d510 — nessun altro sito di chiamata indiretta via pool; vector 7 a doppio installatore confermato (0x16D3F0→0x2643C0 con pool 0x16d524, 0x145F80→0x146104 con pool 0x14623C).
- **(claim 10)** i conteggi 43/44/49/2 valgono per le **solo forme bl** (convenzione del census); includendo i tail b/b.d il totale diventa 44/44/51/2 (tail a 0x2331A2 per 0x16D898, 0x16E1AA/0x190CCA per 0x16D840).
- **(claim 12)** l'id 0x3002 nella chiamata 0x242414 proviene dal pool 0x241F7C caricato nel delay slot, non dall'argomento entrante; 0x16D4D8(0x610) alza effettivamente bit15 di 0xFEF0074; l'alternativa "hardware" resta inferenza.
- Osservazioni extra: 0x16D7E8/0x16D898 sono gate su flag [0x367884] e registro identity (cmp 0x13030513); le classi ALTE 0x1000–0xB000 del router usano servizi separati (0x266xxx, 0x24D388/0x24D3F0) non coperti dal quadro "sei tabelle".

Non verificato dall'agente: esecuzione runtime (il claim 12 resta percorso statico, non osservazione); i 44/51 siti dei conteggi sono spot-verificati, non tutti allineati; il valore 0x140704 in [0x392AC0+0x1C] deriva dal checkpoint iterazione 31 già auditato, non riverificato.
