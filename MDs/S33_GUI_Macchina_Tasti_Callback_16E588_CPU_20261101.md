# Callback 0x16E588 della macchina tasti: ponte eventi -> notifiche servizio -> code (CPU, it.52)

**Iterazione 52 — 1° novembre 2026 — PASS_KEY_CALLBACK_16E588_CPU
17/17 x 2 run identiche post-revisione (20261101T223640721789Z /
223659566842Z; sviluppo 16/16 x3: 222904142682Z / 222927910618Z /
223004497779Z) + regressioni 3/3 PASS.** Punto it.51(a): decodifica
della callback reale 0x16E588 (pool 0x16E38C, registrata all'init
0x16E2F4 via 0x16F988 nella tabella callback 0x446A08) e
classificazione dei 19 siti del generatore 0x16F72C. Revisione
indipendente `cb588-review-52` C1..C11: CONFERMATE con 4 precisazioni
integrate (di cui una con nuovo caso CPU: 0xB).

- Verificatore: [s33_verify_key_callback_16e588_cpu.py](../Python_Trace_Scripts/s33_verify_key_callback_16e588_cpu.py)
- Evidenze: [Risultati/GUI_S33/key_callback_16e588_cpu_20261101T223004497779Z/](../Risultati/GUI_S33/key_callback_16e588_cpu_20261101T223004497779Z/)
  (+ run 222904142682Z, 222927910618Z; sviluppo 222320Z..222829Z con
  fault conservati; banco esplorativo tmp/it52/)

## Domanda

It.51 aveva chiuso la macchina tasti 0x16F630..0x16FA00 (mappa
bit->evento) lasciando la callback reale 0x16E588 come stub. Domanda
di questa iterazione: cosa fa la callback del fan-out 0x16F6B0 con
(classe, stato, &evento) e quali eventi sintetizzano i 18+1 siti
esterni del generatore 0x16F72C? È il ponte
macchina tasti -> callback -> anello/code -> dispatcher.

## Decodifica (statica + CPU su byte originali)

Prologo: push blink + bl 0x334124 (millicode push r17..r13) + frame.
r13=classe, r17=stato, r16=&evento; evento r1/r14 = `ldw_s.x` halfword
CON segno da [r16]; r15 = pool 0x16E6D8 = **0x367898** (latch ctx);
pool 0x16E6DC = **0x36726B**.

| Ramo | Condizione | Azione |
|---|---|---|
| Latch8 libero | `byte[0x3678A0]==0` | salto al corpo principale |
| Latch8 + 0x2701 | latch8≠0 ∧ `byte[0x36726B]`≠0 ∧ evento==0x2701 | bl **0x16ED40**, latch8:=0, **return 0** |
| Latch9 set | latch8≠0, latch9==0, `0x16F920(0x4E)`≠0, evento==0x481 | latch9:=1, poi corpo |
| Latch9 clear | latch8≠0, latch9≠0, evento∈[0x80,0x307F], classe∉{0x4E,9} | latch9:=0, poi corpo |
| Latch9 + query9 | latch9≠0, `0x16F920(9)`≠0, evento==0x2701 | bl 0x16ED40, latch8:=0, latch9:=0, **return 0** |
| Gate fail (corpo) | `0xC9BF8()`≠1 ∨ `0x16BC90()`≠0 | `0xC68F0()`, **return 1** (il fan-out inserisce allora l'evento nell'anello 0x17BC7C) |
| Modo 0x15 + slot 0x62 | `0xCAD30()`==0x15 ∧ `0xD0CA4()`==1 ∧ 0<evento≤0x3FFF ∧ (evento&0x3F80)>>7==0x62, cioè evento ∈ [0x3100,0x317F] (revisione; solo 0x3100 è prodotto dalla mappa tasti) | post **(0, 0x4002, 1)** via 0x169EB4, return 0 |
| Inghiottimento | classe ∈ {0x64, 6, 5, **0xE**, 0xB, 0xF} | **return 0 SENZA post** |
| Evento 0x3100 | (fuori modo-0x15) | **0x16F070(1)**, return 0 |
| Corpo normale | altro | post **(0, 0x4006, classe)**, `0xC68F0()`, se `0xCB618()`≠0 ∧ evento≠0x3101 → repost **(0, evento, stato)**; return 0 |

Epilogo unico 0x16E6CC: mov sp,fp; ld.ab fp; b 0x334184 (pop+blink).
Getter modo ORIGINALE 0xCAD30 (byte 0xC8E80C via pool ld.as 0xCAAC4,
regola EA (PC&~3)+imm*4 con PC≡0 mod 4 eseguita in CPU) e query
ORIGINALE 0x16F920 (byte[0x446808+4*classe], classi <0x61).

## Scoperte

1. **PONTE GUI**: la callback converte ogni tasto fisico accettato in
   (a) una notifica di servizio **(0, 0x4006, classe)** — il reattore
   p1 0x20F414 (it.21) riceve come arg la CLASSE del tasto — e (b), se
   il gate 0xCB618 lo consente, un repost **(0, evento, stato)** nella
   coda 0x169EB4. I gate 0xC9BF8/0x16BC90 falliti producono return 1:
   il fan-out 0x16F6B0 (it.51) inserisce allora l'evento GREZZO
   nell'anello 0x17BC7C (percorso raw di zoom it.48-49).
2. **LISTA INGHIOTTIMENTO = {0x64, 6, 5, 0xE, 0xB, 0xF}**: 0xE è la
   classe 14, cioè il **pulsante 0x700/0x701 (SLOT AKERUOS 2)**, e
   0xB è la classe 11, cioè il **pulsante 0x580/0x581 (SLOT AKERUOS
   1)** (correzione revisione cb588-review-52, caso CPU dedicato
   swallow_class_0xb_580); 0x64 è la classe 100 (evento repeat
   0x3200/0x3201). Per questi la callback non posta nulla e return 0:
   il fan-out fa short-circuit al primo esito 0, quindi niente anello
   né callback successive. **Dei 4 slot AkeruOS: 0x580 e 0x700 sono
   INGHIOTTITI, 0x2180 (classe 67) passa interamente, 0x2700 (classe
   0x4E=78) passa ma è protetto dal latch.** NOTA: questo riguarda
   solo la callback; gli eventi 0x580/0x700 potrebbero raggiungere le
   finestre per altre vie (produttori diretti 0x169EB4 censiti
   it.19/46, iniezione ASCII p4 0x80BC7C, seconda callback 0x323A00
   NON decodificata, ordine slot tabella 0x446A08 runtime APERTO).
3. **LATCH 0x367898 con classi protette**: byte[+8]/byte[+9] formano un
   latch a due stadi; le classi {0x4E, 9} non cancellano latch9 —
   0x4E = 78 = **pulsante 0x2700/0x2701 (SLOT AKERUOS 4)**. Nel dump a
   riposo: **latch8=1, latch9=0, byte[0x36726B]=0, word[0x367898]=1,
   byte[0x3678A2]=1** (payload 1). 0x16ED40 è chiamata SOLO da questa
   callback (2 bl).
4. **Modo 0x15 + 0xD0CA4 + evento 0x3100 (slot id 0x62)** posta
   **(0, 0x4002, 1)** — non 0x4006 (correzione in corsa provata in CPU:
   mov r1,2; bset bit14). 0x4002 ha 29 produttori bset bit14 (it.46).
5. **19 siti generatore 0x16F72C classificati** (censimento it.51
   riverificato): 0x144A82 (classe 0x77 dopo switch su 0xD18FC con
   casi 0x55/0x58/0xA3/0xC2 e gate 0x210BE4()) e diciassette siti
   nella famiglia 0x16E8A6..0x16F176 con classi
   1,2,0x77 / 1,2 / 1,1,2 / dinamica / 0xC / 0x62 / 0x66,0x65,0x65 /
   0x77,0x65,0x77 — cioè la **libreria dei tasti virtuali** che
   sintetizza gli eventi 0x80/0x81, 0x100/0x101, 0x600/0x601,
   0x3100/0x3101, 0x3280/0x3281, 0x3300/0x3301, 0x3B80/0x3B81 — tutti
   con idx=0xFF TRANNE lo scanner fisico 0x16F8D4 (idx reale del
   descrittore); 0x16EC28 ha classe dinamica ma idx=0xFF (precisazione
   it.54 sulla revisione cb588-review-52: sedici -> diciassette). L'init della famiglia
   0x16E838 arma timer 0x14905C(0x3678DB, 0xFFFF9007, 500, 0, 0x16F124)
   e usa 0x1491B8, 0x140678, 0x16EB80, 0x16D898/0x16D7E8, 0x17B5D4/EC.
6. **Query 0x16F920 per classi ≥ 0x61**: il blocco 0x16F928..0x16F94C
   (lettura idx da record, halfword desc flag via 0x3678E8, bit15) è
   staticamente IRAGGIUNGIBILE dall'entry 0x16F920 (nessun ramo al
   0x16F928 nel listato): possibile entry alternativa o codice morto,
   APERTO.

## Casi CPU (17, byte originali 0x16E588..0x16E6E0)

gate_c9bf8_fail, gate_bc90_fail (return 1 + 0xC68F0, nessun post),
main_post_repost (classe 78: (0,0x4006,78)+(0,0x2700,1)),
main_post_cb618_zero, main_post_3101_norepost (post 0x4006 senza
repost), swallow_class_0x64, **swallow_class_0xe_700** (classe 14:
nessun post), **swallow_class_0xb_580** (classe 11: nessun post,
aggiunto dopo revisione), event_3100_f070 (0x16F070(1)),
mode15_3100_post4006_arg1 → **(0,0x4002,1)**, mode15_d0ca4_fail_f070,
latch8_2701_ed40, latch9_set_on_481, latch9_clear_normal (classe 67:
latch9 azzerato + repost), latch9_query9_2701_ed40,
latch9_query9_zero_main (latch9 intatto),
latch8_zero_skips_latch9 (negativo: latch9 non toccato). Fault
0xDEADB001..0x11. Finestre ORIGINALI: .cb 0x16E588..0x16E6E0, .kmach
0x16F630..0x16FA60, .modeget 0xCAD30..0xCAD38 + .modepool
0xCAAC0..0xCAAD0, millicode. Stub con log: 0xC9BF8, 0x16BC90,
0xD0CA4, 0xC68F0, 0xCB618 (ritorno da cella), 0x169EB4, 0x16ED40,
0x16F070. RAM sintetiche: latch 0x367898/0x36726B, cella modo
0xC8E80C, record tasti 0x446808 (gap dump).

## Comandi eseguiti (exit code verificato, senza pipe)

- `timeout 280 python3 Python_Trace_Scripts/s33_verify_key_callback_16e588_cpu.py` → PASS RC=0: sviluppo 16/16 x3 (222904142682Z, 222927910618Z, 223004497779Z) + 17/17 x2 post-revisione (223640721789Z, 223659566842Z, evidenze identiche tranne utc; sviluppo 222320Z..222905Z con fault conservati)
- Regressioni (tutte RC=0): `s33_verify_key_machine_static_map_cpu.py` → PASS 20261101T223033016884Z; `s33_verify_event_router_producers_cpu.py` → PASS 20261101T223038970630Z; `s33_verify_snapshot_capture_record_init_cpu.py` → PASS 4/4 20261101T223046521351Z

## Revisione indipendente (cb588-review-52)

Revisione statica ex-novo (censimenti propri su listato + byte-level
sui 16 payload, nessun verificatore eseguito; appunti
tmp/it52/it52_revisione_C1_C11.md): **C1..C8, C10, C11 CONFERMATE**,
C9 PARZIALE (l'elenco classi nel testo del claim era incompleto, la
classificazione congelata nel verificatore GEN_SITES era corretta e
corrisponde alla sequenza reale dei 17 siti famiglia:
1,2,0x77,1,2,1,1,2,din(0x16EC28),0xC,0x62,0x66,0x65,0x65,0x77,0x65,
0x77 + 0x144A82 classe 0x77). Precisazioni INTEGRATE:
1. **0xB = classe 11 = pulsante 0x580/0x581 SLOT AKERUOS 1** nella
   lista inghiottimento (nuovo caso CPU swallow_class_0xb_580); classi
   mappa tasti silenziosamente inghiottite: 11, 14, 100.
2. Slot 0x62 ⟺ evento ∈ [0x3100,0x317F] con guardia 0<evento≤0x3FFF.
3. **Semantica fan-out condizionata**: return 1 NON basta per
   l'anello; 0x16F6B0 inserisce (0,evento,r19,1) in 0x17BC7C solo se
   byte[0x3678F9]≠0 (a riposo 1), arg r4≠0 e bit0 di
   halfword[0x446808+4*classe+2] (0x16F6A4, settabile via 0x16F950);
   return 0 di UN callback ferma la catena e r0 è il verdetto
   dell'ULTIMO callback invocato. "Return 1 → anello" vale solo
   condizionato.
4. 0x16F988 registra nella PRIMA CELLA LIBERA della tabella 10
   (0x16F9C8..0x16F9DE): l'indice di 0x16E588 è runtime, non fisso.
   Nessuna LE di 0x16ED40/0x16F070 nei payload (nessun caller
   indiretto). 0x16F920 legge byte[record+0] (stato), confermato.

## Controlli negativi e statici

- Census bl congelati: 0x16E588 = 0 chiamanti (callback pura);
  0x16ED40 = {0x16E5B8, 0x16E616}; 0x16F070 = {0x16E692, 0x16ECEC,
  0x16EE26}; 0x169EB4 nella finestra callback = 3 siti
  {0x16E668, 0x16E6A0, 0x16E6BE}; 19 siti 0x16F72C riverificati con
  carichi classe costante entro 0x18 byte prima di ogni bl e idx 0xFF
  in 18/19 (solo 0x16F8D4 no).
- Pool words dal dump: 0x16E6D8=0x367898, 0x16E6DC=0x36726B,
  0xCAAC4=0xC8E80C, 0x16FA34=0x446808.
- LE scan 16 payload: 0x0016E588 solo (0, 0x16E38C).
- Celle latch a riposo lette dal payload 1 e congelate nel JSON.

## Limiti e non dimostrato

- Gate 0xC9BF8/0x16BC90/0xD0CA4/0xC68F0/0xCB618, post 0x169EB4,
  0x16ED40, 0x16F070: STUB con log, comportamento reale NON provato
  qui (chi li produce/a cosa servono resta aperto).
- Il fan-out 0x16F6B0, la seconda callback 0x323A00, l'ordine degli
  slot nella tabella 0x446A08 (runtime) e il percorso degli eventi
  0x700 dopo lo swallow NON sono eseguiti qui.
- RAM runtime (latch, record, cella modo) sintetica nei casi CPU; solo
  i valori a riposo nel dump sono fatti verificati.
- Classi 6/5/0xB/0xF della lista inghiottimento non presenti nella
  mappa 16 tasti it.51 (classi sintetiche della libreria virtuale).
- Nessuna prova hardware, USB, SD, flash; NON_INSTALLARE. Progresso
  funzionale ~10% invariato.

## Prossimo passo (non ripetitivo)

(a) Decodifica della **seconda callback 0x323A00** (0x323856, tabella
0x446A08: ordine short-circuit) per capire chi gestisce gli eventi
inghiottiti dalla prima (in particolare 0x700/0x701); (b) decodifica di
**0x16ED40** (latch clear, chiamata solo qui) e dell'init famiglia
0x16E838 (timer 0xFFFF9007, libreria tasti virtuali); (c) alternativa
it.51(b): census lettori 0x554628/0x22C434 per bit→GPIO.
