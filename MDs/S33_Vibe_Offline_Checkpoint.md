## Iterazione 54 — 1° novembre 2026 — LATCH TARGETS CHIUSI: 0x16ED40 = SCRITTORE `\MEMDUMP.BIN`, 0x16F070 = ARM/DISARM GATE RING PER 15 CLASSI (punto it.52(a), con correzione C9 rapporti it.51/52): PASS_KEY_LATCH_TARGETS_16ED40_16F070_CPU 10/10 x2 run identiche (230012935673Z/230019521884Z) + regressioni 4/4 + revisione indipendente C1..C10 tutte CONFERMATE — byte[0x367898] (latch0) ha writer 0x16F086 e reader 0x16EE1E; produttore della cella trigger 0x36726B = match `"B:\DumpHint"` (0x1592E6)

**Domanda affrontata.** Punto aperto it.52 (dopo revisione
cb588-review-52): decodifica delle due funzioni chiamate dalla
callback tasti 0x16E588 e non ancora decodificate — 0x16ED40 (2
sole bl al mondo, entrambe nei path latch con evento 0x2701) e
0x16F070 (sito 0x16E692 per evento 0x3100 + 2 siti famiglia) — più
la correzione della documentazione C9 nei rapporti it.51/it.52.

**Risultato verificabile e significato.** [Rapporto](S33_GUI_Memdump_Latch_0x16ED40_RingArm_0x16F070_CPU_20261101.md),
[verificatore](../Python_Trace_Scripts/s33_verify_key_latch_targets_16ed40_16f070_cpu.py),
[evidenze](../Risultati/GUI_S33/key_latch_targets_cpu_20261101T230012935673Z/)
(+ run identica `..._230019521884Z/`; sviluppo 225751Z..230000Z con
fault conservati). **PASS_KEY_LATCH_TARGETS_16ED40_16F070_CPU
20261101T230012935673Z**, 10 casi CPU su byte ORIGINALI (motore
pinnato GNU ARC700), 2 run identiche (confronto ricorsivo tranne
utc), fault 0xDEADB001..0x00B.

1. **0x16ED40 È LO SCRITTORE DI DUMP `\MEMDUMP.BIN`** (pool
   0x16EDCC=0x34848C, stringa ASCII nel dump): frame 276 byte;
   bl 0xCB5E4 (ritorno scartato); 0x12B0DC(buf); 0x32DE00(buf,
   "\MEMDUMP.BIN"); 0xAD920(fp-0x20,0,256); 0x12BD5C(buf,fp-0x20,
   256,1) e se ritorna 0 secondo tentativo 0x12BD5C(buf,256,
   0x104064C,1); bl 0xCB5B0 (ritorno scartato); cmp r13 (ritorno
   dell'ULTIMO 0x12BD5C): ==0 → 0x1567F8(0x64,0x64,"Write ok!" a
   0x393044), !=0 → 0x1567F8(0x64,0x64,"Write fail %X" a 0x39304E,
   r13). Argomento r0 in ingresso MORTO. Trigger: latch8 ∧
   byte[0x36726B]≠0 ∧ evento 0x2701, oppure latch9 ∧ query(9)≠0 ∧
   evento 0x2701 (entrambi i siti solo nella callback). Il
   PRODUTTORE della cella 0x36726B è 0x1592E6 dopo match della
   stringa "B:\DumpHint" (0x1592B0, log "UIMgr task freeze %d
   seconds"): un file di servizio sul supporto ARMA il trigger
   (revisione, statica). NESSUN dump eseguito: NON_INSTALLARE,
   niente scritture SD.
2. **0x16F070(arg) = ARM/DISARM DEL GATE RING** per le 15 classi
   {1,2,5,6,7,8,9,0xA,0xB,0xC,0xE,0xF,0x43,3,0x4E} — I QUATTRO SLOT
   AKERUOS 11/14/67/78 INCLUSI: byte[0x367898] := arg (pool
   0x16F0E4; writer UNICO 0x16F086, reader 0x16EE1E guardia del
   re-arm, a riposo =1 nel dump) + 15 jl_s [0x16F950] (pool
   0x16F0E8) con (classe,arg). **0x16F950(classe,flag) provata
   REALE in CPU (leaf, 0 bl): set/clear bit0 di
   halfword[0x446808+4·classe+2]** — il bit richiesto dal fan-out
   0x16F6B0 (via 0x16F6A4) per inserire l'evento nell'anello
   0x17BC7C. Chain CPU: callback reale (98,1,0x3100) modo 0x2C →
   0x16F070(1) → 0x16F950 reali: 15 record bit0=1 con bit1
   preservato, classi fuori lista intatte. Chain MEMDUMP: latch8
   → 0x16ED40 reale → "Write ok!"; latch9 → fail con codice in r3.
3. **CENSIMENTI**: bl 0x16ED40={0x16E5B8,0x16E616}, bl 0x16F070=
   {0x16E692, 0x16ECEC (r14:=0 statico), 0x16EE26 (guardia
   byte[0x367898]==0)}, bl 0x16F950=7 (it.51); NESSUNA LE di
   0x16ED40/0x16F070 nei 16 blocchi; LE 0x0016F950=6 TUTTE pool
   jl_s vivi: 0x16F0E8 + **secondo dispatcher 0x135AC0 (classi
   F070_IDS SENZA 0x4E, non scrive 0x367898)** + 4 p2
   (0x6403B4/0x6430C0/0x658998/0x65D2A0, disarm con classi extra
   0x4/0x10/0x12): il dominio classi di 0x16F950 è sovra-insieme
   di F070_IDS. A riposo: latch0=1, latch8=1, latch9=0,
   0x36726B=0.
4. **CORREZIONE C9 APPLICATA** (revisione cb588-review-52):
   rapporto it.51 «18 siti nella famiglia»→17+scanner e «19
   chiamanti fuori dallo scanner»→18; rapporto it.52 «sedici
   siti»→«diciassette», «TRANNE 0x16EC28 (classe dinamica, idx
   0xFF)»→unica eccezione idx = scanner 0x16F8D4; checkpoint
   «16 siti famiglia»→17.

**Fonti, comandi, fixture, negativi.** Comandi (senza pipe, exit code
verificato): `timeout 280 python3
Python_Trace_Scripts/s33_verify_key_latch_targets_16ed40_16f070_cpu.py`
→ PASS 10/10 RC=0 x2; regressioni RC=0: key machine
**20261101T230029873922Z** (9/9), event router
**20261101T230037990722Z**, snapshot init
**20261101T230130218178Z** (4/4), key callback 16e588 (it.52)
**20261101T230130979685Z** (17/17). Finestre ORIGINALI con SHA
congelati: .cb, .ed40 (0x16ED40..0x16EDDC incluse le pool),
.f070 (0x16F070..0x16F0EC incluse le pool), .f950+
.f950pool (0x16FA34=0x446808), .epi 0x16EE68, .kmach, .modeget/
.modepool, millicode. Pool asserite:
0x16EDCC/0x16EDD0/0x16EDD4/0x16EDD8/0x16F0E4/0x16F0E8/0x16FA34.
Stringhe nel dump asserite: "\MEMDUMP.BIN", "Write ok!",
"Write fail %X". NESSUN pipe: fault marker per-assert. Fixture/
assunzioni: RAM sintetiche latch 0x367898/0x3678A0/A1, 0x36726B,
mode 0xC8E80C, record 0x446808 (gap dump); callee I/O di 0x16ED40
stub con log; ASSUNZIONE (a) 0xCB5B0 preserva r13 (alternativa (b)
APERTA: micro-test tmp/it54/micro_cb5b0_20261101T235432/, traccia
t5b0.trace: layout reale 0xCB5B0 push_s blink/ld.as 0xCB5B2,
dispatchee stato0 0x16BBB8, tail b 0xCA384 NON risolto; pool word
0xCB4A8=0xF00017FC da confermare).

**Limiti e non dimostrato.** Comportamento reale dei callee I/O
(0xCB5E4/0x12B0DC/0x32DE00/0xAD920/0x12BD5C/0xCB5B0/0x1567F8) NON
provato (stub); contenuto/dimensione del dump e filesystem NON
dimostrati (solo la STRUTTURA); (a)/(b) su r13 aperta; 0x104064C
non classificato (fuori dai blocchi dumpati); match "B:\DumpHint" e
dispatcher 0x135AC0 solo statici; fan-out 0x16F6B0, callback
0x323A00, concorrenza/ISR NON eseguiti; nessuna prova hardware,
nessuna scrittura SD, NESSUN dump eseguito; NON_INSTALLARE.
Progresso funzionale circa 10% invariato.

**Agenti.** `latch-targets-review-54` (revisione indipendente ex-novo
C1..C10, censimenti propri su listato + byte dei 16 blocchi, script
tmp/it54/rev_scan_54.py, appunti tmp/it54/review_latch_targets_54.md
copiati in
[Risultati/GUI_S33/key_latch_targets_agent_review_54_20261101.md](../Risultati/GUI_S33/key_latch_targets_agent_review_54_20261101.md),
PMB outbox 409; verificatore NON eseguito dall'agente): **C1..C10
TUTTE CONFERMATE** byte-level, zero controesempi invalidanti.
Precisazioni INTEGRATE nel rapporto: 0x16ECEC r14 statico 0; LE
0x16F950 tutte pool jl_s vivi (secondo dispatcher 0x135AC0 + 4
call-site p2); produttore byte[0x36726B] = 0x1592E6 (match
"B:\DumpHint"); reader byte[0x367898] = 0x16EE1E.

**Strumenti/MCP.** PMB pmb-nikon: prepare + record_batch; agente
independente latch-targets-review-54; motore pinnato GNU ARC700 via
s33_run_gnu_arc700; micro-test esplorativo podman diretto (traccia
t5b0.trace). REA non usato (decodifica coperta da listato GNU
allineato + CPU).

**Prossimo passo (non ripetitivo).** (a) getter 0xCB5B0/0xCB5E4
complete in CPU (finestra pool 0xCB4A0..0xCB5B0 con word 0xF00017FC
+ tail 0xCA384/0xCA318 + dispatchee 0x16BBB8/0x17FBFC/0x180900):
chiude (a)/(b) su r13 e identifica la cella di modalità 0xCB5xx;
(b) seconda callback 0x323A00 (it.52(a)); (c) produttore
"B:\DumpHint" 0x1592B0 e secondo dispatcher 0x135AC0 in CPU.

## Iterazione 52 — 1° novembre 2026 — CALLBACK 0x16E588 DELLA MACCHINA TASTI CHIUSA (punto it.51(a)): PASS_KEY_CALLBACK_16E588_CPU 17/17 x2 run identiche post-revisione (223640721789Z/223659566842Z; sviluppo 16/16 x3 222904Z/222927Z/223004Z) + regressioni 3/3 — ponte eventi->0x4006(classe)->reattore p1 e repost (0,evento,stato) via 0x169EB4; lista inghiottimento {0x64,6,5,0xE,0xB,0xF} con 0xE=CLASSE 14=PULSANTE 0x700/0x701 SLOT AKERUOS 2 e 0xB=CLASSE 11=PULSANTE 0x580/0x581 SLOT AKERUOS 1 (correzione revisione, caso CPU dedicato); latch 0x367898 con classi protette {0x4E=78=0x2700, 9}; 19 siti generatore classificati (libreria tasti virtuali idx 0xFF)

**Domanda affrontata.** Punto (a) dell'it.51: decodifica della
callback reale 0x16E588 (pool 0x16E38C, registrata all'init 0x16E2F4
via 0x16F988 nella tabella 0x446A08; zero bl chiamanti, unica LE
(0, 0x16E38C)) e dei suoi 18+1 siti generatore 0x16F72C. È il ponte
macchina tasti -> callback -> anello/code -> dispatcher.

**Risultato verificabile e significato.** [Rapporto](S33_GUI_Macchina_Tasti_Callback_16E588_CPU_20261101.md),
[verificatore](../Python_Trace_Scripts/s33_verify_key_callback_16e588_cpu.py),
[evidenze](../Risultati/GUI_S33/key_callback_16e588_cpu_20261101T223659566842Z/)
(+ run identica 223640721789Z; sviluppo 16/16 x3
222904142682Z/222927910618Z/223004497779Z con fault conservati
222320Z..222905Z; banco esplorativo tmp/it52/).
**PASS_KEY_CALLBACK_16E588_CPU 20261101T223659566842Z**, 17 casi CPU
su byte ORIGINALI (motore pinnato GNU ARC700), 2 run finali identiche
(confronto ricorsivo tranne utc), fault 0xDEADB001..0x11.

DECODIFICA (finestra .cb 0x16E588..0x16E6E0 originale; query 0x16F920
e getter modo 0xCAD30 ORIGINALI; latch ctx pool 0x16E6D8=0x367898,
cella pool 0x16E6DC=0x36726B; evento `ldw_s.x` halfword con segno):
- ingresso (classe, stato, &evento) dal fan-out 0x16F6B0; byte[0x3678A0]
  (latch8)==0 -> corpo; latch8!=0 ∧ byte[0x36726B]!=0 ∧ evento 0x2701
  -> bl 0x16ED40 (uniche 2 bl al mondo: 0x16E5B8/0x16E616, dentro
  questa callback) + latch8:=0 + return 0;
- latch9: se 0x16F920(0x4E)!=0 ∧ evento 0x481 -> latch9:=1; se latch9!=0
  ∧ evento∈[0x80,0x307F] ∧ classe∉{0x4E,9} -> latch9:=0; se latch9
  resta ∧ 0x16F920(9)!=0 ∧ evento 0x2701 -> 0x16ED40 + latch8:=0 +
  latch9:=0 + return 0;
- corpo: 0xC9BF8()!=1 ∨ 0x16BC90()!=0 -> 0xC68F0() + **return 1**
  (il fan-out inserisce l'evento GREZZO nell'anello 0x17BC7C, it.51);
  modo 0xCAD30()==0x15 ∧ 0xD0CA4()==1 ∧ slot=(evento&0x3F80)>>7==0x62
  (evento 0x3100) -> post **(0, 0x4002, 1)** via 0x169EB4 + return 0
  (correzione in corsa: mov r1,2|bit14, NON 0x4006; 0x4002 ha 29
  produttori bit14 it.46);
- classe ∈ {0x64,6,5,**0xE**,**0xB**,0xF} -> return 0 SENZA post:
  **0xE = classe 14 = pulsante 0x700/0x701 SLOT AKERUOS 2 e 0xB =
  classe 11 = pulsante 0x580/0x581 SLOT AKERUOS 1 INGHIOTTITI dalla
  callback** (e 0x64 = classe 100 = repeat 0x3200/0x3201); DEI 4 SLOT
  AKERUOS: 0x580 e 0x700 INGHIOTTITI, 67 (0x2180) PASSA, 78 (0x2700)
  PASSA ma protetto dal latch;
- evento 0x3100 -> 0x16F070(1) + return 0; altrimenti post
  **(0, 0x4006, classe)** — il reattore p1 0x20F414 (it.21) riceve la
  CLASSE del tasto come arg — + 0xC68F0() + gate 0xCB618()!=0 ∧
  evento!=0x3101 -> repost **(0, evento, stato)** via 0x169EB4;
  sempre return 0 dal corpo (epilogo unico b 0x334184).
- 19 SITI GENERATORE 0x16F72C classificati (censimento it.51
  riverificato con carichi classe entro 0x18 byte e idx 0xFF in 18/19):
  0x144A82 (classe 0x77 dopo switch 0xD18FC casi 0x55/0x58/0xA3/0xC2,
  gate 0x210BE4()) + 17 siti famiglia 0x16E8A6..0x16F176 con classi
  1,2,0x77/1,2/1,1,2/dinamica 0x16EC28 (idx 0xFF)/0xC/0x62/
  0x66,0x65,0x65/0x77,0x65,0x77 = **libreria TASTI VIRTUALI** che
  sintetizza 0x80/0x81, 0x100/0x101, 0x600/0x601, 0x3100/0x3101,
  0x3280/0x3281, 0x3300/0x3301, 0x3B80/0x3B81; init famiglia 0x16E838
  arma timer 0x14905C(0x3678DB, 0xFFFF9007, 500, 0, 0x16F124) e usa
  0x1491B8/0x140678/0x16EB80/0x16D898/0x16D7E8/0x17B5D4/0x17B5EC;
  0x16F8D4 = scanner fisico (idx reale). PUNTO APERTO: blocco
  0x16F928..0x16F94C della query (classi >= 0x61, halfword flag desc
  via 0x3678E8, bit15) irraggiungibile dall'entry 0x16F920.
- DUMP A RIPOSO (payload 1): latch8=1, latch9=0, byte[0x36726B]=0,
  word[0x367898]=1, byte[0x3678A2]=1.

**Fonti, comandi, fixture, negativi.** Comandi (exit code verificato,
senza pipe): `timeout 280 python3
Python_Trace_Scripts/s33_verify_key_callback_16e588_cpu.py` -> PASS
16/16 RC=0 x3 sviluppo e 17/17 RC=0 x2 post-revisione
(223640721789Z, 223659566842Z); regressioni tutte RC=0:
`s33_verify_key_machine_static_map_cpu.py` PASS 20261101T223033016884Z,
`s33_verify_event_router_producers_cpu.py` PASS 20261101T223038970630Z,
`s33_verify_snapshot_capture_record_init_cpu.py` PASS 4/4
20261101T223046521351Z. Finestre ORIGINALI .cb/.kmach/.modeget/
.modepool/millicode con SHA congelati nel JSON; census bl 0x16E588=0,
0x16ED40={0x16E5B8,0x16E616}, 0x16F070={0x16E692,0x16ECEC,0x16EE26},
0x169EB4 nella finestra={0x16E668,0x16E6A0,0x16E6BE}; pool words
0x16E6D8/0x16E6DC/0xCAAC4/0x16FA34; LE scan 0x16E588=(0,0x16E38C).
Casi negativi: latch8_zero_skips_latch9 (latch9 non toccato),
main_post_3101_norepost, swallow_class_0xe_700 (nessun post),
latch9_query9_zero_main (latch9 intatto), gate fail (return 1).
Fixture/assunzioni: RAM sintetiche latch 0x367898/0x36726B, cella modo
0xC8E80C, record tasti 0x446808 (gap dump); gate/post/0x16ED40/
0x16F070 stub con log e ritorno da cella.

**Limiti e non dimostrato.** Comportamento reale di gate
(0xC9BF8/0x16BC90/0xD0CA4/0xC68F0/0xCB618), 0x169EB4, 0x16ED40,
0x16F070 NON provato (stub); fan-out 0x16F6B0, seconda callback
0x323A00, ordine slot tabella 0x446A08 e destino degli eventi 0x700
dopo lo swallow NON eseguiti (produttori alternativi censiti it.19/46:
possibile arrivo via 0x169EB4 diretti o iniezione ASCII p4); concorrenza
e contesto runtime aperti; nessuna prova hardware/USB/SD/flash;
NON_INSTALLARE. Circa 10% invariato.

**Agenti.** `cb588-review-52` (revisione indipendente ex-novo C1..C11,
censimenti propri su listato + byte-level 16 payload, NESSUN
verificatore eseguito, appunti tmp/it52/it52_revisione_C1_C11.md):
C1..C8, C10, C11 CONFERMATE; C9 PARZIALE (elenco classi nel testo del
claim incompleto: 0x16E8F6 classe 0x77, 0x16EA94 classe 1, 0x16EAD4
classe 2 — la classificazione congelata nel verificatore GEN_SITES era
GIA' corretta e passata). Precisazioni INTEGRATE: (1) **0xB = classe
11 = pulsante 0x580/0x581 SLOT AKERUOS 1** nella lista inghiottimento
— nuovo caso CPU swallow_class_0xb_580 17/17, classi mappa inghiottite
11/14/100; (2) slot 0x62 ⟺ evento ∈ [0x3100,0x317F] con guardia
0<evento≤0x3FFF; (3) semantica fan-out CONDIZIONATA: return 1 non
basta per l'anello (serve anche byte[0x3678F9]≠0, r4≠0, bit0
halfword[record+2] via 0x16F6A4/0x16F950; return 0 ferma la catena; r0
= verdetto ultimo callback); (4) 0x16F988 registra nella PRIMA CELLA
LIBERA della tabella 10 (0x16F9C8..0x16F9DE): indice runtime. Nessuna
LE di 0x16ED40/0x16F070 (nessun caller indiretto).

**Strumenti/MCP.** PMB pmb-nikon: prepare + record_batch; agente
explore cb588-review-52; motore pinnato GNU ARC700 via s33_run_gnu_arc700.
REA non usato (decodifica coperta da listato GNU congelato + CPU).

**Prossimo passo (non ripetitivo).** (a) seconda callback 0x323A00
(0x323856: ordine tabella 0x446A08 e gestione degli eventi inghiottiti,
in particolare 0x700/0x701); (b) 0x16ED40 + init famiglia 0x16E838
(timer 0xFFFF9007); (c) alternativa it.51(b): census lettori
0x554628/0x22C434 bit->GPIO.

## Iterazione 51 — 1° novembre 2026 — MACCHINA TASTI p0 0x16F630..0x16FA00 CHIUSA (recupero it.50 interrotta, punto it.49(a)): PASS_KEY_MACHINE_STATIC_MAP_CPU 9/9 x3 run identiche (it.50: 215644087341Z/215656312452Z; it.51: 220850417476Z, confronto ricorsivo identico tranne utc) + regressioni 2/2 + revisione indipendente C1..C10 tutte CONFERMATE

**Domanda affrontata.** Punto (a) dell'it.49: decodifica della macchina
tasti a monte del fan-out 0x16F6B0 («produttore FISICO APERTO»). La
it.50 aveva verificatore PASS 9/9 x2 ed evidenze complete ma la sessione
è stata interrotta (log round_000050/console.log: wait annullata mentre
l'agente di revisione non era ancora tornato). It.51: riesecuzione
identica del verificatore, revisione indipendente completata, rapporto
scritto, checkpoint aggiornati.

**Risultato verificabile e significato.** [Rapporto](S33_GUI_Macchina_Tasti_0x16F630_Mappa_Bit_Evento_CPU_20261101.md),
[verificatore](../Python_Trace_Scripts/s33_verify_key_machine_static_map_cpu.py),
[evidenze](../Risultati/GUI_S33/key_machine_static_map_cpu_20261101T220850417476Z/)
(+ coppia it.50 `..._215644087341Z/`, `..._215656312452Z/`; sviluppo
214652Z..215532Z con fault conservati). **PASS_KEY_MACHINE_STATIC_MAP_CPU
20261101T220850417476Z**, 9 casi CPU su byte ORIGINALI (motore pinnato
GNU ARC700): install_sync, press_700_query, release_701,
zoom_pair_380_400, repeat_98_arm_cancel, no_change_negative,
ring_gated_press, ec38_runtime_entry, slot_map_all_four; fault
0xDEADB001..09. SHA tabella descrittori 0x392F04 =
b70d04c2fddac5f1e10101d96e9a8d03c30a861d22bc9621cca448d92c675c1f.

SCOPERTA CENTRALE — **mappa bit dell'ingresso fisico a 64 bit ->
evento**, 16 tasti, byte del dump a 0x392F04 (16 record stride 20,
delimitati, NESSUNA classe mancante, revisione): INSTALLER 0x16F66C
(unico bl 0x16E306, r0=pool 0x16E388=0x392F04, r1=0x10) scrive
byte[0x446808+4*classe+1]=indice e ctx 0x3678E4 {+0 abilitato, +4 base,
+8 count, +0xA scanner-armato 0x3678EE, +0xC/+0x10 stato 64-bit
0x3678F0/F4}; SCANNER 0x16F86C(lo,hi,genera) XOR-ctx -> shift-right 64
0x335C4C -> GENERATORE 0x16F72C(idx,classe,stato,flag): classi <0x61
stato1->classe<<7, stato0->(classe<<7)|1, trigger 0x17C150({press,release},2,1);
REPEAT classi>=0x61 con press_ev: arm 0x14905C(0x3678F8, idx, press_ev,
0, 0x16FA64) + bit15 flag, evento |1 SOLO dal callback timer 0x16FA64
(revisione); CLASSE 106 (bit30, flag 0, press_ev 0) OGNI trigger posta
ENTRAMBI 0x3500/0x3501 (revisione); SYNC 0x16F8EC complemento TRANSITORIO
+ genera=0 (nessun evento); QUERY 0x16F920(classe)=byte[0x446808+4*classe]
521 bl + 1 tail b.d 0x31DD54; FAN-OUT 0x16F6B0: 10 callback 0x446A08+4i
(SHORT-CIRCUIT al primo esito 0) con (classe,stato,&evento), gate
byte[0x3678F9] (a riposo nel dump = 0x01; 56 bl + 2 tail-b a 0x16F964)
-> inserisce (0,evento,r3arg,1) nell'anello 0x17BC7C: **il produttore
fisico di it.49 è questa macchina**. Callback registrate: 0x16E588
(init 0x16E2F4 via 0x16F988) + 0x323A00 (0x323856, revisione).
MAPPA: bit20 cl7 -> 0x380/0x381, bit16 cl8 -> 0x400/0x401, bit21 cl9 ->
0x480/0x481, bit15 cl10 -> 0x500/0x501, bit31 cl98 -> 0x3100 repeat 500ms,
bit3 cl3 -> 0x180/0x181, **bit12 cl11 -> 0x580/0x581, bit7 cl14 ->
0x700/0x701, bit8 cl67 -> 0x2180/0x2181, bit13 cl78 -> 0x2700/0x2701
(i quattro slot AkeruOS, prova simultanea slot_map_all_four)**, bit30
cl106 -> 0x3500+0x3501, bit35 cl102 -> 0x3300 repeat 300ms, bit60 cl99
-> 0x3180 repeat 300, bit61 cl101 -> 0x3280 repeat 300, bit37 cl100 ->
0x3200 repeat 200, bit32 cl118 -> 0x3B00 repeat 200. INPUT: init 0x16E2F4
(unico bl caller 0xC5D9E) legge 0x14066C = ~0x22C434 = ~[0x554628]
(cella nel gap runtime NON dumpabile; polarità «1=premuto» provata a
livello macchina, convenzione elettrica del pin APERTA); INIEZIONE
0x16EC38(lo,hi) gate 0x16E6E0 e 0x16E3A2(classe,bit) via 0x16F914
AND-ctx + shift-left 64 0x334E9C: ZERO bl diretti, registrazione
indiretta (pool 0x16E390 -> cella 0x366DE8 via 0x140634; pool 0x16E38C
-> 0x16E588). 0x16F950 (bit0 alto, 7 chiamanti esterni INCLUSI
0x6531DE/0x6531E6 handler zoom ASLV it.48) e 0x16F964 (stb 0x3678F9)
sono DUE funzioni separate (correzione it.50 in corsa, confermata).
Generatore CONDIVISO: 18/19 bl fuori dalla macchina (iniettori
0x16E8A6..0x16F176 + 0x144A82). Funzioni regione extra: 0x16F928
(query flag>>15), 0x16F96C (cancel [0x80,0x307F]+[0x5400,0x57FF], 0 bl),
0x16F9F0 (unregister slot callback).

**Fonti, comandi, fixture, negativi.** Comandi eseguiti (senza pipe,
exit code verificato): `timeout 280 python3
Python_Trace_Scripts/s33_verify_key_machine_static_map_cpu.py` ->
PASS 9/9 RC=0 (evidenza 220850417476Z); regressioni
`s33_verify_event_router_producers_cpu.py` -> PASS
20261101T220928377441Z RC=0 e `s33_verify_snapshot_capture_record_init_cpu.py`
-> PASS 4/4 20261101T220935969096Z RC=0. Finestre ORIGINALI: .kmach
0x16F630..0x16FA64, .desc 0x392F04..0x393044, .shift64 0x335C4C,
.shiftl 0x334E9C, .ec38 0x16EC38..0x16EC88, .e3a2 0x16E388..0x16E41C,
millicode; census bl congelate + LE scans attese (0x16EC38 solo pool
0x16E390, 0x16E588 solo 0x16E38C). Fixture/assunzioni: RAM sintetiche
ctx 0x3678E4, record 0x446808, callback 0x446A08 (gap dump
0x428600..0x5FE800; ctx a riposo nel dump = zero, verificato payload 1);
stub con log per callback/0x17C150/0x17BC7C/0x149028/0x14905C/0x1491E8/
0x1593AC/0x1594A4/0x16E6E0/0xAD90C. NEGATIVI: no_change_negative
(scanner senza cambi -> nessun evento/callback/timer/anello);
controllo identico su tre run; census 0x16E3A2/0x16EC38 = 0 bl
(nessun produttore diretto); tabella descrittori delimitata (nessun
17° record); scansione LE 16 blocchi = nessun altro writer statico di
0x446808/0x3678E4/F8/F9/0x446A08/0x392F04.

**Limiti e non dimostrato.** La mappa è bit->evento, NON ancora
pulsante fisico->bit: identità del pin/GPIO della parola 0x554628
APERTA; callback reali stub (decodifica statica); wiring runtime di
0x16EC38 statico (pool); i 18 chiamanti esterni del generatore non
decodificati; nessuna prova hardware, USB, SD, flash; NON_INSTALLARE.
Progresso funzionale circa 10% invariato (nessuna nuova applicazione
avviata, nessuna foto reale).

**Agenti.** `kmach-review-51` (it.51, revisione ex-novo C1..C10 su
listato GNU righe 374516..374611/376300..376770 + byte del dump
block_01_type1_load_00360800.bin offset 0x32704 + census rg + LE scan
16 blocchi, PMB outbox 405): tutte CONFERMATE byte-esatte, 8 correzioni
di documentazione INTEGRATE nel rapporto (repeat/classe 106, secondo
callback 0x323A00, short-circuit fan-out, ctx completo, sync
transitorio, gate 0x3678F9 a riposo 0x01 e 56 bl, 0x14066C=~[0x554628],
funzioni extra regione), 7 controesempi NON invalidanti documentati.
L'agente della it.50 non tornò mai (sessione interrotta): sostituito da
kmach-review-51.

**Strumenti/MCP.** PMB pmb-nikon: prepare (contesto progetto) e
record_batch (esito); agente explore kmach-review-51; motore pinnato
GNU ARC700 via s33_run_gnu_arc700. REA non usato in questa iterazione
(decodifica già coperta da listato GNU congelato + verificatore CPU).

**Prossimo passo (non ripetitivo).** Decodifica della callback reale
0x16E588 (pool 0x16E38C, registrata via 0x16F988 all'init) e dei suoi
siti 0x16E8A6..0x16F176 di chiamata al generatore 0x16F72C: è il ponte
macchina tasti -> callback -> anello -> dispatcher che chiude la catena
fisico->GUI; in alternativa census dei lettori di 0x554628/0x22C434 per
risalire dal bit al GPIO (identità fisica dei pulsanti).

## Iterazione 49 — 1° novembre 2026 — PRODUTTORI 0x380/0x400 CENSITI (punto it.48(a)): PASS_ZOOM_EVENT_PRODUCERS_CENSUS 20261101T213509446205Z x2 run identiche + regressioni 2/2 — registro p3 COMPLETO (39 record) con 0x381/0x401→0x65B5D4 HANDLER DI RILASCIO (purge 0x17BF60 + repost del tasto ancora premuto via 0x16F920(8/7)), 20 siti produttori diretti + 1 duale, 76 cancellatori + 12 indiretti, libreria iniettori p4 (arg 0xFF/0 e auto-ripetizione 100 ms) provata in CPU 4/4 su byte originali

**Domanda affrontata.** Punto aperto (a) dell'iterazione 48: chi accoda a
runtime gli eventi 0x380/0x400 (zoom in/out AutoSceneLiveView, registro p3,
handler 0x65B3A8)? Census dei siti 0x17BF60/0x16F6B0/coda 0x169EB4 per
questi id, poi decodifica del produttore più promettente.

**Risultato verificabile e significato.** [Rapporto](S33_GUI_Zoom_380_400_Produttori_Censimento_CPU_20261101.md),
[verificatore](../Python_Trace_Scripts/s33_verify_zoom_event_producers_census.py),
[evidenze](../Risultati/GUI_S33/zoom_event_producers_census_20261101T213509446205Z/)
(+ riesecuzione identica ...T213559063117Z, `zoom_event_producers_latest.json`).
**PASS_ZOOM_EVENT_PRODUCERS_CENSUS 20261101T213509446205Z** statico+censuses
+ 4 casi CPU byte originali, riesecuzione identica. REGISTRO p3
0x783B08..0x783C40 completo (39 record, terminatore (0,0x20E814)):
**0x381/0x401 → 0x65B5D4**, handler di RILASCIO zoom (entry reale push_s
blink a 0x65B5D4, byte congelati `f1c0520b4e6cfc1cc8b60a230037`; la riga
listing a 0x65B5D2 è decodifica spuria della coda del pool 0x4111;
zero bl caller, zero LE: raggiunto SOLO via registro p3). 0x65B5D4:
gate C9BF8/CAD30/149474 → timer 14905C(node,2,0xBB8=3000) → [ctx+4]∈{4,5}
(gli stati del consumatore it.48) → cancel (0,0x400,0x400)+(0,0x380,0x380)
via jl_s [r14=pool 0x65B714=0x17BF60] (×2+×2) → purga servizi →
[ctx+4]:=r15, CF060(1) → **0x16F920(8)≠0 → post (r13,0x400,0) via
0x169EB4@0x65B700, else 0x16F920(7)≠0 → post (r13,0x380,0)**: RIPUBBLICA
il tasto ancora premuto al rilascio dell'altro; percorsi alternativi:
attesa 0x145C3C(0x30D40=200000, pool 0x65B39C) su flag, uscita b 0x65B1B8
(loop, NON return). PRODUTTORI diretti via 0x169EB4: 0x380×8 (0x654322,
0x65b700, 0x7cbc72, 0x802036, 0x80be9a, 0x80bed4, 0x80bef4, 0x9e223a),
0x400×10 (0x2101f2, 0x654b04, 0x654b9c, 0x7cbc8a, 0x80204e, 0x8020ba,
0x80bc92, 0x80bccc, 0x80bcec, 0x9e2250), 0x381@0x80bea6, 0x401@0x80bc9e;
SITO DUALE 0x65b700 (rami 0x65B6EA r1=1024 / 0x65B6FA r1=896); NESSUN
hit via 0x169F40/0x169F00; 0x16F6B0 (fan-out tasti, 7 chiamanti, tabella
callback 0x446808+512+4i FUORI dai payload) ha eventi DINAMICI: produttore
FISICO APERTO. CENSUS API: 0x169EB4=304, 0x169F40=28, 0x169F00=33,
0x16F6B0=7, 0x17BF60=188. CANCELLATORI 0x17BF60(desc,lo,hi) coprenti
0x380/0x400: 76 siti diretti ([0x1,0x7FFF]×1, [0x80,0x307F]×65,
[0x300,0x500]×2, [0x380,0x380]×4, [0x400,0x400]×4) + 12 indiretti
jl_s [pool] (0x65B640/4A/BA/C4, 0x65D2F6/300, 0x9DEFBE/C8, 0x7F7DEE/F8,
0x7FA484/8E); NON coprenti dimostrati: 0x16F97E (delay slot asl_s
r1,r1,0xa → [0x5400,0x57FF]) e 0x65A898 (bset 0xe → [0x400C,0x400C]).
LIBRERIA INIETTORI p4: press+release 0xFF/0: 0x80BC7C(0x400), 0x80BD4C
(0x480), 0x80BDE8(0x500), 0x80BE84(0x380); arg 0: 0x80BD18(0x200),
0x80BC48(0x780); estese 0x700/0x580/0x600/0x680; auto-ripetizione
0x80BCB0/0x80BD80/0x80BE1C/0x80BEB8 periodo pool 0x186A0=100ms + sleep
resto; DISPATCHER 0x809F78(record,cmd) UNICO chiamante 0x2D77BE (p0,
interprete comandi ASCII 'S'/'A'/'F'/'D'), casi 0x24..0x36+0x3A byte-
verificati (0x3A→0x80BE84@0x80A3E4: correzione alla revisione che diceva
0x37). CPU 4/4: press380 (2 post (0,0x380,0xFF),(0,0x381,0), 0 sleep);
repeat380 DUR 250000 → 3 post + sleep [100000,100000,50000]; 50000 → 1+
[50000]; 350000 → 4+[100000×3,50000]. SCOPERTA METODOLOGICA (prima prova
CPU nel progetto): bl SENZA .d NON ha delay slot — il b_s -32 a 0x80BEF8 è
il loop-back dopo il ritorno di 0x169EB4; stabilita con banco esplorativo
(tmp/explore_repeat380*, fault-address probing) PRIMA di congelare le
asserzioni. Pool verificate: 0x65B708=0x681F83, 0x65B70C=0xBB8,
0x65B710=0x681F5C, 0x65B714=0x17BF60, 0x65B718=0x16F920, 0x65B39C=0x30D40,
0x65B5D0=0x4111, 0x16FA3C=0x446808, 0x16FA40=0x3678F9, 0x16FA54=0x307F,
0x16FA58=0x57FF, 0x80BD08/0x80BDD8/0x80BE74/0x80BF10=0x186A0, 0x652E54/
0x6591EC/0x7D48B0=0x307F, 0x7FAB84=0x7C60.

**Fonti, comandi, fixture, negativi.** Census su
Risultati/Disassemblati/Firmware1.1.asm (6.1M righe) con risolutore
documentato (def const/pool, copie registro, catene asl, delay slot di
bl.d, proprio e altrui); payload verificati via verified_payloads;
finestre originali confrontate byte per byte al link. Negativi e guardie:
0x16F97E e 0x65A898 non coprenti (sopra); LE scans 0x65B3A8/0x65B5D4/
0x65BEA4/0x65C46C/0x809F78/0x65B5D6 congelate; nessun 0x380/0x400 via
0x169F40/0x169F00/0x16F6B0. Regressioni eseguite dopo la prima PASS senza
pipe, RC=0: event router producers 20261101T212501827282Z, consumatore
ASLV 20261101T212512111605Z (16/16, solo regressione). Assunzioni banco:
stub 0x169EB4/0x145C3C con log; r16/r13 preservati; millicode
0x334100..0x3341E4; nessun anello/WindowManager reale.

**Agenti e MCP.** Agente `producer-review-45` (tools.agents.spawn,
atteso e integrato; due turni): C1–C8 verificati ex-novo; correzioni
ACCETTATE: sito duale 0x65b700; arg press 0x200/0x780=0 e libreria oltre
0x80BF60 (coppie 0x700/0x580/0x600/0x680, iniettore indiretto 0x80C084);
tabella callback 0x446808+512+4i (non +i*128, add2 ×4 it.39);
percorsi alternativi 0x65B5D4 (attesa 200000, uscita b 0x65B1B8);
cancellatori ~96 con regole proprie, 0x16F97E non coprente (asl delay
slot), 0x16F972 mancato (aggiunto), 12 pool indiretti; CORREZIONE ALLA
REVISIONE: caso dispatcher 0x3A (non 0x37) per 0x80BE84. I censimenti
coincidono su ogni sito che entrambi risolvono; la differenza numerica
(76 vs ~96) è nei siti non risolvibili localmente (limite dichiarato,
es. 0x65B342 r1 dinamico). Server MCP: mcp_pmb_nikon (prepare iniziale +
record_batch finale). REA non presente tra i connettori (confermato
it.44/47/48). Strumenti: bash, python3, objdump/objcopy GNU ARC700
(work/build-arc), Runner sim pinnato, tools.agents (spawn,
send_message), search_tool_functions. «task con agente explore»
inesistente (come it.44/47/48): usato tools.agents.spawn. Nessun
hardware/USB/SD.

**Limiti.** Produttore FISICO bit-tasto→0x380/0x400 APERTO (regione
0x16F72C..0x16F920); 0x65B5D4 decodifica statica (pool verificate, corpo
NON in CPU; servizi fixture/interpretazione); percorso anello→WindowManager
→registro p3 non eseguito in questo banco; scheduling/concorrenza APERTI;
tabella callback 0x446A08 fuori dai payload; V1.1 vs V1.0; nessun
hardware/boot/scatto; NON_INSTALLARE; circa 10% invariato.

**Prossimo passo concreto (non ripetitivo).** (a) **Decodifica macchina
tasti**: funzione 0x16F920 (query stato tasto per classe evento, 521
chiamanti, id 7→0x380/8→0x400) e regione 0x16F72C..0x16F920 che alimenta
0x16F6B0, per la mappa bit fisico→evento: chiude l'ultimo pezzo del
produttore runtime. (b) Alternativa: CPU di 0x65B5D4 con stub dei servizi
(purge+repost in esecuzione). (c) Alternativa: decodifica 0x65B71C
(forward zoom del consumatore, punto it.48(b)). Il punto it.48(a) è
CHIUSO: non rieseguire il verificatore zoom producers come nuovo lavoro.

---

## Iterazione 48 — 1° novembre 2026 — CONSUMATORE 0x65B3A8 (EVENTI 0x380/0x400) CHIUSO (punto it.47(a)): CPU 16/16 x2 run identiche + regressioni 4/4 — CONSUMO del ring provato (ldb gate, word[0x47BBB4+4*gate], DECREMENTO gate se ==0xA a 0x65B524/26, parola NON azzerata, gate==0 salta, gate 0xFF legge 0x47BFB0), chiamata REALE dell'handler 0x4111 con (node,0,0) quando la coda resta piena dopo la purga, ri-notifica interna 20E814(node,0,0) (SCOPERTA: 0x65CCC8 forwarda l'evento IN INGRESSO, mov_s r1,r13 a 0x65CD3C, NON la costante 0x4111), forward proprio 20E814(node,0x4111,arg) in ENTRAMBI i rami

**Domanda affrontata.** Punto aperto it.47(a) del rapporto
[S33_GUI_AutoSceneLiveView_Append_Writers_4110_4111_CPU_20261101.md](S33_GUI_AutoSceneLiveView_Append_Writers_4110_4111_CPU_20261101.md):
l'handler 0x65B3A8 (registro p3, eventi 0x380/0x400, record 0x783B58/0x783B68),
unico chiamante bl di 0x65CCC8 e primo decrementatore del gate, esegue davvero
il CONSUMO del ring? Chiama davvero l'handler 0x4111 con (node,0,0)? Cosa
inoltra a 0x20E814 nei due rami della coda non vuota?

**Risultato verificabile e significato.** [Rapporto](S33_GUI_AutoSceneLiveView_Consumer_380_400_CPU_20261101.md),
[verificatore nuovo](../Python_Trace_Scripts/s33_verify_aslv_consumer_380_400_cpu.py),
[evidenze](../Risultati/GUI_S33/aslv_consumer_380_400_cpu_20261101T210144995277Z/),
[riesecuzione identica](../Risultati/GUI_S33/aslv_consumer_380_400_cpu_20261101T210207318802Z/).
**PASS_ASLV_CONSUMER_380_400_CPU 20261101T210144995277Z** 16/16 casi CPU byte
originali, riesecuzione byte-identica **20261101T210207318802Z** (sha
eddbb0649be605cd), regressioni 4/4 PASS. CONFERMATO in CPU: gate d'ingresso
1707D8(4)+C9BF8()==1 uscita (ret=C9BF8)+CAD30()==0x7E uscita+CF060(1)+GATE DI
STATO [ctx+4]: {0,3} passano, ==8 → :=0 e passa, ALTRO esce con **ritorno =
puntatore ctx**; 135A84 riceve (ctx, stato, arg) — NON (node,ev,arg) — bit1
uscita ret 2; C8BA0(0)!=0 uscita. Dispatch cmp r17,1024: ev==0x400 vs ELSE;
**POLARITÀ OPPOSTA del gate zoom** (casi 6/7 al confine 0x64): 0x400 bls
(fallisce ≤0x64), 0x380 blo (fallisce <0x64); [ctx+0x20] 0x681F7C := 0 (0x400)
/ := 1 (0x380, via 65D008/65CE88 PRIMA della scrittura) + forward
65B71C(node,ev,arg); zoom fail → r13 := 0x1493A4 (0x400) / 0x14938C (0x380)
+ timer SOLO 0x380: 14918C(node,0xC)==0 → 14905C(node,0xC,400,400,0). Coda
comune: 149028(node,{1,2,3,4,6}) via jl_s [r15=0x149028], 65D1CC(node),
65D8B4, 145920, 145150(node), 177484: VUOTA → r13≠0: DECD4/DD094/149DF4 +
[ctx+4]:=4 + **jl_s [r13] LINKED (rientra a 0x65B566: NON è tail-call)** →
14A1F8>0x64 uscita else 14905C(node,3,1000,1000,0); r13==0: stato {2,3} →
149474!=0 uscita, [ctx+4]:=5, 14A1F8, mode 0x2C → 14905C(node,1,500,500,0).
NON VUOTA → purga 177460/17743C/177484: ANCORA PIENA → **bl 0x65CCC8
(handler 0x4111 REALE, finestra .h41) con (node,0,0)** → append 0xA (it.47
riprovato in catena) + ri-notifica interna **20E814(node,0,0)** + 14941C/
177460 con r1=0 + forward proprio 20E814(node,0x4111,arg) (pool 0x65B5D0)
con **arg r16 PRESERVATO** (0x65CCC8 non tocca mai r16/r17); SVUOTATA →
**CONSUMO**: ld.as r2→[0x65B388]=0x47BBB8, ldb gate [r2,0x10], gate==0 salta
(ble_s, byte zero-esteso), ld.as r0→[0x65B390]=0x47BBB4, add2 +4*gate, word
==0xA → **gate-1** (0x65B524/26, unico decremento noto; parola NON azzerata),
poi 65D8B4/145150(node)/20E814(node,0x4111,arg). Uscita UNICA: b 0x65B1B8
(disp −1024) → mov sp,fp/ld.ab fp → b 0x334184 (disp −0x32703C, CORRETTA nel
motore pinnato) → pop r17..r13+blink: bilancia push 0x334124. STATI: [ctx+4]
:= 0 (stato 8, caso 16 PERSISTENTE), := 4, := 5 — census revisione: NESSUN
altro writer nella finestra. SCOPERTA NUOVA: il tail dell'handler 0x4111
forwarda l'evento CON CUI È CHIAMATO (mov_s r1,r13 / mov_s r2,r15 a
0x65CD3C/3E): dal registro ripubblica 0x4111, dal consumatore ripubblica
evento 0 (it.47 non distingueva: entrava sempre con ev=0x4111).

**Fonti, indirizzi e comandi.** Finestre byte-originali: .h380 (2,
0x65B3A8..0x65B5D4, 556 byte), .poolh (2, 0x65B388..0x65B398), .epi (2,
0x65B1B8..0x65B1C4), .mili (0, 0x334100..0x3341E4), .h41 (2,
0x65CC18..0x65CD54, freeze it.47), .epi9 (2, 0x659588..0x659594). Pool
interni 0x65B5BC=ctx/0x65B5C0=ctx+0x20/0x65B5C4=0x1493A4/0x65B5C8=0x14938C/
0x65B5CC=0x149028/0x65B5D0=0x4111; esterni 0x65B388=ring/0x65B390=TBL via
ld.as [pcl,-97/-98] (EA=(PC&~3)+imm*4). Census LE 16 blocchi: 0x65B3A8 solo
0x783B5C/0x783B6C; census bl: 0x65B3A8 ZERO chiamanti (callback puro),
0x65CCC8 UNICO bl 0x65B53A. `python3
Python_Trace_Scripts/s33_verify_aslv_consumer_380_400_cpu.py` → PASS x2
(210144995277Z/210207318802Z). Run intermedie con correzioni oracolo
documentate (205024/205121/205159/205257/205349Z: fail casi 6, 8, 12, 13) e
run 15-casi 205437/205505Z PASS identiche. Regressioni post-PASS (log
/tmp/reg48b_*): aslv_helper_d098 210236011164Z, aslv_b060_arg18_clear
210256024919Z, service_raise_pending 210315Z, snapshot_capture_record_init
210320169589Z.

**Fixture, assunzioni, negativi e limiti.** Banco: 34 stub RETSEQ (8
valori/sid in ordine di chiamata), logger 16B, fixture ring 0x47BBB0..0x47C070
(gate 0x47BBC8, FF read 0x47BFB0=0x47BBB4+4*0xFF), ctx 0x681F5C 0xD0 byte
sentinella. Nei casi 13/14 il corpo REALE di 0x65CCC8 gira nel banco (frame
completo push 0x33412C/epilogo 0x659588/pop 0x334194). Negativi: slot −1
(0x47BBB4) mai scritto, ctx+0xC sentinella, conteggio chiamate esatto +
"nessuna chiamata extra" per caso, ritorni al banco esatti (1/0x7E/ctx/2/1/
0x65/0), leftover r1/r2 ricalcolati staticamente (stato a SC8BA0, 6/ARG/400
nella coda — il mov r2,400 del timer 0x380 persiste fino all'uscita, RING/gate
nel consumo), parola del ring NON azzerata dal decremento, 65DAD0/14941C
assenti nei casi consume. Limiti: ctx/ring/gate RAM runtime nel gap di load,
fixture-imposte; **l'ipotesi che 0x1493A4/0x14938C RITORNINO** (continuazione
a 0x65B566) è assunzione di banco, comportamento reale non provato;
produttori runtime di 0x380/0x400/0x4110/0x4111 e scheduling APERTI;
significato dei motivi {3,4,5,6,9,0xA,0xB,0xC,0xD} interpretazione; 0x65B71C
e i servizi 149028/65D1CC/65D8B4/145920/177460/17743C/177484 stub;
sopravvivenza r16 nei callee profondi = convenzione (nel banco preservata);
nessun hardware/boot/scatto; NON_INSTALLARE; circa 10% invariato.

**Agenti e MCP.** **Agente `consumer-review-48`** (tools.agents.spawn,
atteso e integrato; due controesempi nell'oracolo previsti in anticipo e
coincidenti con i fault empirici: FF_WORD 0x47BFB8→0x47BFB0; forward interno
r1=0 non 0x4111; previsione "12 PASS poi fault 12/13/14" combaciata con la run
intermedia 205257Z): revisione statica ex-novo con disassembly propri su
TUTTI i 16 blocchi, census LE a ogni allineamento, census bl/b/bcc/j, target
dei b 32-bit ricalcolati con la formula di decode7.c del motore pinnato,
condizioni bcc dalle tabelle arc-desc.h, round-trip assembler byte-esatto,
freeze ricavati → **C1–C9 CONFERMATI** (gate chain, polarità, coda, rami,
consumo, epilogo, census, .h41 senza r16/r17, NESSUNA uscita senza
epilogo, NESSUN delay slot nei corpi, ZERO rami in entrata da fuori
finestra); precisioni integrate (dispatch else; ordine 65D008→65CE88→
[ctx+0x20]:=1→forward; 65D1CC(node)); gap di copertura chiuso col caso 16.
Revisione: [Risultati/GUI_S33/aslv_consumer_380_400_agent_review_consumer48_20261101.md](../Risultati/GUI_S33/aslv_consumer_380_400_agent_review_consumer48_20261101.md).
Server MCP: mcp_pmb_nikon (prepare iniziale + record_batch finale). REA non
presente tra i connettori (confermato). Strumenti: bash, python3, objdump/
objcopy GNU ARC700 (work/build-arc), Runner sim, tools.agents (spawn),
tools.process (background), search_tool_functions. «task con agente explore»
inesistente (come già documentato in it.44/47): usato tools.agents.spawn.
Nessun hardware/USB/SD.

**Prossimo passo concreto (non ripetitivo).** (a) **Produttori runtime
degli eventi 0x380/0x400** (chi accoda 0x380/0x400 verso il registro p3:
census dei siti 17BF60/16F6B0/coda 0x169EB4 per questi due id, poi decodifica
del produttore più promettente): con writer (it.39/47), lettore (h100 it.37)
e consumatore (it.48) chiusi in CPU, il pezzo mancante della catena
ring→gate→h100→0x65E900→finestra è CHI la alimenta a runtime. (b)
Alternativa: CPU della funzione 0x65B71C (forward zoom del consumatore) per
capire dove finisce l'evento dopo il gate 14A1F8/CDACC/CD514. (c)
Alternativa: decodifica di 0x1493A4/0x14938C (target del jl_s [r13]) per
chiudere l'assunzione "ritornano". Il punto it.47(a) è CHIUSO: non rieseguire
il verificatore consumer 380/400.

---

## Iterazione 47 — 1° novembre 2026 — WRITER APPEND 0x4110/0x4111 CHIUSI (punto it.39(a)): CPU 14/14 x2 run identiche + run finale script corretto + regressioni 4/4 — handler 0x4110=0x65CC40 accoda 9, handler 0x4111=0x65CCC8 accoda 0xA, ENTRAMBI senza reset del gate, guardia word[0x47BBB4+4*gate]!=0xA, enqueue a [0x47BBB8+4*gate] e gate+1; il gate può crescere oltre 1 tra un 0x65C720 e l'altro (ipotesi it.39 PROVATA con i casi doppì)

**Domanda affrontata.** Punto aperto it.39(a) del rapporto
[S33_GUI_AutoSceneLiveView_Ring_Writer_65C720_CPU_20261101.md](S33_GUI_AutoSceneLiveView_Ring_Writer_65C720_CPU_20261101.md):
i due writer residui del sottosistema gate, solo statici in it.37, eseguono
davvero l'APPEND di 9/0xA al ring SENZA resettare il gate, con guardia
word[0x47BBB4+4*gate]!=0xA? Possono far crescere il gate? Cosa fanno i tail?

**Risultato verificabile e significato.** [Rapporto](S33_GUI_AutoSceneLiveView_Append_Writers_4110_4111_CPU_20261101.md),
[verificatore nuovo](../Python_Trace_Scripts/s33_verify_aslv_append_writers_cpu.py),
[evidenze](../Risultati/GUI_S33/aslv_append_writers_cpu_20261101T202252150931Z/),
[riesecuzione identica](../Risultati/GUI_S33/aslv_append_writers_cpu_20261101T202318161207Z/),
[run finale](../Risultati/GUI_S33/aslv_append_writers_cpu_20261101T203730763689Z/).
**PASS_ASLV_APPEND_WRITERS_CPU 20261101T202252150931Z** 14/14 casi CPU byte
originali, riesecuzione byte-identica 20261101T202318161207Z, run finale
20261101T203730763689Z. IDENTIFICAZIONE (nuovo, prima non documentato):
registro p3 0x783C10 (0x4110)->0x65CC40 e 0x783C18 (0x4111)->0x65CCC8,
terminatore (0,0x20E814) a 0x783C40; census LE: unici riferimenti; census
bl: 0x65CC40 ZERO chiamanti, 0x65CCC8 UNICO bl a 0x65B53A DENTRO l'handler
0x380/0x400 = 0x65B3A8 (che a 0x65B512..0x65B526 LEGGE il gate e lo
DECREMENTA se l'ultima word==0xA: primo consumatore/decrementatore del gate
trovato). PROVATO IN CPU: append 9/0xA a [ring+4*gate] con add2 scala x4 e
gate+1 SENZA reset; guardia word[0x47BBB4+4*gate]==0xA blocca (per
ENTRAMBI, quindi 9 ripetibili e 0xA mai consecutivo: casi dbl_4111_twice e
dbl_9_then_A con gate 1->2->3); gate==0 append incondizionato a slot 0;
gate=0xFF -> append a 0x47BFB4 e byte gate wrap 0x00 con registro r0=0x100
(caso w4110_gate_ff), guardia attiva anche a 0xFF (w4111_gate_ff_guard);
[ctx+0x10]=ret(0x145D1C), [ctx+0x14]=0x47BBB8, [ctx+0xD]=1, [ctx+0xC] MAI
toccato (diverso da 0x65C720). TAIL: 0x4110 -> 65DAD0/145150(node)/
177030(9)/145D1C(0) + 20E814(0, 0x4110, arg) (r0=0!); 0x4111 ->
65DAD0/145150(node)/145D1C(0) (NESSUN 177030) + 20E814(NODE, 0x4111, arg) +
SEMPRE 14941C e se 0 anche 177460. SKIP bit1 di 135A84: 0x4110 solo
20E814(0,0x4110,arg); 0x4111 solo 14941C(2,...)/177460 senza 20E814.
Frame ORIGINALE completo: push_s blink + millicode 0x33412C (push r15/r14/
r13) + epilogo condiviso 0x659588 + pop 0x334194 (ld r15/r14, ld.ab r13,
ld.ab blink, j_s [blink]) con bilancio provato dal valore di ritorno al
banco. CONSEGUENZA: famiglia dei writer del sottosistema gate CHIUSA in CPU
(0x65C720 reset+slot0; 0x4110/0x4111 append); il ciclo post-0x65C720 è:
0x65C720 scrive il motivo a slot 0, lascia gate=1, accoda l'evento
0x4110/0x4111; l'handler dell'evento appende 9/0xA a slot 1; il lettore h100
consuma word[0x47BBB4+4*gate] = ultima voce.

**Fonti, indirizzi e comandi.** Finestre byte-originali: .h41 (2,
0x65CC18..0x65CD54, sha256 53588bea…cadc, pool 0x65CC24=0x47BBB8 /
0x65CC28=0x47BBB4 / 0x65CC2C=0x681F5C), .epi (2, 0x659588..0x659594), .mili
(0, 0x334100..0x3341E4). `python3 Python_Trace_Scripts/s33_verify_aslv_append_writers_cpu.py`
-> PASS x3 (due identiche + finale). Regressioni 4/4 PASS post-PASS:
aslv_helper_d098 202347Z, aslv_b060_arg18_clear 202407Z,
service_raise_pending 202426Z, snapshot_capture_record_init 202430Z (log
/tmp/reg41_*, diretti senza pipe).

**Fixture, assunzioni, negativi e limiti.** Banco RW-style: stub a sequenza
RETSEQ (12 callee: 135A84/65BE24/DECD4/DD094/149DF4/65DAD0/145150/177030/
145D1C/20E814/14941C/177460), logger 16B/chiamata, fixture ring
0x47BBB0..0x47C010 con gate a 0x47BBC8, ctx 0x681F5C sentinella. Negativi:
slot -1 (0x47BBB4) mai scritto, ctx+0xC sentinella 0xA5, conteggio chiamate
esatto + "nessuna chiamata extra", 14941C!=0 -> nessun 177460 e ritorno
0x55, guardia blocca con gate intatto, bit1 skip senza scritture,
doppie chiamate con seconda invocazione bloccata dalla guardia. Limiti:
ring/gate/ctx sono RAM runtime nel gap di load (fixture imposte, NON dal
dump); produttori runtime degli eventi 0x4110/0x4111 e scheduling non
provati; significato dei valori 9/0xA interpretazione; 0x65B3A8 solo
individuato; nessun hardware; NON_INSTALLARE; circa 10% invariato.

**LEZIONE DI BANCO (correzione in corsa, audit).** La b 32-bit a 0x65CCC2
(PC≡2 mod 4, disp −14136) era stata trattata come wrap del sim a 0x65D588
(lezione it.44), con trampolino syncret documentato collocato lì. La
revisione indipendente ha impugnato la claim e la TRACCIA del motore
pinnato la smentisce: `0x65ccc2 b 0x659588 - pc <- 0x659588`, la b esegue
CORRETTAMENTE (idem 0x65CD50). Syncret = codice morto precauzionale; la
lezione it.44 NON si riproduce in questi siti con questo motore (evidenze
it.44 NON revocate, divergenza da chiarire). Tracce:
[wrap_trace](../Risultati/GUI_S33/aslv_append_writers_wrap_trace_20261101T20261101T203728Z/)
(wrap_trace_summary.json + 2 .trace).

**Agenti e MCP.** **Agente `aw-review-41`** (tools.agents.spawn, due turni,
atteso e integrato): revisione statica ex-novo (disassembly propri di tutti
i 16 blocchi /tmp/aw41/dis00..15, census LE32/halfword, sha256 ricalcolati,
sorgenti del sim letti) -> **C1–C8 CONFERMATI** byte-esatti: registro p3,
census LE/bl con l'unico chiamante 0x65B53A e il decremento gate
0x65B524/0x65B526, decodifica completa dei due handler, differenze vs
0x65C720, riderivazione dei 14 casi (gate_ff r0=0x100/stb 0x00, EA a
65DAD0 nel caso gate0 di 0x4111), congruenza hex/asserzioni, classificazione
di TUTTI gli utenti ring/gate del block 2 (writer solo quelli noti; residuo
0x65C922 ld_s senza store) e nessuna collisione del syncret. Due note APERTA
dell'agente: (1) commenti objdump ld.as non conclusivi ma pool reali
0x65B388/0x65B390 verificati; (2) claim wrap non chiudibile staticamente ->
RISOLTA empiricamente con la traccia (smentita). Revisione:
[aw41](../Risultati/GUI_S33/aslv_append_writers_agent_review_aw41_20261101.md).
Server MCP: mcp_pmb_nikon (prepare iniziale + recall x2 + record_batch
finale). REA non presente tra i connettori (confermato). Strumenti: bash,
python3, objdump GNU ARC700 (toolchain opt + work/build-arc), Runner sim,
tools.agents (spawn/send_message), search_tool_functions. Nessun
hardware/USB/SD. «task con agente explore» inesistente (come già documentato
in it.44): usato tools.agents.spawn.

**Prossimo passo concreto (non ripetitivo).** (a) **CPU del consumatore
0x65B3A8** (handler eventi 0x380/0x400): legge il gate a 0x65B512
(ldb [r2,0x10]), legge word[0x47BBB4+4*gate] (0x65B51E) e DECREMENTA il gate
se ==0xA (sub 0x65B524 + stb 0x65B526), poi chiama DIRETTAMENTE l'handler
0x4111 a 0x65B53A con (node, 0, 0) e consegna 20E814(node,...) a 0x65B544;
con la famiglia dei writer chiusa, questo è il pezzo che trasforma il ring
in una coda consumata (chi produce 0x380/0x400? come si coordina con h100?).
(b) Alternativa: produttori runtime degli eventi 0x4110/0x4111 (coda di
servizio interrogata da 0x65C720 via 17BE18/17BF60) e il residuo 0x65C922.
Il punto it.39(a) è CHIUSO: non rieseguire il verificatore append writers.

---

## Iterazione 39 — 1° novembre 2026 — RING WRITER 0x65C720 CHIUSO (punto it.37(a)): CPU 22/22 su byte originali — reset [ctx+0xC]+gate, AL MASSIMO UN enqueue per invocazione (if/elif, priorita' bit3>bit2>bit4>bit1), add2 scala x4 provata in CPU (sem7.c + caso micro gate=3 -> parola a 0x47BBC4=ring+4*3), dispatch modo 0x7D con validatore 3 out-byte di 127984 (b1|b2|b3>=0xA -> C7BDC), coda di servizio 0x4111/0x4110/177484 con 14941C/177460/17BF60/20E814, finale C9750/C975C, ritorno r15 (verificatore Ring_Writer PASS x2 run identiche)

**Domanda affrontata.** Prossimo passo it.37(a): il writer del sottosistema
gate 0x65C720 (5 chiamanti: 2 in 0x4405, 0x440E, h100 a 0x65B200, 0x4006),
decodificato solo staticamente in it.37, non era mai stato eseguito in CPU.
Resetta davvero [ctx+0xC] e il gate [0x47BBC8]? Quanti motivi accoda per
invocazione? La scala dell'indice del ring e' davvero x4 (add2)? Cosa fa la
sezione coda di servizio?

**Risultato verificabile e significato.** [Rapporto](S33_GUI_AutoSceneLiveView_Ring_Writer_65C720_CPU_20261101.md),
[verificatore nuovo](../Python_Trace_Scripts/s33_verify_aslv_ring_writer_cpu.py),
[evidenze](../Risultati/GUI_S33/aslv_ring_writer_cpu_20261101T201306910162Z/),
[riesecuzione identica](../Risultati/GUI_S33/aslv_ring_writer_cpu_20261101T201333569437Z/),
[revisione agente](../Risultati/GUI_S33/aslv_ring_writer_agent_review_rw39_20261101.md).
**PASS_ASLV_RING_WRITER_CPU** 22/22 casi CPU byte originali x2 run
byte-identiche (fault 0xDEADB001..0x16). CONFERMATO in CPU: prologo bl
0x334118 spinge r20..r13 (8 reg) ed epilogo b 0x33416C li ripristina con
blink dalla cella pushata (ld.ab EA=rA post-incremento, provato); frame
fp=0xC8EFD8, 12B0DC(fp-0xC=0xC8EFCC); gate1 C7E04()==0 -> ret 0 senza
scrivere; gate2 query 17BE18(0,0x3180,0x3180)/(0,0x3181,0x3181) !=0 -> ret
0 SENZA reset; reset incondizionato [ctx+0xC]:=0 e gate:=0; modo REALE
0xCAD30: 0x7D -> 127984(fp-3..fp-1) 3 out-byte, b1|b2|b3>=0xA -> r18=C7BDC
(ldb zero-extend + blt_s con segno, esito coincidente su 0..255); altro
modo -> C7E04()==1 ? r18=127284() : r18=-1; dispatch if/elif r19!=0:
bit3->0xB, bit2->0xD, bit4->6, bit1->4 (r15 resta 1), else 127278()==0 &&
r18==0 -> ENQ 3, !=0 -> ENQ 5 (r15=0), r18!=0 -> ctx write [ctx+0xC]:=1,
[ctx+0xD]:=0, r15=0, NESSUN enqueue; r19==0: 127278()!=0 -> ENQ 5, r18==0
-> ENQ 0xC, else ctx write; ENQ(v): ldb gate, add2 r1,ring,r0 = ring+4*gate
(SCALA X4: sem7.c add2_L_r_r SLLSI(...,2) + caso 21 micro con gate fixture
3 -> parola 0xB a 0x47BBC4=0x47BBB8+12, gate 3->4), st, gate+1; coda:
17BE18(0,0x4111,0x4111)!=0 -> 14941C(); se 0 -> 177460();
17BF60(0,0x4111,0x4111); r15=1; 20E814(node,0x4111,0); elif 0x4110 ->
stesso senza 20E814; elif 177484()!=0 -> 14941C/177460, r15=1; finale
C9750()==0 -> r15=0; C975C(1); ritorno r15. CONSEGUENZE (rifiniscono
it.37): (1) il "ring" e' un canale a SLOT 0 rinnovato: 0x65C720 resetta
SEMPRE il gate prima del dispatch, scrive [0x47BBB8] e lascia gate=1;
l'accumulo oltre lo slot 0 (9/0xA dei writer 0x4110/0x4111, non provati in
CPU) richiede invocazioni SENZA 0x65C720 intermedio; (2) coerenza
writer/lettore chiusa in CPU: h100 legge word[0x47BBB4+4*gate] = il motivo
appena scritto; (3) lezione registri vivi: le query 0x3180/0x3181 caricano
r1/r2 con le costanti del pool (leftover fino alla coda), e mov r0,r17 a
0x65C7EA (SOLO ramo r19!=0) sovrascrive il leftover di 127284: i due bracci
del dispatch passano a 127278 un r0 DIVERSO. Pool: 0x65C90C=0x3181,
0x65C910=0x681F5C, 0x65C914=0x47BBB8, 0x65C918=0x4111, 0x65C91C=0x4110.
Census bl 0x65C720 = 5 siti confermato con 3 metodi dall'agente (0x65CAEE e'
bl_s 16-bit 0xFF0D, non bl 32-bit; il linear sweep objdump desincronizza
sulla pool 0x659594-98: senza sync forzato attribuirebbe i siti di 0x4405
all'handler 0x4401).

**Fonti, indirizzi e comandi.** Finestre byte-originali: .rw
0x65C720..0x65C920 (payload 2, freeze 0x200 byte), .mili 0x334100..0x3341E4
(payload 0), .modeget 0xCAD30 + .modepool 0xCAAC4 (payload 0). Millicode
push/pop 0x334118/0x33416C; enqueue 0x65C7F0..0x65C81E; epilogo 0x65C900.
`python3 Python_Trace_Scripts/s33_verify_aslv_ring_writer_cpu.py` ->
PASS_ASLV_RING_WRITER_CPU **20261101T201306910162Z** + identica
**20261101T201333569437Z**. Regressioni 4/4 PASS post-PASS:
aslv_helper_d098, aslv_b060_arg18_clear, service_raise_pending,
snapshot_capture_record_init (log /tmp/reg39_*, diretti senza pipe).

**Fixture, assunzioni, negativi e limiti.** Banco: stub a sequenza (RETSEQ 4
valori/sid, contatori SCNT) perche' 17BE18/C7E04 hanno chiamate ripetute con
semantiche diverse; stub speciale 127984 che scrive 3 out-byte da fixture
OUTCELL; caso micro two-pass con blink land ricavato via objdump (mov
blink,<land>; push_s blink: l'epilogo millicode legge blink dalla MEMORIA,
non dal registro - lessonza appresa dopo 4 tentativi documentati nel
rapporto). Fixture: ctx 0x681F5C sentinella 0xA5, modo 0xC8E80C, ring
0x47BBB0..0x47BCD0 con gate iniziale 0x5A (prova il reset: senza reset
l'EA sarebbe 0x47BD28 non mappato -> fault). Negativi: gate1/gate2 senza
scritture (sentinelle intatte), bits_priority (0x1E -> SOLO 0xB, gate=1),
ctxwrite senza enqueue (ring[0] sentinella, gate=0), 14941C!=0 -> niente
177460, 4110/177484 ripristinano r15=1, C9750==0 forza ret 0, [0x47BBB4]
slot-0 del lettore MAI scritto dal writer, CNT esatto + "nessuna chiamata
extra" in ogni caso. Limiti: produttori runtime del gate, contenuti reali
delle code, writer 0x4110/0x4111 (9/0xA), concorrenza tra i 5 chiamanti e
significato dei motivi {3,4,5,6,0xB,0xC,0xD} restano interpretazione/da
provare; gate e ring sono celle RAM runtime nel gap di load: SOLO fixture
del banco; nessun hardware; NON_INSTALLARE; circa 10% invariato.

**Agenti e MCP.** Agente `rw-review-39` (tools.agents.spawn, atteso e
integrato): revisione statica indipendente C1-C7 CONFERMATA (census triplo
metodo, millicode, controesempi, validatore 0x7D unsigned/signed, valori
ENQ); precisazioni INTEGRATE (bl_s 16-bit a 0x65CAEE, sync objdump per
l'attribuzione 0x4405, ld.ab, limiti dichiarati). Appunti
tmp/it39/REVISIONE_rw_review_39.md e copia in
Risultati/GUI_S33/aslv_ring_writer_agent_review_rw39_20261101.md. Server
MCP: mcp_pmb_nikon (prepare iniziale + record finale; recall it.37). REA
non presente tra i connettori. Strumenti: bash/python3, objdump/objcopy GNU
ARC700, Runner sim (podman), tools.agents. Nessun hardware/USB/SD.
NB: lo strumento «task con agente explore» non esiste in questo ambiente;
usato l'equivalente tools.agents.spawn.

**Prossimo passo concreto (non ripetitivo).** (a) **CPU dei writer
0x4110/0x4111** (accodano 9/0xA con guardia word[0x47BBB4+4*gate]!=0xA,
it.37): eseguirli con fixture del ring prova l'APPEND senza reset e
chiude la famiglia dei writer del sottosistema gate (possono far crescere
il gate oltre 1 tra un 0x65C720 e l'altro). (b) Alternativa: produttori
dell'evento 0x100 (13 siti 17BF60, in particolare 0x659D3C DENTRO 0x4405).
Il punto it.39 e' CHIUSO: non rieseguire il verificatore ring writer.

---

**Domanda affrontata.** Prossimo passo it.36: handler 0x100
(0x65B1CC, record ev 0x0100 del registro p3 a 0x783B50, PRIMO
chiamante dell'helper 0x65D098, writer [ctx+4] 2/6 via
0x65B212/0x65B2EA nel census it.25) — mai decodificato né eseguito.
Cosa fa attorno all'helper? (1) con byte gate [0x47BBC8] > 0
riconsegna davvero (node,ev,arg) ORIGINALI a 0x65B060 e apre una
finestra via tabella runtime? (2) con gate==0 arma davvero lo
stato 6 ([ctx+4]:=6, +0x1C:=1, +0x1D:=0, +0x1E:=1) sotto
modo/stato/guardia? (3) il ciclo 0x100→helper→0x81→teardown→0 può
RI-ARMARE lo stato 6 nella stessa invocazione? (4) EA vera della
ld.as 0x65A09A il cui commento GNU ;0x659fa8 cade nel codice?

**Risultato verificabile e significato.** [Rapporto nuovo](S33_GUI_AutoSceneLiveView_Handler_100_CPU_20261101.md),
[verificatore nuovo](../Python_Trace_Scripts/s33_verify_aslv_h100_cpu.py),
[evidenze finali](../Risultati/GUI_S33/aslv_h100_cpu_20261101T194718263688Z/),
[riesecuzione identica](../Risultati/GUI_S33/aslv_h100_cpu_20261101T194824137656Z/).
**PASS_ASLV_H100_CPU**: 12/12 casi CPU su byte ORIGINALI x2 run
identiche (fault 0xDEADB001..0C). CONFERMATO in CPU: testa
17083C(1)+1707D8(2)+149028(node,0xA)+helper(r1/r2 leftover)+
C7DD8(r0=ritorno helper invariato)+65C720(node); PATH A (gate>0):
[ctx+4]:=2, C5870(r0=costante 2, NON gate byte, ritorno
inutilizzato), CF538(0)=[0x3657BA]:=0, RICONSEGNA ORIGINALE
0x65B060(node,ev,arg) via r16/r15, word[0x47BBB4+4·gate] →
0x65E900 → packed(idx,arg) → 1453E4(idx,arg); PATH B (gate==0):
getter modo; 0x7E con sotto-rami CD5AC/arg 0xFFFFFF80/D10E8/
65D590(node,0x86)+uscita; !=0x7E con gate C7E04==1/[ctx+0xC],
stato==2 o D10C4!=0, DE254==0x15, guardia 0xCA310: ==1 → ARM
[ctx+4]:=6 + byte 1/0/1 su +0x1C/+0x1D/+0x1E + 65DB78/145150/
14905C(node,4,1000,1000,0)/176828(3,1,0x32)/145C3C(0x30D40
delay)/176828(3,0,0x32); !=1 → 17BF60 x2/12CAD4(0x00B00106)/
141CE8/17083C(2)/1453E4(4,[ctx+0x2A]). CATENA (caso 9 chain_rearm,
helper REALE + b060 REALE, stato 6+guardia 1+gate 0+modo 0x2B+
arg18 0x100+D10C4=1): helper→stato 2→teardown completo→stato 0→
handler pathB legge stato 0, D10C4!=0 → RE-ARMA stato 6 NELLA
STESSA INVOCAZIONE (finale [ctx+4]=6, +1C=1, +1D=0, +1E=1,
[ctx+0x18]=0 cancelled). Epilogo condiviso 0x659F8C→pop
0x33418C (r16,r15,r14,r13; 4 tail: h100/0x7CEA/0x581-0x2701/
0x65D13C). MAPPER 0x65E900 (9 chiamanti) provato REALE: word==0→0
SENZA chiamate; 149028([0x681FBC],6); jump table 0x65E936 →
3→0xA7, 4→0x000100A7(arg1), 5→0x000300A7(arg3), 6→0x000400A7
(arg4), 7..10→0, 11→0x4D, 12→0xA7, 13→0x000200A7(arg2).
SOTTOSISTEMA GATE (RAM runtime, gap di load 0x428600..0x5FE800,
NON nel dump): 0x65C720 (5 chiamanti: 2 in 0x4405, 0x440E, h100,
0x4006) azzera [ctx+0xC] (0x65C780) e [0x47BBC8] (0x65C786), poi
accoda word {3,4,5,6,0xB,0xC,0xD} in [0x47BBB8+4·gate] e
INCREMENTA il byte gate: RING di motivi di riapertura; writer
aggiuntivi 0x4110 (accoda 9) e 0x4111 (accoda 0xA); reader byte:
h100, 0x440E (0x65A092 cella diretta), 0x180 (0x65C31E esce se
!=0), 0x4405, 0x4006; ALIAS: 0x65D390 (pool 0x65D484) e 0x7D40
(0x65AC48) leggono 0x47BBB8 come array di record stride 10;
0x65C920 = return &0x47BBB8; POOL: 0x47BBC8 {0x659598, 0x65A3B0,
0x65C400}, 0x47BBB4 {0x659CD8, 0x65B390, 0x65CC28}, 0x47BBB8
{0x659CD4, 0x65AC48, 0x65B388, 0x65C914, 0x65C924, 0x65CC24,
0x65D484}; PRODUTTORI evento 0x100: 13 diretti via 17BF60
(incluso 0x659D3C DENTRO l'handler 0x4405) + 1 via coda 0x169EB4.
LEZIONI: (1) ld.as [pcl,-240] a 0x65A09A: arc-elf32-as assembla
-240 ESATTAMENTE nei byte originali 101700f6, EA VERA
(pc&~3)+(-240)·4=0x659CD8 dove sta il pool 0x0047BBB4, COMMENTO
GNU ;0x659fa8 ERRATO (non scalato ×4; plain LD corretto);
provata in CPU (caso ldas_ea_659cd8). (2) LDB_S è UNSIGNED
(manuale ARCompact 5115-029 "Load unsigned byte"; sem7.c ZEXTQISI):
il ble 0x65B20A ≡ "gate==0", byte ≥0x80 → path A (coerente it.42
ldw_s.x); il caso-segno originale è stato RIFORMULATO come
gate10_far (path A con indice ring 0x10 → cella 0x47BBF4), non
indebolito. Conseguenza AkeruOS: un evento 0x100 consegnato alla
finestra può lasciare stato 6 (ri-armato) o 2 (path A), MAI
assumere stato 0 dopo il ritorno; il ritorno del gestore è il
ritorno dell'ultima chiamata del percorso; il gate va letto
unsigned.

**Fonti, indirizzi e comandi.** Finestre CPU byte-originali: .h100
0x65B1CC..0x65B3A8 (0x1DC byte con pool 0x65B388=0x47BBB8/
0x65B38C=0x681F60/0x65B390=0x47BBB4/0x65B394=0x681F5C/
0x65B398=0x681F8C/0x65B39C=0x30D40/0x65B3A0=0x307F/
0x65B3A4=0x00B00106), .e900 0x65E8FC..0x65E974 (pool 0x65E8FC=
0x681FBC, jump table 0x65E936, pool 0x65E970=0x000300A7), .epi2
0x659F8C, .mili 0x334100..0x3341E4, .gget/.modeget/.modepool,
.epi 0x659588, .b60, .helper, .pool9 0x659CD4 (pool 0x47BBB8/
0x47BBB4), .ldas 0x65A09A..0x65A0A6 (101700f6 3578 0080
62084002). `python3
Python_Trace_Scripts/s33_verify_aslv_h100_cpu.py` →
PASS_ASLV_H100_CPU **20261101T194718263688Z** + identica
**194824137656Z** (4 run parziali precedenti con correzioni
oracolo documentate nel rapporto). Statica di supporto
tmp/it37/ (h100_decode.py, ldas/ oracolo assemblatore).
Regressioni 10/10 PASS: snapshot record init 194846240683Z,
guard setter census 194847043201Z, service raise pending
194848Z, wm notify registry 194902956970Z, notify reactors
194905762663Z, aslv slot handlers 194912278380Z, aslv open
wrapper 194933261390Z, aslv close handler 194954598917Z, aslv
b060 arg18 clear 195015099943Z, aslv helper d098 195035321665Z.

**Fixture, assunzioni, negativi e limiti.** ctx 0x681F5C fixture
0xD0 byte sentinella 0xA5 (stato +4 word, +8=0xFF, +9=0x5A, arg18
+0x18 word, +0x2A byte, nodo salvato +0x60 word=0xBEEF letto da
0x65E900); guardia 0x365751; modo 0xC8E80C; gate system
0x47BBB0..0x47BBD0 fixture (tbl[0..3] a 0x47BBB4..C4, byte gate a
0x47BBC8, variante far 0x50 byte per il caso 12); celle
0x442734/0x3669EC/0x3680F0 per il teardown reale. ~30 callee
stub; originali eseguiti: corpo handler 0x100, millicode,
epiloghi 0x659F8C/0x659588, getter modo/guardia, mapper 0x65E900,
helper 0x65D098 e corpo 0x65B060 nelle catene. Negativi: word 0
del mapper → NESSUNA 149028(saved,6) contro word 4/0xB/3 con la
chiamata; stato 5+D10C4==0 → uscita senza scritture; guardia 0 →
NESSUNA scrittura dello stato 6; registri vivi tracciati (r1=
0x681F60 dopo lo store, r0=2 per C5870, r0=stato per 136280/
D10C4, r1/r2=0xB/0xFA residui dopo il teardown reale, r1=9 dopo
mov r1,9); assert "nessuna chiamata extra" + sentinelle in ogni
caso; celle fixture intatte dove il firmware non deve scrivere.
Limiti: tabella 0x47BBB4 e byte 0x47BBC8 RAM runtime (gap di
load): i valori nei casi sono imposti dal banco, SOLO la mappa
word→finestra di 0x65E900 è codice originale provato; ring
writer 0x65C720 e writer 0x4110/0x4111 decodificati solo
staticamente (mai eseguiti in CPU); produttori runtime del gate
e scheduling non provati; concorrenza tra i 5 chiamanti
dell'helper e i lettori del ring APERTA; significato di 0xA7
(167)/0x4D (77) e dei valori ring {3..13} resta interpretazione;
gate 0xFF su hardware non decisibile dall'offline (ISA: unsigned;
nessuna prova fisica); no hardware/boot/rendering/scatto;
NON_INSTALLARE, ~10% invariato.

**Agenti e MCP.** **Agente `h100-review-37`** (tools.agents.spawn,
atteso e integrato): revisione statica ex-novo con census DOPPIO
(sweep objdump + scanner byte-level derivato dai sorgenti
binutils; coincidenza 100%) → C1 decodifica CONFERMATA punto per
punto con 4 precisioni INTEGRATE (uscita immediata dopo
65D590(node,0x86) che azzera anche [ctx+0x30]/[ctx+0x34];
[ctx+0x30]/[ctx+0x34] ricevono il ritorno di 145D1C; gate riletto
non rivalidato >0; C5870 chiama 158D04(0x42700002,0x80,0,0) con
ritorno inutilizzato e CF538 è setter [0x3657BA]:=0); C2 census
(0x65B1CC=0 chiamanti, 0x65C720=5, 0x65E900=9, 0x65DB78=1
DEDICATO a h100, 0x65D590=4) CONFERMATI; C3 epiloghi/millicode
CONFERMATI; C4 jump table 0x65E936 CONFERMATA byte per byte; C5
writer 0x4110 (accoda 9)/0x4111 (accoda 0xA) e attribuzione pool
0x65CC24/28 → 0x4006/0x4110/0x4111, 0x65D484 → 0x65D390 array
record, 0x65AC48 → 0x7D40; C6 produttori evento 0x100 (13+1
siti); C7 nessun controesempio, nessun accesso ctx fuori
d'insieme. Appunti /tmp/h100rev37 (REVISIONE.md, CONTROLLENTE.md,
listati). Server MCP: mcp_pmb_nikon (prepare iniziale + record
finale). REA non presente tra i connettori. Strumenti: bash/
python3, objdump/as GNU ARC700, Runner sim, tools.agents.
Nessun hardware/USB/SD.

**Prossimo passo concreto (non ripetitivo).** (a) **CPU del ring
writer 0x65C720** (0x65C720..0x65C928, finestre ~0x210 byte con
già 2 disassemblati): decodifica completa già disponibile — porte
0xC7E04()==0, query coda 0x17BE18 per 0x3180/0x3181, bit di r17
(0x135A84), 0x137774/0xDE3E4/0x127278/0xC7BDC/0x127284, enqueue
word in [0x47BBB8+4·gate] + incremento — eseguirlo con byte
originali e fixture del ring chiude il ciclo
ring→gate→h100→0x65E900→finestra. (b) Alternativa: CPU del
pattern gate condiviso dentro 0x4405 (0x659A80/0x659C14 chiamenti
a 0x65C720; 0x659A9A/0x659C6E a 0x65E900) o dei writer
0x4110/0x4111 (accodano 9/0xA con guardia
word[0x47BBB4+4·gate]!=0xA). (c) Alternativa: produttori evento
0x100 (13 siti 17BF60, in particolare 0x659D3C dentro 0x4405). Il
punto it.36 è CHIUSO: non rieseguire il verificatore h100.

**Domanda affrontata.** Prossimo passo it.34(a): CPU dell'helper
0x65D098 della finestra AutoSceneLiveView (ctx 0x681F5C) —
decodificato e congelato in it.34 ma mai eseguito. Il gate
stato==6 ∧ guardia(0xCA310)==1 produce davvero la sequenza
cortocircuitata 149028(node,4) + 149028(node,0xF) +
176828(3,0,0x32) + [ctx+4]:=2 + 0x65B060(node,0x81,1) +
[ctx+0x1C]:=0 + epilogo condiviso? E cosa fa/restituisce l'helper
quando il gate fallisce? Il ciclo stato6→0x81→teardown resta
coerente quando 0x65B060 e' invocato DALL'helper e non dal
registro?

**Risultato verificabile e significato.** [Rapporto nuovo](S33_GUI_AutoSceneLiveView_Helper_D098_CPU_20261101.md),
[verificatore nuovo](../Python_Trace_Scripts/s33_verify_aslv_helper_d098_cpu.py),
[evidenze finali](../Risultati/GUI_S33/aslv_helper_d098_cpu_20261101T192248034163Z/),
[riesecuzione identica](../Risultati/GUI_S33/aslv_helper_d098_cpu_20261101T192310898166Z/).
**PASS_ASLV_HELPER_D098**: 7/7 casi CPU su byte ORIGINALI
(fault 0xDEADB001..07) x2 run identiche (piu' prima coppia
191426/191449Z). CONFERMATO in CPU: gate a due stadi (bne stato
PRIMA del bl 0xCA310: getter saltato se stato!=6; casi
d098_gate_s5 ret==5 con log vuoto, d098_gate_g7 ret==7,
d098_gate_g0 ret==0); percorso pass completo (caso
d098_pass_s6_g1 con 0x65B060 stub); INTEGRAZIONE con handler
0x81 REALE in 3 catene (d098_chain_teardown_2b: stato 6→2→
cancel 0x100 + teardown→stato 0, +0x1E:=1, celle gate 0, poi
helper [ctx+0x1C]:=0; d098_chain_nocancel_2c: arg18 0x101 NON
cancellato, teardown comunque; d098_chain_7e: 149028(node,9)+
65DDA8(0,0) nel teardown reale). RITORNI distinti: r0 = parola
stato (gate-1 fallito) / valore guardia (gate-2) / ritorno di
0x65B060 (pass). Census: 5 chiamanti bl tutti blocco 2 attribuiti
a ev 0x0100/0x0600/0x3301/0x3181/0x0180 (0x65C18C cade in
0x65C178 ev 0x3301, correzione della stima manuale 0x600); zero
LE/pool per 0x65D098/0xCA310/0x659588; 12 rami b a 0x659588 nel
blocco 2 (famiglia epilogo condiviso); [ctx+0x1C]=0x681F78 con 6
pool in 0x4405/0x4406/0x440E (correzione revisione)/0x381-0x401,
alcuni come BASE per campi vicini. Conseguenza AkeruOS: lo stato
6 e' consumato da un helper condiviso che consegna 0x81
DIRETTAMENTE all'handler (non via registro/WindowManager): dopo
un ritorno dell'helper il teardown e' gia' avvenuto (stato
osservabile 0) e il valore di ritorno e' stato/guardia letti,
non un codice di errore.

**Fonti, indirizzi e comandi.** Finestre CPU byte-originali:
.mili 0x334100..0x3341E4, .gget 0xCA30C..0xCA318 (pool
0x365751 + getter 6 byte 'ld r0,[pcl,-4]; ldb_s; j_s'),
.epi 0x659588..0x659594 (mov sp,fp; ld.ab fp; b 0x334194),
.helper 0x65D098..0x65D0EC (pool 0x65D0E8=0x681F5C; tail b
0x65D0E4 disp -15196 eseguito CORRETTAMENTE dal sim insieme al b
-3298300 dell'epilogo: la divergenza it.44 non si generalizza,
nessun trampolino); catene con .b60/.modeget/.modepool/.poolctx/
.poolg di it.34. Chiamanti congelati: 0x65B1F6/0x65BFA0/0x65C18C/
0x65C23C/0x65C30E. `python3
Python_Trace_Scripts/s33_verify_aslv_helper_d098_cpu.py` ->
PASS_ASLV_HELPER_D098 **20261101T192248034163Z** + identica
**192310898166Z** (precedenti 191426303960Z/191449123984Z).
Statica di supporto tmp/it36/ (helper_decode.py, helper_decode2.py,
le_probe.py, sola lettura). Regressioni 9/9 PASS (snapshot record
init 191539Z, guard setter census 191540Z, raise pending 191552Z,
wm notify registry 191556Z, notify reactors, aslv slot handlers,
aslv open wrapper, aslv close handler, aslv b060 arg18 clear).

**Fixture, assunzioni, negativi e limiti.** ctx 0x681F5C fixture
0xD0 byte sentinella 0xA5 (stato +4 word, arg18 +0x18 word);
guardia 0x365751 fixture con sentinelle 0xA3; ingresso
0x65D098 con r0=NODE e r1/r2 garbage 0x11/0x22 (MORTI: l'helper
imposta tutti gli argomenti delle chiamate). ~25 callee stub
nelle catene; originali eseguiti: corpo helper, millicode
(0x33412C/0x334194), getter guardia 0xCA310, epilogo condiviso,
corpo 0x65B060 con getter modo 0xCAD30. Negativi: getter saltato
se stato!=6 (log vuoto + ret==5 distinto da guardia 1); nessuna
chiamata oltre il conteggio atteso; [ctx+0x18] mai scritto
dall'helper (casi 1-4 invariato; catene: modificato SOLO dal
b060 reale, cancel esclusiva 0x100, 0x101 intatto); [ctx+0x1C]
scritto SOLO sul pass (stb, vicino 0x1D intatto); celle
guardia/gate e sentinelle sempre verificate. Limiti:
[ctx+0x1C]:=0 dipende da r15=0 che sopravvive a bl 0x176828 e
bl 0x65B060 — provata SOLO staticamente (revisione: 0x176828
push 0x334128/epilogo b 0x33418C, 0x16C8E4 idem, 0x65B060 push
0x334124/epilogo b 0x334184, bilancio 20/20; nel banco sono
stub); significato runtime stato 6, eventi 0x600/0x3301,
servizi 0x149028/0x176828 NON identificati (in 0x176828 case 3
l'arg 0x32 e' DEAD: lavoro effettivo 0x16C8E4(0x51,8,0));
produttori runtime dello stato 6 e della guardia 1 APERTI;
concorrenza/schedulazione non provate; jump table relative non
coperte dal LE scan; no hardware/boot/scatto; NON_INSTALLARE,
~10% invariato.

**Agenti e MCP.** **Agente `d098-review-36`** (tools.agents.spawn,
atteso e integrato): revisione statica ex-novo su TUTTI i 16
blocchi -> C1 (corpo/gate) C2 (r15 preservato: controesempio
escluso) C3 (tail/epilogo/ritorni; atterraggio su 0x659588 NON su
0x659584/86 del flusso 0x4405) C4 (census 5/5, zero vie
indirette) C5 (12 rami a 0x659588) C7 (nessun controesempio)
CONFERMATI; C6 correzione INTEGRATA (pool 0x65A3E0/0x65A49C =
handler 0x440E 0x659FA0, non 0x4406; alcuni pool usano 0x681F78
come base per campi vicini) + docstring verificatore corretto e
rieseguito; correzione di registro: pairing millicode
0x334120<->0x334180 (non 0x33417C = pop di 0x33411C). Appunti
/tmp/rev36 (REVISIONE.md + listati 16 blocchi), PMB outbox 395
(record_batch proprio). Server MCP: mcp_pmb_nikon (prepare
iniziale + record_batch finale di questa sessione). REA non
presente tra i connettori. Strumenti: bash/python3, objdump GNU
ARC700 (work/build-arc), Runner sim, tools.agents. Nessun
hardware/USB/SD.

**Prossimo passo concreto (non ripetitivo).** (a) **Produttori
dello stato 6** di [ctx+4] (0x681F60): writer statici gia'
censiti in it.25 (0x65B1CC handler 0x100 scrive 2/6 via
0x65B212/0x65B2EA gate [0x47BBC8]) — decodificare/CPU-provare
l'handler 0x100 (0x65B1CC, PRIMO chiamante dell'helper) per
chiudere il ciclo 0x100→stato6→helper→0x81: e' il pezzo che
manca per conoscere CHI porta la finestra in stato 6 e quando
la consegna cortocircuitata scatta davvero. (b) Alternativa:
contesto fratello 0x681F98 (handler 0x7D40 0x65AB5C, writer
0x681FB0/B4/B8). (c) Alternativa: census/decodifica dei restanti
rami a 0x659588 (0x65D68E e famiglia 0x65Dxxx oltre l'ultimo
handler p3). Il punto it.34(a)/it.36 e' CHIUSO: non rieseguire
il verificatore 0x65D098.

**Domanda affrontata.** Punto aperto it.30(a) — produttore/
consumatore di [ctx+0x18] (0x681F74) della finestra AutoSceneLiveView
(ctx 0x681F5C) dopo l'apertura: chi cancella lo 0x100 residuo che
l'handler 0x4405 lascia quando la riapertura differita e' bloccata
(casi it.30 7-9). Recupero del lavoro it.33 interrotto per assenza
di output (sopravvivevano solo i censimenti tmp/it33, mai provati).

**Risultato verificabile e significato.** [Rapporto nuovo](S33_GUI_AutoSceneLiveView_Handler_081_B060_CPU_20261101.md),
[verificatore nuovo](../Python_Trace_Scripts/s33_verify_aslv_b060_arg18_clear_cpu.py),
[evidenze](../Risultati/GUI_S33/aslv_b060_cpu_20261101T190743571858Z/),
[riesecuzione identica](../Risultati/GUI_S33/aslv_b060_cpu_20261101T190802453662Z/).
**PASS_ASLV_B060_HANDLER_081**: 9/9 casi CPU su byte ORIGINALI
(fault 0xDEADB001..09) x2 run identiche. 0x65B060 = handler evento
0x0081 del registro p3 (record 8, ev@0x783B48, handler@0x783B4C,
unica LE in 16 blocchi); 3 chiamanti bl (0x6599C6 differito 0x4405,
0x65B224 handler 0x100, 0x65D0DE helper 0x65D098). Corpo: prologo
17083C(1,r1,r2)/148E68/148E14 (r1/r2 MORTI dopo il save r17/r16);
gate 0xD10C4()==1 AND [ctx+4]==3 -> ritorno anticipato con
r0=[ctx+4] (NON tocca [ctx+0x18], casi 3/8); cancellatore
[ctx+0x18]==0x100 -> :=0 + 0xCB5B0(0x100), 0x101/altro NON toccato
(casi 2/9) — RISPOSTA it.30(a): lo 0x100 differito bloccato e'
consumato dall'handler 0x81; teardown stati 2/3: [ctx+0x1E]:=1,
[ctx+4]:=0, [ctx+0x1D]:=0, [[0x3669EC]+0xF0]:=0 e [0x442734]:=0
(LE STESSE celle gate dell'handler 0x4405 percorso 0x55, it.30),
CD558->CDF4, 14A228/65BBD8/65DAD0, mode getter ORIGINALE (7E ->
149028(node,9)+65DDA8(0,0) con r1:=0), 143AFC(0x16/15/14),
CE5C8->2106F4(1), 660C34, AD90C(ret,0x110), bl.d 145C3C con delay
slot pool 0x65B1C8=0x7530 (145C3C(30000)), 145150(node), mode
2C->14905C(node,1,500)/68->14905C(node,0x13,100), CD8CC ret0 ->
14905C(node,0xB,250), 12845C ret!=0 -> 14905C(node,0xE,400),
65CF58(node); stati altri -> solo 143AFC x3. Writer [ctx+0x18]
ASLV COMPLETI: 0x659586 (apertura, arg), 0x65996A/0x6599B4
(chiusura differita 0x100/0), 0x65B0B0 (cancel). LE 0x681F74 = 0
ovunque; LE 0x681F5C = i 20 pool finestra (blocco 2). Helper
0x65D098 decodificato (statico+freeze, NON in CPU): stato6 ∧
guardia(0xCA310)==1 -> 149028(node,4)+149028(node,0xF)+
176828(3,0,0x32)+[ctx+4]:=2+0x65B060(node,0x81,1)+[ctx+0x1C]:=0,
tail b 0x659588; gate-fallito stesso tail. Conseguenza AkeruOS:
il completamento post-differito passa dalla consegna 0x81, non da
un nuovo evento WindowManager; la coda deve gestire cancel 0x100,
teardown condiviso gate e ritorno anticipato = stato.

**Fonti, indirizzi e comandi.** Finestre CPU byte-originali: .mili
0x334100..0x3341E4, .modeget 0xCAD30..+pool 0xCAAC4, .poolctx
0x65AFF8=0x681F5C, .poolg 0x65B00C=0x442644, .b60 0x65B060..0x65B1CC
(pool interni 0x65B1C4=0x3669EC, 0x65B1C8=0x7530), sha .b60
77419751be83...bddfb8. Census bl su 16 blocchi = 3 (indirizzi
sopra); census store disp 0x18 regione ASLV = 6 siti. `python3
Python_Trace_Scripts/s33_verify_aslv_b060_arg18_clear_cpu.py` ->
PASS_ASLV_B060_HANDLER_081 **20261101T190743571858Z** + identica
**190802453662Z** (9 casi: b060_clear_s5, b060_noclear_101,
b060_early_s3, b060_teardown_s2, b060_teardown_s3_2c,
b060_teardown_s2_68, b060_teardown_7e, b060_d10c41_s5,
b060_teardown_s2_101). Censimenti it.33 rilanciati concordanti
(census_loaders4: 64 loader/20 pool; census_all_st18: 6 store).
Regressioni 8/8 PASS: snapshot record init **185902847062Z**,
guard setter census **185903622471Z**, service raise pending
**185914Z**, wm notify registry **185919051518Z**, notify reactors
**185921854665Z**, aslv slot handlers **185928361135Z**, aslv open
wrapper **185948839763Z**, aslv close handler **190010031532Z**.

**Fixture, assunzioni, negativi e limiti.** ctx 0x681F5C fixture
0xD0 byte sentinelle 0xA5 (stato +4 word, [ctx+0x18] +0x18 word,
+8=0xFF/+9=0x5A avanzi); modo 0xC8E80C per caso; gate
[0x442734]/[0x3669EC]=0x368000/[0x3680F0]; ~25 callee STUB
(logger {sid,r0,r1,r2}, ritorni imposti); originali eseguiti: corpo
.b60, millicode, getter modo 0xCAD30. Negativi: cancel SOLO a
0x100 (0x101 intatto anche nel teardown); gate d10c4==1 NON
blocca da solo (solo con stato 3, che restituisce [ctx+4]);
CD558/CD8CC/12845C/148E68 ret opposti -> chiamate assenti;
stati altri non toccano stato/celle gate; LE [ctx+0x18] diretta
zero. Limiti: statica + CPU fixture, no hardware/scheduler/
concorrenza; significato runtime stati 2/3/5, evento 0x81 e
servizi NON identificati; helper 0x65D098 NON eseguito in CPU;
contest fraterno 0x681F98 (handler 0x7D40 0x65AB5C, writer
0x65AC0C/0x65AC18 -> 0x681FB0/B4/B8) e handler 0x80 0x65AC58
APERTI; NON_INSTALLARE, ~10% invariato.

**Agenti e MCP.** **Agente `b060-review-34`** (tools.agents.spawn,
atteso e integrato): revisione statica ex-novo (objdump proprio,
census su 16 blocchi + TBIB/TBM/P1RES, LE a ogni offset) ->
C1/C2/C3 CONFERMATI; C4 PARZIALE (3 chiamate omissionate helper
0x65D098: 149028(node,4)@0x65D0BC, 149028(node,0xF)@0x65D0C4,
176828(3,0,0x32)@0x65D0D0) INTEGRATE; C5 CONTROESEMPIO INTEGRATO:
0x65AC0C/0x65AC18 appartengono all'handler 0x7D40 (0x65AB5C) con
base pool 0x65AC50=0x681F98 (0x65ABAC/0x65ABB4) -> scrivono
0x681FB0/B4/B8 NON [ctx+0x18] ASLV (attribuzione errata nella
prima stesura, riverificata byte-esatto e verificatore rieseguito
con nota corretta); C6: nessun altro writer gate nel corpo, zero
usi r16/r17, nessun ramo tralasciato, ritorni confermati. Appunti
/tmp/rev34, PMB outbox 393. Server MCP: mcp_pmb_nikon (prepare
iniziale + record_batch finale). REA non presente tra i
connettori. Strumenti: bash/python3, objdump GNU ARC700
(work/build-arc), Runner sim, tools.agents. Nessun hardware/USB/SD.

**Prossimo passo concreto (non ripetitivo).** (a) **CPU dell'helper
0x65D098** (stato 6 ∧ guardia 1 -> stato 2 + consegna 0x81
cortocircuitata con (node,0x81,1)): chiude il ciclo stato6→0x81 e
riusa finestre/stub del verificatore nuovo. (b) Alternativa:
contesto fratello 0x681F98 (handler 0x7D40 0x65AB5C record 6,
writer 0x681FB0/B4/B8) per la famiglia di contesti della finestra.
(c) Alternativa: writer 0x65B212/0x65B2EA dell'handler 0x100
(stati 2/6, gate [0x47BBC8]). Il punto it.30(a)/it.33 e' CHIUSO:
non rieseguire il verificatore 0x65B060.

## Iterazione 30 — 1° novembre 2026 — HANDLER 0x4405 CHIUSURA AUTOSCENELIVEVIEW DECODIFICATO E CPU-PROVATO: ciclo apertura->stato->chiusura della finestra CHIUSO. Tre destini di [ctx+0x18] (word scritta dall'apertura 0x659554 con r2): ==0x100 COMPLETAMENTO (0x14504C(node,0x12)!=6 -> CAFBC+Caff8(3); [ctx+0x24]:=1; post 169EB4(node,0x80,0)+(node,0x100,0); 65CFA0; 14503C(node,0)->bclr bit0xA->1450C8; ritorno 0, stato resta 0); ==0x101 RIAPERTURA DIFFERITA ([ctx+0x18]:=0x100; CAFBC(ctx); Caff8(3); 65CFA0; 65AC58(node,r1,r2) ri-dispatch con argomenti ORIGINALI; rilegge [ctx+0x18]==0 -> ritorno 0; query 17BE18(0,0x100,0x100)!=0 -> ritorno 0; cfg[2]!=0 oppure cfg[1]!=0 con lettori ORIGINALI 0x16F920 -> ritorno 0; ALTRIMENTI [ctx+0x18]:=0, 661780(0), [ctx+4]:=2 a 0x6599C2 (writer n.2), 65B060(node), purge 17BF60(0,0x80,0x307F), ritorno 0); ALTRO valore = PERCORSO PUNTATORE (660C34(valore); [ret+0xF0]>0 -> seconda 660C34 con r0=byte letto + AD90C(ret2,0x110); catena modi {0x6F,0x70,0x6E,0x7A,0x7B,0x7C}->15A5C8; coda 84 chiamate fino 809DF4(1,1)). TEARDOWN: [ctx+4]:=0 (word st_s 0x65964A, writer n.1) + [ctx+0x39/0x2C/0x1C/0x26/0x1D/0x1F/0x23]:=0, [ctx+0x1E]:=1, [ctx+0x28]:=0 con stw_s HALFWORD 16 bit; [ctx+8]/[ctx+9]/[ctx+0x18] NON toccati; 15AD44()!=0 -> [ctx+0x38]:=0. GATE INGRESSO 0x14504C(node,0x12)==0x55 -> [0x442734]:=0 e [[0x3669EC]+0xF0]:=0 (doppia indirezione). TIMER 64-bit [0x682020]/[0x682024] = ctx+0xC4/+0xC8 (pool 0x659924): entrambe zero -> skip; elapsed=now-t0 (sub+sbc) >= 0x16E360 -> 143AFC(0xC) diretto; else 145C3C(1500000-elapsed) POI SEMPRE 143AFC(0xC) (0x659630 fall-through). CHIUSURA RISORSA CaptureMenu: 145B08(node,0x4800,0) (9<<11, NON 0x1200) + 8101FC(0) + 145654(node,0x480C) delay-slot + D148C(ret,0,0). MODO/GUARDIA con getter ORIGINALI (0xCAD30 -> byte 0xC8E80C via ld.as pool 0xCAAC4, statico 0x2C; 0xCA310 -> 0x365751): 0x2C+guard7 catena A, 0x2C+guard!=7 catena B (loop 1421C8), 0x2C+D0924()!=0+guard!=7 blocco lungo (15A5C8/201830/D08C8/CFDEC, query 0x3101). CELLE NOTIFICA: CF554#1==1 -> [0x366AF1]==1: post 0x80+0x100; else [0x366AF0]==1: post 0x80 e cfg[1]==0 -> 0x81; poi ENTRAMBE :=0; CF554#2 SEMPRE chiamata (bne_s 0x659846 -> 0x659890); #2==1 -> CE6A0 e SOLO SE CE6A0()==0 query 17BE18(0,0x80,0x80)/(0,0x100,0x100), una !=0 -> 12CAD4(0x00B80035). 0xCAD38(1) a 0x659836 (setter statico it.23: [0x365753]:=1 -> il reattore 0x20EAF4 (0x700) lo legge per CaptureMenu ARG 0). RITORNO 0 via epilogo condiviso 0x65953C (mov sp,fp; ld.ab fp; b 0x334174); census bl 0x65959C = 0 chiamanti su TUTTI i blocchi (callback puro; LE unica a 0x783B14, record 0x4405 con id a 0x783B10); census LE propri: 0x659890->0, 0x6599C2->0, 0x682020->2 (pool 0x659924 + 0xB1D084 blocco 6). WRITER STATICI AGGIUNTIVI (revisione, NON eseguiti nei casi): [ctx+0x2B]:=1 a 0x659BFA (blocco modo 0x15), [ctx+0x30]/[ctx+0x34]:=0 a 0x659D2A/C (puntatore, CD5AC()==1), SECONDO writer celle gate a 0x659D54..0x659D5E (pool 0x659EE4/0x659EE8, percorso puntatore). NESSUN altro writer di [ctx+4]; NESSUN ritorno senza teardown

**Domanda affrontata.** Punto aperto it.28: decodificare e provare in
CPU l'handler 0x4405 (0x65959C, chiusura) — il writer più ricco di
[ctx+4] (0 e 2) e consumatore naturale del contesto predisposto
dall'apertura 0x659554 — per chiudere il ciclo
apertura→stato→chiusura della finestra AutoSceneLiveView.

**Risultato verificabile e significato.** [Rapporto nuovo](S33_GUI_AutoSceneLiveView_Close_Handler_4405_CPU_20261101.md),
[verificatore nuovo](../Python_Trace_Scripts/s33_verify_aslv_close_handler_cpu.py),
[evidenze](../Risultati/GUI_S33/aslv_close_handler_cpu_20261101T182145395518Z/),
[riesecuzione identica](../Risultati/GUI_S33/aslv_close_handler_cpu_20261101T182349872845Z/).
**PASS_ASLV_CLOSE_HANDLER_4405**: 13/13 casi CPU su byte ORIGINALI
(fault 0xDEADB001..0D) x2 run identiche (evidenze byte-identiche
salvo utc). Conseguenza AkeruOS: dopo una consegna 0x4405 la finestra
NON è semplicemente chiusa — il valore salvato [ctx+0x18] decide fra
completamento (stato 0, notifiche 0x80/0x100, [ctx+0x24]:=1),
riapertura differita (stato 2, purge eventi, gated da coda/cfg) e un
percorso puntatore; la chiusura tocca ANCHE il lato CaptureMenu
(risorsa 0x4800, stato [0x365753]:=1). La coda AkeruOS non può
assumere che una chiusura lasci lo stato a 0.

**Fonti e indirizzi.** Blocchi 0/2/3 V1.1; finestre CPU byte-originali:
`.mili` 0x334100..0x3341E4, `.guard` 0xCA2F4..0xCA31A (getter
eseguito), `.modeget` 0xCAD30..0xCAD38 + `.modepool` 0xCAAC4
(=0xC8E80C), `.cfgread` 0x16F920..0x16F928 + pool 0x16FA34
(=0x446808), `.wrap` 0x6593A0..0x659554 (epilogo condiviso
0x65953C→0x334174), `.h4405` 0x65959C..0x659EF0 (pool interni
0x65991C..0x65995B, 0x659CCC..0x659CEB, 0x659EE4..0x659EEC).
Registro p3: record 0x4405 id@0x783B10, handler@0x783B14 (unica LE
dell'indirizzo nei payload). Census bl 0x65959C=0 su tutti i blocchi.

**Comandi eseguiti ed esiti.** `python3 Python_Trace_Scripts/
s33_verify_aslv_close_handler_cpu.py` → PASS_ASLV_CLOSE_HANDLER_4405
**20261101T182145395518Z** + riesecuzione identica
**20261101T182349872845Z** (13 casi: m2c_g7_arg100, m2c_gN_arg100,
entry55, timer_rem, timer_exp, arg101_deferred, arg101_qblocked,
arg101_cfg1, arg101_cfg2, notify_f1, notify_f0, notify_q80, ptr).
Regressioni 7/7 PASS: snapshot init **182515483830Z**, guard setter
census **182516269256Z**, service raise pending **182527Z**, wm
notify registry **182531955480Z**, notify reactors **182534866498Z**,
aslv slot handlers **182541461679Z**, aslv open wrapper
**182602516302Z**.

**Fixture e assunzioni.** Contesto 0x681F5C fixture 0xD0 byte
(sentinelle 0xA5): [ctx+4] word stato pre-chiusura 6, [ctx+8]=0xFF /
[ctx+9]=0x5A (avanzi apertura), [ctx+0x18] per caso, timer a
[ctx+0xC4/+0xC8], byte alti di [ctx+0x28] a 0 (scrittura halfword).
Guardia 0x365751, modo 0xC8E80C, tabella cfg 0x446808 (byte 4·id),
celle 0x366AF0/0x366AF1, puntatore gate 0x3669EC→0x368000 (target
0x3680F0), celle gate 0x442734/0x3680F0, 0x365753 sentinella. ~91
stub da 10 byte (`push_s blink; mov_s r12,sid; mov r3,0x600;
jl_s [r3]`; common a 0x600 registra {sid,r0,r1,r2}, ritorna
`pop_s blink; j_s [blink]`); due coppie di stub a 4 byte di distanza
con sezione condivisa `mov_s+b_s`+coda. Ritorni stub imposti per caso
(rettab 0x368400). Assunzione: significato runtime degli stati
{0,2}, cfg[1]/[2], valori 0x100/0x101 di [ctx+0x18] NON identificato.

**Controlli negativi e regressioni.** Query coda/cfg[1]/cfg[2]
bloccano il writer n.2 (casi 7-9): stato resta 0, [ctx+0x18] resta
0x100, NESSUNA chiamata 0x661780/0x65B060/0x17BF60 dopo il gate;
gate 0x55: le due celle si azzerano SOLO con ritorno 0x55 (casi 1-2
con ritorno 0: sentinelle intatte); [ctx+8]/[ctx+9]/[ctx+0x38]/
0x365753 intatti senza gate; timer a zero → NESSUNA chiamata timer;
elapsed<soglia → 0x145C3C(1499000) esatto POI 143AFC(0xC); assert
«nessuna chiamata oltre il conteggio atteso» in ogni caso; percorso
puntatore completo (84 chiamate) senza scritture a [ctx+0x18]/
[ctx+0x24]/celle notifica. LEZIONI DI BANCO (nuove): (1) `stw_s` è
store HALFWORD 16 bit — fixture word su celle scritte con stw_s rendono
ingannevoli le assert a 32 bit ([ctx+0x28]); (2) il common logger NON
deve scrivere mirror in celle fisse vicino all'area log: lo slot
voce LOG+16k+4 collide (accaduto k=33 mirror r4 e k=34 retcell);
(3) `bl.d` con delay slot `ld r0,pool`: lo stub riceve il valore pool
come a0 (0x14949C/0x65E430, 0x145654/0x480C); (4) rami bcc_s 16 bit:
target=(pc&~3)+(s9<<1) (SLEIGH ARCompact.sinc 347-348), GNU concorda
su tutti i 105 rami compatti della finestra; (5) le differenze di
indirizzi (0x682020−0x681F5C=0xC4) vanno calcolate a macchina: un
errore a occhio (+0x60) ha prodotto fixture fuori cella e timer mai
eseguito.

**Limiti e non dimostrato.** Statica + 13 casi CPU con fixture:
nessun hardware/boot/rendering/scatto/persistenza; NON_INSTALLARE;
~10% invariato. ~91 callee STUB (inclusi 0x14504C, 0x169EB4,
0x17BE18, 0x17BF60, 0x14905C, 0x158D04, 0x65AC58, 0x65B060,
0x809DF4): comportamento reale non provato qui; 0xCAD38 scrive
[0x365753] solo come claim statico it.23. Produttori RUNTIME di
[ctx+0x18] (candidati: risultato packed 0x4405 del WindowManager
it.18 via 0x65AC58; 0x661780/0x65B060), di cfg[1]/[2], delle celle
0x366AF0/0x366AF1/0x442734/0x3669EC e del timer [0x682020]: APERTI.
Blocchi NON eseguiti nei casi (target stub rimossi; raggiungerli
esegue garbage e fallisce il probe): blocco lungo modo 0x2C
(D0924-gate, 15A5C8/201830/D08C8/CFDEC, query 0x3101), blocco modo
0x15 (con [ctx+0x2B]:=1), blocco modo 0x7E (celle [ctx+0x30/0x34],
D10CC/DEBF0/F0A94/143AFC 0x26-0x28), secondo writer celle gate
0x659D54, 0x602340-famiglia, 0x189D78/CB70C, 0xD2544/D3E6C,
0x12EF48, 0x20E814. Concorrenza, schedulazione, ordine runtime
0x4401/0x4405/0x4406 NON provati. V1.1 vs V1.0 non confrontato.

**Agenti e MCP.** **Agente `close-review-30`** (tools.agents.spawn,
atteso e integrato; «task con agente explore» non esiste come tool,
usato agents.spawn come nelle iterazioni precedenti): revisione
statica ex-novo (objdump proprio, carve allineati, EA ld.as
(PC&~3)+4·imm validata su 0xCAD30→0xCAAC4, census bl/b con formula
propria validata 4/4, LE census propri) → **C1..C10 CONFERMATI**;
correzioni INTEGRATE nel rapporto: (a) secondo writer celle gate
0x659D54..0x659D5E; (b) writer [ctx+0x2B]:=1 a 0x659BFA e
[ctx+0x30]/[ctx+0x34] a 0x659D2A/C (omessi dalla mia mappa); (c)
precisazione C7 (query solo con CF554#2==1 ∧ CE6A0()==0); (d)
argomenti seconda 660C34/AD90C; (e) record p3 id@0x783B10/
handler@0x783B14. CONTROESEMPI richiesti (a) altri writer [ctx+4] e
(c) ritorni senza teardown: NESSUNO. Appunti in /tmp/rev30, PMB
outbox 392. Server MCP: `mcp_pmb_nikon` (prepare iniziale +
record_batch finale, outbox 391). REA non presente tra i connettori.
Strumenti: bash/python3, objdump GNU ARC700, Runner sim, tools.agents.
Nessun hardware/USB/SD; repository non modificato dall'agente.

**Prossimo passo concreto (non ripetitivo).** (a) **Produttore di
[ctx+0x18]=0x100/0x101**: chi scrive la cella oltre all'apertura —
candidati il risultato packed 0x4405 del WindowManager (it.18:
`0x14510C` risolutore, `(idx,arg16)`) che potrebbe transitare via
0x65AC58/0x65B060, oppure i writer interni del percorso differito;
è il pezzo che rende prevedibile la scelta completamento/differita
per la coda AkeruOS. (b) Alternativa: eseguire in CPU il blocco lungo
modo 0x2C (gate 0xD0924) con 15A5C8/201830/CFDEC e la query 0x3101
(connette la chiusura al percorso CaptureMenu arg 4 di it.25).
(c) Alternativa: writer 0x65B212/0x65B2EA (handler 0x100, stati 2/6
legati a [0x47BBC8]) per completare la mappa degli stati finestra.
Il punto it.28/it.30 è CHIUSO: non rieseguire il verificatore
dell'handler 0x4405.

# Passaggio di consegne — studio generale con Vibe

## Iterazione 28 — 1° novembre 2026 — HANDLER DI APERTURA 0x4401 (0x659554) E WRAPPER EVENTI 0x6593A0 DI AUTOSCENELIVEVIEW DECODIFICATI E CPU-PROVATI: l'handler di apertura salva il nodo in [0x681FBC] e il PUNTATORE 0x47BBB8 (via 0x65D6A0 e la funzione a due istruzioni 0x65C920 = «return &cella», NON il byte) in [0x681FBC+8], poi scrive [0x681F5C+8]:=0xFF, [0x47BBC8]:=0, copia la guardia CaptureMenu (getter ORIGINALE 0xCA310) in [ctx+9] e la riscrive con il setter ORIGINALE 0xCA2F4 (stesso valore, r1 residuo ignorato), salva l'argomento in [ctx+0x18] (word) e ritorna 0x681F5C; il WRAPPER 0x6593A0 è il VERO GATE degli eventi finestra PRIMA della dispatch p3: calcola r14=(ev&0x3F80)>>7 e filtra sulla cella stato [0x681F5C+4] letta come WORD 32 bit — eventi fuori [0x80..0x307F] (lifecycle) vanno diretti al router 0x169F60(ctx,0x783B08,node,ev,arg); STATO 6 con slot fuori {1,2,3,0x10,0xC} → ritorno 0 SENZA dispatch (i quattro slot pulsante r14=0xB/0xE/0x43/0x4E INGHIOTTITI), stati 4/5 idem per r14{9,A,3,B,E,43,4E,F}; stato 2 gate cfg[1] (lettura ORIGINALE 0x16F920, byte 0x446808+4·id): !=0 → ritorno 0 SOLO per r14∈{7,8,9,A,B,C,E,F,11,12,43,4E} (revisione: NON incondizionato), ==0 → prosegue; guardia 7 + 0xD10C4()==1 + stato{2,3} + 0<byte[ctx+0x23]≤6 + r14{3,0xC} → 0; cfg[8]/cfg[7] (cfg8==0∧cfg7==0→router); stato{4,5} slot{1,2} sotto-gate zoom (0x14A1F8 vs 100/400, cfg[8], 0x1493D8/0x14941C con uscita diretta router a 0x6594F8, re-lettura [ctx+4] a 0x659510); ogni altro r14 in {4,5} → [ctx+4]:=0 + bl 0x1493BC + bl.d 0x145C3C con r0=0x30D40 nel DELAY SLOT (eseguito CORRETTAMENTE dal sim) POI router; p6 0xAF5F08 NON è un secondo registro notifiche (chiude it.25): è un record della tabella di COPPIE di intervalli di codice 0xAF4B70..0xAF5F68 (639 record {u32,u32} tutti nel blocco 2), record @(0x659554,0x659555); 0x65D2E8 = PURGA Coda di 15 eventi 0x17BF60(0,id,id) id 0x180/0x380/0x400/0x480/0x500/0x580/0x581/0x600/0x601/0x700/0x701/0x2180/0x2181/0x2700/0x2701 (coda b 0x65CECA, correzione revisione: non 8); 19 casi CPU byte originali PASS x2 run identiche; census: 0x659554=0 bl caller, 0x6593A0=0 (callback puri), 0x65D6A0=1, 0x65C920=1, 0x65D2E8=3; LE: 0x659554 solo 0x783B0C (campo handler record 0x4401)+0xAF5F08, 0x6593A0 solo 0x783AF4, 0x47BBC8 solo pool 0x659598/0x65A3B0/0x65C400

**Domanda affrontata.** Punto aperto it.25: «handler 0x4401 di
apertura della finestra 0x659554 …; oppure il secondo registro p6
0xAF5F08 che riusa 0x659554» — e, collegato, con quale gate il
wrapper 0x6593A0 decide quali pressioni pulsante raggiungono gli
handler slot 0x65C46C/0x65C6B4 decodificati in it.25.

**Risultato verificabile e significato.** [Rapporto nuovo](S33_GUI_AutoSceneLiveView_Open_Handler_Wrapper_CPU_20261101.md),
[verificatore nuovo](../Python_Trace_Scripts/s33_verify_aslv_open_wrapper_cpu.py),
[evidenze](../Risultati/GUI_S33/aslv_open_wrapper_cpu_20261101T170345784381Z/),
[riesecuzione identica](../Risultati/GUI_S33/aslv_open_wrapper_cpu_20261101T170413338706Z/).
**PASS_ASLV_OPEN_WRAPPER**: 19 casi CPU su byte ORIGINALI (16 wrapper
+ 3 handler apertura; fault 0xDEADB001..13) x2 run identiche. I quattro
slot pulsante NON sono sempre visibili: negli stati finestra
{4,5,6} ([ctx+4]) la pressione è inghiottita dal wrapper PRIMA del
registro p3; in stato 2 il gate è cfg[1]; il wrapper può AZZERARE lui
stesso lo stato ([ctx+4]:=0) e chiamare 0x145C3C(0x30D40) nel delay
slot. Conseguenza AkeruOS: la coda non può assumere che ogni pressione
produca una notifica CaptureMenu (2,4)/(2,5) — serve osservare lo
stato finestra [ctx+4] e le celle cfg[1]/[7]/[8] (runtime, produttori
aperti).

**Fonti e indirizzi.** Blocchi 0/2/3 V1.1; finestre CPU byte-originali:
`.mili` 0x334100..0x3341E4, `.guard` 0xCA2F4..0xCA31A (pool
0xCA30C=0x365751), `.cfgread` 0x16F920..0x16F928 + pool
0x16FA34=0x446808, `.wrap` 0x6593A0..0x659554, `.open`
0x659554..0x65959C (pool 0x659594=0x681F5C, 0x659598=0x47BBC8),
`.d6a0` 0x65D6A0..0x65D6D0 (pool 0x65D6CC=0x681FBC), `.c920`
0x65C920..0x65C928 (pool 0x65C924=0x47BBB8); wrapper pool
0x659548=0x681F5C, 0x65954C=0x30D40, 0x659550=0x783B08; registro p3
0x783B08: 0x4401→0x659554, 0x4405→0x65959C, 0x4406→0x659EF0,
0x4409→0x65A4A4, 0x440E→0x659FA0, 0x400C→0x65A708, 0x7D40→0x65AB5C.

**Comandi eseguiti ed esiti.** `python3 Python_Trace_Scripts/
s33_verify_aslv_open_wrapper_cpu.py` → PASS_ASLV_OPEN_WRAPPER
**20261101T170345784381Z** + riesecuzione identica **170413338706Z**
(evidenze byte-identiche salvo utc, 19/19). Regressioni 6/6 PASS:
snapshot record init **170439048305Z**, guard setter census
**170439820601Z**, service raise pending **170451Z**, wm notify
registry **170455525917Z**, notify reactors **170458416927Z**, aslv
slot handlers **170504924640Z**. Statica: objdump GNU ARC700 su
finestre carve, LE scan `le_scan`, census 16 listati GNU, tabella p6
scandita record per record.

**Fixture e assunzioni.** Contesto 0x681F5C fixture 0x68 byte
(sentinelle 0xA5): **[ctx+4] impostato come WORD 32 bit** (scoperta
al primo fallimento: `ld_s r0,[r13,0x4]` legge 4 byte); guardia
0x365751 fixture con getter/setter ORIGINALI eseguiti; tabella cfg
0x446808 fixture (byte id 1/7/8, lettura ORIGINALE 0x16F920); celle
0x47BBB8/0x47BBC8 fixture con sentinelle; stub logger {id,r0,r1,r2} a
0x367100+16k, specchietti r3/r4 del router, cella ritorno 0x367320;
stub a 0x169F60/0x65D2E8/0x145C3C/0x1493BC/0x1493D8/0x14941C/
0x14A1F8/0xD10C4/0x189D78 con ritorni imposti per caso. Assunzione:
significato runtime degli stati {0,2,3,4,5,6} e di cfg[1]/[7]/[8]
NON dedotto.

**Controlli negativi e regressioni.** Inghiottimento stati 6/5/4 con
i quattro slot → ritorno 0, ZERO chiamate stub, stato invariato
(casi 3/4/5/11/14); gate cfg[1]=1 → inghiottito (9) vs cfg[1]=0 →
prosegue (10); percorso pulizia: [ctx+4] azzerato + 0x145C3C riceve
ESATTAMENTE 0x30D40 via delay slot (13); guardia 7 ripristinata
identica (17/18/19), vicini 0xA5 intatti; rilascio slot 1 in stato 6:
0x65D2E8 + router senza gate successivi (8); assert «nessuna chiamata
oltre il conteggio atteso» in ogni caso. LEZIONI DI BANCO (nuove):
(1) `ld_s` carica SEMPRE una WORD: fixture a byte su cella letta con
ld_s → confronti 0xA5A5A5xx (accaduto su [ctx+4]); (2) il `bl.d` con
delay slot che carica un LIMM nel registro argomento (0x659524/28) è
eseguito CORRETTAMENTE dal sim; (3) a call-site r0/r1/r2 = risultato
dell'ULTIMA istruzione prima del bl (0x65D2E8 riceve r0=ev&1 dal
bmsk; 0x189D78 riceve r0=0x47BBB8); (4) funzione con `j_s.d` +
delay slot ld = «return &cella» (0x65C920).

**Limiti e non dimostrato.** Statica + 19 casi CPU con fixture: nessun
hardware/boot/rendering/scatto/persistenza; NON_INSTALLARE; circa 10%
invariato. Produttori RUNTIME di cfg[1]/[7]/[8] e 0x47BBB8/0x47BBC8
APERTI; writer STATICI di [ctx+4] censiti dalla revisione (13 store
in 9 funzioni, vedi rapporto) ma NON provati in CPU; 0x169F60,
0x145C3C, 0x1493BC/D8/41C, 0x14A1F8, 0xD10C4, 0x189D78, 0x65D2E8
STUB; router non rieseguito in catena con 0x65C46C; significato
funzionale degli stati e del byte[ctx+0x23] non identificato; V1.1
vs V1.0 non confrontato.

**Agenti e MCP.** **Agente `openwrap-review-28`** (spawn + follow-up,
atteso e integrato): reingegnerizzazione ex-novo (objdump propri,
census LE propri, 152/152 finestre congelate byte-identiche, due run
confrontate) → C1/C2/C4/C5/C6/C8 CONFERMATI CON PRECISIONE; C3 con
correzione obbligatoria del gate (c) (non incondizionato) INTEGRATA;
C7 conteggio 8→15 INTEGRATO; controesempi accolti e integrati (uscita
0x6594F8, re-check 0x659510, stato 6 slot{2,3,0x10,0xC} pressione non
inghiottita); nessuna polarità errata, nessuno store non dichiarato;
census writer [ctx+4] completo (13 store); PMB outbox 389. Server MCP:
`mcp_pmb_nikon` (prepare iniziale + record_batch finale). REA non
presente tra i connettori. Strumenti: bash/python3, objdump GNU
ARC700, Runner sim (hash invariati), tools.agents. Nessun
hardware/USB/SD. Nessun file del progetto modificato dall'agente
(lavoro in /tmp/rev28).

**Prossimo passo concreto (non ripetitivo).** Decodificare e provare
in CPU l'handler **0x4405 (0x65959C, chiusura)** — il writer più ricco
di [ctx+4] (0 e 2) e naturale consumatore del contesto predisposto
dall'apertura 0x659554 — per chiudere il ciclo
apertura→stato→chiusura della finestra; in alternativa i writer
0x65B212/0x65B2EA (handler 0x100: stati 2/6 legati a [0x47BBC8]) o il
ramo 0x63 di 0x20F414 e il callback 0x7F6824. I punti it.25/it.23
sono CHIUSI: non rieseguire i verificatori corrispondenti.

## Iterazione 25 — 1° novembre 2026 — HANDLER SLOT PULSANTE DI AUTOSCENELIVEVIEW DECODIFICATI E CPU-PROVATI: il registro p3 0x783B08 appartiene alla finestra "AutoSceneLiveView" (descrittore 0x783AE8, wrapper 0x6593A0→router 0x169F60, contesto 0x681F5C); l'handler di pressione 0x65C46C (0x580/0x700/0x2180/0x2700) pre-elabora (timer id 9, chiusura sottofinestre con 0x145B08 su array 0x783A1C a 14 voci, 0x17BF60(0,0x80,0x307F), modo 0x7E/0x2C) e catena in 0x65C5F8 che DISTINGUE I QUATTRO SLOT: 0x700→0x1453E4(2,4), 0x2180→0x1453E4(2,5) (ORIGINE delle coppie «ID 2 arg 4/5» dei banchi sintetici), 0x2700→0x1453E4(0xB7,1), 0x580→0xD2500(0)+0xCA404(0x2C)+0x1453E4(0x87,0) se modo≠0x2C; rilascio 0x65C6B4 (0x581/0x2701) catena solo se modo 0x2C ∧ 0x26C4F8()!=0 (byte[0x36B43D]); 16 casi CPU byte originali PASS x2 run identiche; polarità 0x14918C invertita (==0→crea timer 0x14905C(nodo,9,5000,0x32,0) ed esce SENZA catena); b di coda -5152/-10084 eseguite CORRETTAMENTE dal sim (micro-test, la divergenza it.44 non si generalizza)

**Domanda affrontata.** Punto aperto it.23: decodificare l'handler p3
0x65C46C collettore dei 4 slot (0x580/0x700/0x2180/0x2700, registro
finestra 0x783B08) per distinguere i pulsanti fisici.

**Risultato verificabile e significato.** I quattro slot NON sono
equivalenti. In AutoSceneLiveView la pressione 0x700 notifica CaptureMenu
con arg 4 e 0x2180 con arg 5 (i due argomenti sintetici dei banchi
derivano dalla catena 0x65C46C→0x65C5F8→0x1453E4); 0x2700 notifica la
finestra 0xB7 con arg 1; 0x580 pilota la transizione di modo 0xCA404(0x2C)
e la finestra 0x87 (se modo≠0x2C; in 0x2C avvia solo 0x26C508, timer
pulsante con guard byte[0x36B43D] e gate cfg[0x0B]/[0x4E]). Il rilascio
0x2701 riottiene (0xB7,1) solo in 0x2C con guard attiva; 0x581 in 0x2C
esce senza notifiche. Ramo modo 0x7E: 0x700 ESCE senza notifiche,
0x580/0x2180/0x2700 fanno teardown 0x65D534 se 0xCD5AC (byte[0x3657DB]<2)
e 0x145A60(nodo,0x480C,2) passano.

**Fonti e indirizzi.** Blocchi 2/3/0 del firmware V1.1; registro p3
0x783B08 (39 record + terminatore {0,0x20E814} a 0x783C40), descrittore
0x783AE8 {0x442,0x330087,0x783A1C,0x6593A0,0,0x783C4A}, nome
"AutoSceneLiveView" a 0x783C4A, array 14 sottofinestre (ID 0x480C/0x480E/
0x480D/0x4801..0x4805/0x4809/0x4806..0x480B, ordine NON contiguo), pool
handler 0x65C5DC=0x480C, +0xE0=0x1388, +0xE4=0x783A1C, +0xE8..+0xF0=
0x4A12/0x4A87/0x4A8A, +0xF4=0x307F; wrapper pool 0x659548=0x681F5C,
0x65954C=0x30D40, 0x659550=0x783B08; census bl 16 payload: 0x65C46C/
0x65C6B4/0x6593A0 = 0 chiamanti (callback puri), 0x65C5F8 = 2 (0x65C5D4,
bl_s 0x65C6F0); 0x659554 anche a p6 0xAF5F08 (secondo registro, APERTO).

**Comandi eseguiti ed esiti.** `python3 Python_Trace_Scripts/
s33_it25_blmicro.py` + caso manuale tr.s/tr.ld (micro-test b di coda:
0x65C5D8→0x65B1B8 e 0x65C6F2→0x659F8C CORRETTE in trace); `python3
Python_Trace_Scripts/s33_verify_aslv_slot_handlers_cpu.py` PASS_
ASLV_SLOT_HANDLERS 20261101T163644112536Z + riesecuzione identica
163743659383Z (16/16, fault 0xDEADB001..10); regressioni 5/5 PASS:
snapshot init 163809460170Z, guard census 163812570997Z, raise pending
163826Z, wm notify registry 163842997883Z, notify reactors 163845672909Z.

**Fixture e assunzioni.** Byte modo 0xC8E80C per caso (getter 0xCAD30
ORIGINALE eseguito); array 0x783A1C fixture con 2 descrittori sintetici
0x500000/0x500010 (ID halfword 0x480C/0x480D a +4 come nel dump); nodo
0x1234; 28 stub log {id,r0,r1,r2}; helper stubbati con semantica dall
analisi statica (0x14918C/0x14905C timer id 9 tabella 0x443ADC; 0x17BF60
cancella coda in [lo,hi]; 0x26C4xx timer pulsante; stub corti 16 byte con
logger locale 0x26C400 per la coppia 0x26C4F8/0x26C508 a 16 byte di
distanza).

**Controlli negativi e regressioni.** Casi 4/7/10/14/15/16 = percorsi
senza catena o senza notifiche; caso 6 gate 0xD0924 con extra 0xCB5E4;
assert «nessuna chiamata oltre il conteggio atteso» in ogni caso;
regressioni 5/5 come sopra. Micro-test: la divergenza it.44 (wrap mod
8192 dei b negativi grandi) NON vale per -5152/-10084; memoria non mappata
<128 MiB è zero-filled silenzioso (loop, non fault).

**Limiti e non dimostrato.** Nessuna mappa fisica dei tasti; produttori
runtime di modo, conteggio 0x14504C(nodo,6) e guard 0x36B43D aperti; con
conteggio >14 il loop leggerebbe i puntatori p1 (limite statico);
finestra 0xB7 e coppia (0x87,0) da identificare; unità dei timer non
provate; 0x1453E4/0x632798 stubbati (consegna reale non rieseguita);
nessuno scatto/hardware/persistenza; NON_INSTALLARE invariato; ~10%
invariato.

**Agenti.** `helper-explore-25`: decodifica statica helper (0x632798,
famiglia 0x26C4xx con ripubblicazione 0x581/0x2701 via 0x16F6B0, timer
tabella 0x443ADC stride 0x1C, 0x17BF60, setter semplici, 0xCD5AC,
0x12845C, 0x15A5C8, millicode catene fall-through), PMB outbox 387.
`slot-review-25`: revisione indipendente C1-C9, 0 controesempi
invalidanti, 3 correzioni integrate (14 voci/ordine ID; polarità 0x14918C
invertita; seconda via al blocco chiusura via 0x7E∧0xCD5AC()==0), conferme
pool/pcl/delay-slot/census, PMB outbox 386. Entrambi solo statici, nessun
file modificato.

**Server MCP e strumenti.** PMB (prepare/recall/record_batch) usato;
agenti spawn/wait usati (2 completati, attesi); nessun REA-specific tool
disponibile oltre objdump GNU locale (nessun tool MCP REA registrato
nella sessione); runner podman arc700-legacy OK (prima esecuzione
fallita per container freddo, ripetuta OK).

**Prossimo passo concreto.** Handler 0x4401 di apertura della finestra
0x659554 (scrive 0xFF→[0x681F5C+8], [0x47BBC8]:=0, copia guardia
0x365751→[0x681F5C+9] e la reimposta con 0xCA2F4, registra 0x30D40 via
0x145C3C nel delay slot) per collegare lifecycle/stato di AutoSceneLive
View agli slot; oppure ramo 0x63 di 0x20F414 (0x17BE80(0,0x3181,0), it.23)
e callback 0x7F6824 con lista esclusione 0x99ACAC; oppure la finestra
0xB7 (target slot 3) e il secondo registro p6 0xAF5F08 che riusa 0x659554.

[Rapporto](../MDs/S33_GUI_AutoSceneLiveView_Slot_Handlers_CPU_20261101.md),
[prove](../Risultati/GUI_S33/aslv_slot_handlers_cpu_20261101T163743659383Z/),
[micro-test b](../Risultati/GUI_S33/aslv_tailb_blmicro_20261101T162741Z/).

## Iterazione 23 — 1° novembre 2026 — REATTORI DEL REGISTRO NOTIFICHE p1 DECODIFICATI E CPU-PROVATI: 0x20EAF4 (0x0700) apre CaptureMenu solo con stato 0x365753==1 e ARG 0 (correzione della banca sintetica «arg 4»); 0x20E940 (0x0080/0x2180, stesso handler per R02/R19) scarta la pressione se la coda contiene già 0x3101, cancella 0x81/0x80/0x101/0x100 dalla coda e richiede la finestra 0x87; 0x20F414 (0x4006) azzera la guardia CaptureMenu se ≠7 e smista sull'argomento (0x65→0x1443C0 con cfg|0xC0000000 e cella 0x36972D); 0x580/0x2700 assenti dal registro globale MA presenti nel registro finestra p3 0x783B08 → 0x65C46C (APERTO); 16 casi CPU byte originali con getter/setter/millicode ORIGINALI, PASS x3 run identiche

**Domanda affrontata.** Punto (a) di it.21/47: «decodificare e provare in
CPU il reattore 0x20F414 (evento 0x4006) e i reattori slot (0x700→
0x20EAF4, 0x2180→0x20E940, 0x580/0x2700)» per chiudere la catena
snapshot→coda→dispatcher→finestra→callback→router→registro→reattore.

**Risultato verificabile.** [Rapporto nuovo](S33_GUI_Notifica_Reattori_Slot_Registro_CPU_20261101.md), [verificatore nuovo](../Python_Trace_Scripts/s33_verify_notify_reactors_cpu.py), [prove finali](../Risultati/GUI_S33/notify_reactors_cpu_20261101T161952929543Z/), [prima run](../Risultati/GUI_S33/notify_reactors_cpu_20261101T160819606803Z/), [riesecuzione identica](../Risultati/GUI_S33/notify_reactors_cpu_20261101T160829082666Z/). **PASS_NOTIFY_REACTORS 20261101T160819606803Z** + riesecuzione **160829082666Z** identica + evidenza finale post-audit **161952929543Z** (inventario `.pool6` completato, cpu_cases byte-identici). 16 casi CPU su byte ORIGINALI (fault 0xDEADB001..0xDEADB010, marker per-assert 0xDEADxxxx):
- **0x20EAF4 (0x0700)**: `stato := byte[0x365753]` (getter ORIGINALE 0xCAD5C, pool 0xCAD58, struct CaptureMenu+3); ==1 → **0x1453E4(2, 0)** (CaptureMenu, ARG 0 — NON 4); ==2 → 0x1453E4(**sexw**(word[0x365776]), 0) (getter 0xCD9C8; caso negativo 0x8002→0xFFFF8002); altro → nessuna notifica. Casi 1-4.
- **0x20E940 (0x0080 E 0x2180, stesso handler)**: gate [0x365756]==2 → esci (getter 0xCB4A8); [0x365753]==3 → esci; **query-coda 0x17BE18(0,0x3101,0x3101)≠0 → SCARTO della pressione** (0x17BE18 = interval-query sull'anello base 0x47A848 stride 12, 128 voci, it.45); gate DOPPIO **cfg[0x61]==42 → esci** (0x16F920 ORIGINALE: tabella runtime 0x446808+id×4 — RAM, gap 0x428600..0x5FE800, valori fixture; 0x16E41C ORIGINALE ritorna sempre (42,0); il caso cfg61=42 VERIFICA la scalatura ×4); gate id precoce ==1/==0x7E (resolver ORIGINALE 0x1453FC); blocco modo-2 solo con 0x365753==2 (0x817BD8, 0x177484, 0x14941C/0x17743C, 0xBBC04(4), 0xD0080 + selettori modo 0xCAD30==0x37 e id 5/158/0x5E/0x4D → 0xCBDF8+0x177030); poi **CANCEL 0x17C074(0,{0x81,0x80,0x101,0x100},arg)** (cancellazione dall'anello: evento +4 azzerato su match, decodifica statica) e **0x1453E4(0x87, 0)**. Casi 5-11 (pass: 7 chiamate; modo2 id5: 18; modo2 id0x5E con CE6E8→0: 20, ordine esatto).
- **0x20F414 (0x4006) ingresso**: byte[0x36575B] (getter 0xC9BF8, struct+0xB)==0 → uscita 0x20F878 (solo 0xD008C(0)); **guardia**: 0xCA310≠7 → **setter ORIGINALE 0xCA2F4 scrive 0** (la 0x4006 ripulisce la guardia stantia; casi per-no-write con guardia 7 e vicini intatti); dispatch extb(arg): **0x65** → 0x1443C0(node,0,cfg[0x65]|0xC0000000) + 0xD008C(0) + **[0x36972D] := 0x210BC8()** + gate modo 0x2C / **0xD0924()==0** / id {135,6,167}; **0x63** (solo statico): [0x369735]:=1, 0x137774, **0x17BE80(0,0x3181,0)** post coda, 0x12B8E8/0x12B888; {1,0xC,0x62,0x66,3} → gate 0x177484; altro → uscita. Casi 12-16.
- **Statica**: registro p1 67 record ricontrollato; 0x0580/0x2700 ASSENTI; i tre reattori hanno ZERO bl caller e le UNICHE parole LE a 4-allineati in 16 payload + firmware.bin sono i campi handler del registro (callback puri). **Controesempio audit**: registro finestra **p3 0x783B08..0x783C40** (default (0,0x20E814)@0x783C40) instrada **0x580/0x700/0x2180/0x2700 → 0x65C46C** e 0x581/0x2701 → 0x65C6B4: gli slot hanno handler a livello finestra.

**Comandi realmente eseguiti ed esiti.** `python3 Python_Trace_Scripts/s33_verify_notify_reactors_cpu.py` → PASS 160819606803Z + 160829082666Z + 161952929543Z (identici salvo utc/inventario). Regressioni 5/5 PASS: guard setter census **160851475924Z**, snapshot record init **160924900280Z** (nome corretto `s33_verify_snapshot_capture_record_init_cpu.py`), service raise pending **160903Z**, wm notify registry **160907467859Z**, wm service dispatch **160910245724Z**. Analisi statica: objdump GNU ARC700 su finestre carve dai payload verificati, LE scan `le_scan`, census listato GNU.

**Fixture e assunzioni.** Celle 0x365751/0x365753/0x365756/0x36575B/0x365776/0xC8E80C/[0x366EA4]/[0x36972D] fixture (sentinelle 0xA5); tabella cfg 0x446808 fixture (RAM runtime, NON nei payload); nodo 0x1234, arg 0x77/0x99/0x65/1; stub solo ai call-site profondi con trampolino push_s blink/mov r7,sid/jl_s logger comune (tabella ritorni 0x367400); logger log {id,r0,r1,r2} a 0x367100+16k, contatore 0x367000. Getter/setter/millicode 0x334114..0x33413A/0x334178..0x3341E4, 0xCA2F4/0xCA310, 0xC9BF8, 0xCAD5C, 0xCB4A8, 0xCD9C8, 0xCAD30, 0x16F920, 0x16E41C, 0x1453FC ORIGINALI (finestre byte-identiche, ELF↔payload verificato a ogni build).

**Controlli negativi e regressioni.** sexw negativo (0x8002→0xFFFF8002); guardia 7 → setter MAI chiamato; guardia 5 → vicini intatti; gate cfg61 con 42 (unica prova della scalatura ×4); stato 0x365753=0 → zero notifiche; inattivo 0x36575B=0 → guardia intatta. **LEZIONI DI BANCO (nuove)**: (1) le finestre devono includere l'istruzione di ritorno (j_s/b_s) e i POOL pcl letti dal corpo: il taglio prima manda l'esecuzione in RAM-zero del sim → loop (accaduto: W_RES hi 0x145412→0x145414, W_EXIT6 0x20F87E→0x20F880, pool 0x20EA58 e 0x20F790 esclusi); (2) uno stub con `jl_s` SOVRASCRIVE blink: senza push_s/pop_s il logger rientra nello stub e loopa (12M istruzioni, fault progressivo oltre lo stack 0xC93000); (3) stub ≥20 byte non coesistono a 12/36 byte di distanza (0x17743C/0x177460/0x177484, 0xD0080/0xD008C): trampolino + logger comune + rettab; (4) i b/b_s negativi PICCOLI (−758, −282) sono eseguiti CORRETTAMENTE dal sim (la divergenza it.44 riguarda solo i negativi GRANDI); (5) i valori r1/r2 residui ai call-site sono deterministici e asseribili (es. 0xD008C riceve (0x4006,arg) in uscita, (0,0xC000005A) dopo 0x1443C0) — ma 0xCE6E8 riceve r0=modo, non l'id (CAD30 clobber): verificare SEMPRE il produttore immediato di ogni registro asserito.

**Limiti e questioni non dimostrate.** Statica + 16 casi CPU con fixture: nessun hardware, boot, rendering, scatto, persistenza; NON_INSTALLARE; circa 10% invariato. 0x17BE18/0x17C074/0x1453E4/0x177484/0x1443C0/0xD008C/0x210BC8 e il blocco modo-2 sono STUB (0x17C074 cancel-coda = decodifica statica); ramo 0x63 e oltre-0x177484 NON provati in CPU; cfg[0x61]/cfg[0x65] reali ignoti (tabella runtime); handler 0x65C46C/0x65C6B4 (p3) NON decodificati; producers/schedulazione non provati; V1.1 vs V1.0.

**Agenti e MCP.** **Agente `reactor-audit-23`** (tools.agents.spawn, atteso e integrato): metodo indipendente (ridisassembly ex-novo, census propri, LE scan a ogni allineamento su 16 payload + firmware.bin intero, 20/20 SHA finestre + 163/163 .bin rilette dalle evidenze congelate senza rieseguire il verificatore) → **C1/C2/C3/C6/C7/C8 CONFERMATI, C4/C5 CONFERMATI con omissioni documentali APPLICATE al rapporto** (gate doppio cfg, uscite precoce id 1/0x7E, gate 0xD0924, ramo 0x63, semantica interval-query di 0x17BE18); **controesempi accolti**: registro finestra p3 0x783B08 (slot→0x65C46C/0x65C6B4), setter compagni 0xCAD38/0xC9BDC/0xCD9AC/secondo getter 0xCD8CC (pool 0xCD8F0)/writer candidato 0xCA5DE; 0x36972D senza altri accessi; inventario .pool6 completato con riesecuzione finale. Esito in PMB (outbox 384) e checkpoint breve. Server MCP: `mcp_pmb_nikon` (prepare iniziale + record_batch finale). REA non presente tra i connettori. Strumenti: bash/python3, objdump GNU ARC700, Runner sim (arc-elf32-run hash invariato), tools.agents. Nessun hardware/USB/SD.

**Prossimo passo concreto (non ripetitivo).** (a) **Decodifica e CPU dell'handler p3 0x65C46C** (registro finestra 0x783B08, payload3): riceve TUTTI e quattro gli slot logici pulsante 0x580/0x700/0x2180/0x2700 (e 0x65C6B4 per 0x581/0x2701) — è il collettore che manca per distinguere i quattro pulsanti fisici e il primo candidato per il «pulsante 3» (0x2700). (b) Alternativa: CPU del callback finestra 0x7F6824 con lista esclusione 0x99ACAC e tabella 0x99AB8C (punto (b) di it.21, ancora aperto). (c) Alternativa: ramo 0x63 di 0x20F414 (0x137774, 0x17BE80(0,0x3181,0), 0x12B8E8/0x12B888) per collegare il reattore 0x4006 ai ponti guardia it.43-44. I reattori p1 sono CHIUSI: non rieseguire il verificatore né l'audit di questi claim.

## Iterazione 21 della richiesta (it.19 Vibe) — 1° novembre 2026 — CONSUMATORE REGISTRO p1: REPLICATO E ESTESO — la sessione interrotta it.47 lo aveva già chiuso (router 0x169F60, wrapper 0x20E814, base 0x3E8BB4, accoppiamenti corretti 0x4006→0x20F414/0x4005→0x20F294) senza aggiornare i checkpoint; questa iterazione lo ha riscoperto indipendentemente e aggiunge: CATENA NIDIFICATA CPU tabella-finestra p5 0x99AB8C→default R35={0,0x20E814}→wrapper ORIGINALE→registro globale→reattore (caso p5_default_to_global, 350 istruzioni, due invocazioni annidate del router); LISTA DI ESCLUSIONE 0x99ACAC identificata (17 voci u16: slot 0x580/0x700/0x2180/0x2700 + 0x480/0x500/0x380/0x400 + 0x4004 + terminatore) e CPU-provata (excl_hit: evento in lista→ritorno 0 senza dispatch); callback finestra 0x7F6824 decodificato dall'audit: gate [0x80,0x307F], fuori range → 0x169F60(r0=0x99ACAC, r1=0x99AB8C, nodo, evento, arg) (pool p4 0x7F6A48/0x7F6A4C); wrapper GEMELLO 0x224AB8→tabella p1 0x3EB554 (default pure 0x20E814); census 228 bl a 0x169F60 (p0:36→p1, p2:29→p3, p4:143→p5, p6:20→p7; 228 tabelle distinte; 202/228 con r0≠0, 193 liste di esclusione valide); 182 parole 0x20E814 in dati (p1:20, p3:7, p5:135, p7:20) = slot default di tabelle finestra che inoltrano al registro globale; PRECISIONE: il router legge l'evento come HALFWORD a +0 (`ldw_s.x`), non u32 — coi dati reali (pad sempre 0) le letture coincidono; il registro p1 NON ha record default (terminatore null-null a 0x3E8DC4: evento non abbinato → ritorno 0)

**Domanda affrontata.** Punto it.46(a) indicato aperto dal checkpoint: consumatore del registro notifiche p1 0x3E8BB8..0x3E8DC8, candidati installer 0x145010/0x145018 e resolver 0x14505C.

**Risultato verificabile.** [Rapporto nuovo](S33_GUI_Router_0x169F60_p5_Default_Catena_Esclusioni_CPU_20261101.md), [rapporto della sessione interrotta it.47](S33_GUI_Registro_Notifiche_Consumatore_CPU_20261101.md) (già valido, ora riconosciuto), [verificatore nuovo](../Python_Trace_Scripts/s33_verify_wm_notify_registry_cpu.py), [prove](../Risultati/GUI_S33/wm_notify_registry_cpu_20261101T155229008610Z/) + riesecuzioni identiche 154903181063Z/154909405237Z/154932736078Z (10 casi CPU byte originali: ev4410→0x20E848, ev4006→0x20F414 CORRETTO, ev7ce4→0x20E900, unmatched→ritorno 0 NESSUN default, excl_hit/excl_miss, null_handler, wrapper 0x20E814, p5_ev3b81→0x7F8674, p5_default_to_global→0x20E900; fault 0xDEADB001..0A). Errata applicata al [rapporto it.46](S33_GUI_WM_Service_Dispatch_0x169D78_CPU_20261101.md).

**Comandi realmente eseguiti.** `s33_verify_wm_notify_registry_cpu.py` PASS 155229008610Z (+3 identiche); regressioni PASS: wm service dispatch 154912169644Z, wm current switcher 154917531798Z, capture guard setter census 154935478062Z, service raise pending 154947Z, event router producers 154951182708Z. PMB prepare iniziale; record_batch finale. Analisi statica: LE scan 0x3E8BB4 (unica parola 4-allineata = pool 0x20E844), 0x366E94 (pool 0x145350/0x145BE4), decode 0x145010..0x145098 (getter add2_s ×4) e del percorritore 0x145818 (node+6 count, node+8 array, bit 1/2/4/6 → 0x1456EC).

**Fixture e assunzioni.** Finestre originali router/wrapper/millicode/registro p1/tabella p5; stub SOLO ai reattori raggiunti (log {id,r0,r1,r2} a 0x367000+48); liste di esclusione sintetiche a 0x367600; tabella null-handler sintetica a 0x367800; nodo 0x1234, arg 0x77 imposti dal banco. Il caso p5_default_to_global esegue il wrapper ORIGINALE (nessuno stub su 0x20E814).

**Controlli negativi e regressioni.** unmatched (nessun dispatch: il registro NON ha default, contro il claim iniziale del coordinatore); excl_hit (esclusione blocca); null_handler (handler 0 → ritorno 0); LE confini vecchi 0x3E8BB8/0x3E8DC8 = zero 4-allineate (conferma del motivo per cui it.46 non trovava il consumatore); p3 tables byte-regression. 5 verificatori storici PASS.

**Limiti e questioni non dimostrate.** Callback 0x7F6824 solo statico (audit), NON eseguito in CPU; reattore 0x20F414 NON decodificato; solo 2 route della tabella p5 eseguite; census da listato GNU (jl invisibili); schedulazione runtime non provata; nessun hardware/scatto; NON_INSTALLARE; circa 10% invariato.

**Agenti e MCP.** Agente `registry-audit-21` (tools.agents.spawn, atteso e integrato): C1/C3/C4/C5 CONFERMATI; C2 PARZIALE con due correzioni APPLICATE (indici R57/R58 al posto di R63/R64; NESSUN default in p1); C6 controesempi positivi accolti (wrapper gemello 0x224AB8→0x3EB554; 182 slot default; r0≠0 in 202/228 con 193 liste valide; callback 0x7F6824 decodificato). L'agente ha registrato l'esito in PMB. Server MCP: `mcp_pmb_nikon` (prepare, record_batch). REA non presente tra i connettori disponibili.

**Prossimo passo concreto (non ripetitivo).** (a) Decodificare e provare in CPU il **reattore 0x20F414 (evento 0x4006 corretto)** e i reattori slot (0x700→0x20EAF4, 0x2180→0x20E940, 0x580/0x2700) per chiudere snapshot→coda→dispatcher→finestra→callback→router→reattore (da it.47, ancora valido). (b) **CPU del callback finestra 0x7F6824** con lista esclusione 0x99ACAC e tabella 0x99AB8C: tre percorsi (in-range gestito direttamente, out-of-range escluso, out-of-range inoltrato) per chiudere il ruolo runtime della lista di esclusione e il gate [0x80,0x307F]. NON rieseguire i verificatori di questo punto: è CHIUSO.

## Iterazione 18 (it.47 Vibe, ciclo 15) — 1 novembre 2026 — WRITER DI [0x366EA4] CHIUSO: è il commutatore 0x145180(target,arg), UNICO chiamante bl = wrapper 0x1453E4(idx,arg) (580 chiamanti bl in tutto il firmware) → tabella finestre RAM [[0x366E94+8]] via 0x14507C; current [0x366E94+0x10] scritto in TRE siti (0x1452EE current:=target dopo 0x4401, 0x145306 :=pending dopo 0x4415, 0x145338 :=r15=OLD/pending), pending [ +0x14] in TRE siti (0x145234/0x14534C/0x14538A); gate non-rientranza busy [0x366EBB]=0x366E94+0x27 (set 0x1451AC/clear 0x145396, i gate d'ingresso non lo toccano); check 0x14503C(ptr,off)=[ptr+off] legge flag [nodo+0] (bit 0/7/8/9/A/C); REDIRECT: il RISULTATO delle consegne 0x4403/0x4405 (packed=(idx,arg16)) alimenta il risolutore 0x14510C→0x14507C e il commutatore riparte in un LOOP di transizioni concatenate (CPU: T1→T2 con current riscritto T1→P→T2); abort 0x4404=-1 lascia current INTATTA; post-successo: bitA flag=0→post A 0x17BF60, bitA=1∧bitC=0→gate [0x366E94+0x24] sceglie 0x145150 (diretto) o 0x145158 (coda 0x169EB4, ricorsione su [nodo+8] se bit0); TROVATA SECONDARIA: writer controllo attivo [0x366EAC]=0x145B9A st r13,[r0,0x18] dentro 0x145B08 (673 chiamanti, consegna 0x4408 all'attivo prima di cambiarlo; pool 0x145BE4/0x145BF0; solo statico); LEZIONE SIM: i displacement POSITIVI grandi nei bl.d/b 32-bit (fino a 0x1EE048) sono eseguiti CORRETTAMENTE a entrambi gli allineamenti — la divergenza it.44 vale solo per i NEGATIVI grandi; NESSUN taglio: il commutatore torna dall'epilogo millicode ORIGINALE 0x33418C (verificatore nuovo PASS ×4: 152007762890Z+152018293529Z identiche, post-audit 153605977322Z+153638728092Z identiche; 8 casi CPU con finestre originali 0x145180..0x1453E4+helper+millicode)

**Domanda affrontata.** Punto aperto (b) dell'iterazione 46: chi scrive la cella della finestra corrente [0x366EA4] (contesto maestro WindowManager 0x366E94+0x10, letta dai resolver 0x1453F4/0x1453FC via pool 0x14579C) — l'audit it.46 non aveva trovato writer statici e ipotizzava store indiretti nel commutatore 0x145180.

**Risultato.** [Rapporto](S33_GUI_WM_Current_Switcher_0x145180_CPU_20261101.md), [script](../Python_Trace_Scripts/s33_verify_wm_current_switcher_cpu.py), [prove](../Risultati/GUI_S33/wm_current_switcher_cpu_20261101T153605977322Z/), [riesecuzione identica](../Risultati/GUI_S33/wm_current_switcher_cpu_20261101T153638728092Z/) (le run pre-audit 152007762890Z/152018293529Z sono anch'esse PASS e byte-identiche).
- **Writer identificato e CPU-provato**: il commutatore 0x145180 stesso, via master+0x10/master+0x14 (il pool della cella ESATTA 0x366EA4 esiste solo per i due GETTER). Layout maestro completato: +0/+4 tabella0 (setter 0x145010), +8/+C tabella1 (setter 0x145018, count s16), +0x10 CORRENTE, +0x14 PENDING, +0x18 ATTIVO (writer 0x145B9A), +0x24 gate post, +0x27 busy. LE scan congelati (ora anche 0x366EAC→{0x1457D0}, 0x366EB8→{0x1457A0}, 0x366EA8→NESSUNO).
- **8 casi CPU** (finestre ORIGINALI, epilogo 0x33418C eseguito, stub solo per 0x169D78/0x169EB4/0x17BF60/0x17BE80): null_target, invalid_target (bit0), busy_gate, open_first (current:=T1 0x1452EE, pending:=T1 0x14538A, post A), abort_4404 (0x4404→-1: corrente MAI scritta, busy azzerato), close_ok (0x4414→pending:=current 0x145234; pending:=OLD 0x14534C), return_pending (target==pending: 0x4415 al pending, current:=pending 0x145306, gate=1→0x145150 diretto), chain_redirect (0x4405 redirige: due iterazioni, current T1→P (0x145338)→T2, pending:=T2 0x14538A, 11 consegne).
- **Semantica delay slot decisa in CPU**: il beq 0x1452AA usa le flag del btst bit9 a 0x1452A4 → la (pending,0x4406,target) avviene SOLO con bit9 del PENDING; la (pending,0x4402,0) solo con bit8; r15 a 0x145338 = OLD o pending (delay 0x1452F2), NON il chain-next.
- **Census** (tre metodi concordi, BLcc esclusi verificati a zero): 0x145180→1 (0x1453EC nel wrapper 0x1453E4); wrapper→580 {p0:114, p2:59, p4:352, p6:55}; 0x14510C→2 (0x1451FC/0x14531C); 0x14507C→43; 0x14505C→1 (0x16A040, servizio default 0x16A6E4); 0x145020→1; 0x145010/0x145018→0 bl (solo indirette: APERTO); 0x145B08→673.
- **LEZIONE DI BANCO (nuova)**: (1) sim esegue bl.d/b 32-bit con displacement POSITIVO grande a entrambi gli allineamenti (micro-test tmp/it18_bltest: 0x1451F0→0x169D78, 0x14522A, 0x1453AC→0x17BF60, 0x14514C→0x334194, 0x14510E→0x33412C, 0x145182→0x334128) — la divergenza it.44 riguarda SOLO i negativi grandi; (2) gap di zero tra finestre ELF contigue: una `b` originale esclusa dal range decodifica come branch su sé stesso (loop infinito visto su 0x14514C prima di estendere la finestra a 0x145150); (3) delay slot di bne_s che clobbera il registro prima del confronto (stub r0/nodo) e flag del btst usate da un beq successivo.

**Comandi/esiti.** `python3 Python_Trace_Scripts/s33_verify_wm_current_switcher_cpu.py` → **PASS_WM_CURRENT_SWITCHER 20261101T152007762890Z**, riesecuzione identica **152018293529Z**, post-audit **153605977322Z** + riesecuzione identica **153638728092Z** (verified_evidence.json identici salvo utc; 8 casi fault 0xDEADB001..08 al successo, 0xDEADC000+i per controllo fallito). Regressioni 6/6 PASS: guard census 152032313705Z, flag matrix 152046174641Z (14 casi), snapshot record init 152049234353Z (4 casi), service raise pending 152052Z, wm service dispatch 152059567278Z (it.46), event router producers 152103470517Z (it.45). Correzioni di banco documentate (asserzioni non indebolite, anzi estese): pool 0x145798=0x4409 mancante → aggiunta finestra .origp798; polarità ramo post (bitA=0→post A); beq 0x1452AA su flag btst bit9; stub delay-slot; sp in r26/gp; sezione .stack mancante; finestra .orig10c estesa a 0x145150.

**Fonti precise.** Payload0 (base 0x0AD800): commutatore 0x145180..0x1453E4 (pool interni 0x145350..0x145378), helper 0x14503C..0x14505C/0x14507C..0x145098/0x14510C..0x145150, attivatori 0x145150..0x145180, pool 0x145798=0x4409 e 0x14579C=0x366EA4, wrapper 0x1453E4..0x1453F2, millicode 0x334120..0x33413C/0x33418C..0x3341E4, funzione B 0x145B08..0x145B9E (pool 0x145BDC/0x145BE4/0x145BF0). Evidenze in Risultati/GUI_S33/wm_current_switcher_cpu_* (census, pool, LE scan, distribuzione 580 chiamanti, .s/.ld/.elf/.bin byte-identici al payload).

**Limiti.** Statico + 8 casi CPU con fixture (stub registratori per dispatcher/coda/post): nessun hardware, boot, rendering, scatto o persistenza; NON_INSTALLARE; circa 10% invariato. Significato FISICO dei bit di flag 0/7/8/9/A/C inferito dai soli rami (descrittori sintetici); i gestori reali di 0x4403/0x4405 NON eseguiti (i redirect sono fixture); schedulazione dei 580 chiamanti NON provata; chi installa le tabelle a runtime (0x145010/0x145018 senza chiamanti bl) APERTO; claim 0x145B08/[0x366EAC] SOLO statico (boundary da confermare); writer via limm/aritmetica/indiretti non esclusi (taint raggio 40, solo basi da pool); V1.1 vs V1.0.

**Agente e MCP.** **Agente `switcher-audit-18`** (tools.agents.spawn, atteso e integrato): C1-C7 CONFERMATI byte-esatti (decoder bl proprio su 354.607 righe, 0 discrepanze; emulatore indipendente che riproduce gli 8 casi; nessun controesempio nel taint), C8 limiti confermati; quattro precisazioni testuali APPLICATE e riverificate con le due run post-audit (r15 a 0x145338; 0x4406 a OLD oltre il gate bit7; LE scan 0x366EAC/0x366EB8 aggiunti; esclusione BLcc dichiarata); ha registrato l'esito in PMB (outbox 380). Server MCP: `mcp_pmb_nikon` (prepare iniziale + record_batch finale); REA non presente tra i connettori. Strumenti: bash/python3, objdump GNU, Runner sim ARC700, tools.agents. Nessun hardware/USB/SD.

**Prossimo passo (non ripetitivo).** (a) **Consumatore del registro notifiche p1 0x3E8BB8..0x3E8DC8** (punto it.46(a), ancora aperto): candidati ora precisi — gli installer 0x145010/0x145018 (setter delle due tabelle RAM a [0x366E94]/[+8], senza chiamanti bl: cercare jl/jump table) e il record resolver 0x14505C (unico chiamante 0x16A040 nel servizio default 0x16A6E4); un inizializzatore che copia il registro p1 in RAM collegherebbe consegna→notifica. (b) In alternativa: CPU del commutatore del controllo attivo 0x145B08 (673 chiamanti) per chiudere il terzo campo del contesto maestro con lo stesso metodo. Il punto writer-corrente è CHIUSO: non rieseguire il verificatore né l'audit di questi claim.

## Iterazione 46 — 1 novembre 2026 (ciclo 14) — DISPATCHER 0x169D78 DECODIFICATO E CPU-PROVATO: lo switch è sull'EVENTO (correzione it.45), hook [[0x367808]] con swallow 0x55AA5AA5, tabella byte 0x169DDC ×2 (`add1_s` GNU fuorviante, CPU), eventi 0x4401-0x4409→servizi {0x16A05C,0x16A0BC,default,0x16A188,0x16A1FC,0x16A66C,0x16A6A8,0x16A29C} + 0x5401-3→{0x16A834,0x16A7A4,0x16A8BC} + default 0x16A6E4; PRODUTTORE 0x4006 TROVATO (bset bit14: 0xCB950 e 0x20F972 riverificati byte, confuta it.45 «nessun produttore»); registri notifiche {handler,evento} p1 0x3E8BB8..0x3E8DC8 (66 record, 0x4006→0x20F294) e p3 (0x7834C0/0x783BE0) — CONSUMATORE APERTO; contesto maestro 0x366E94 (pool 0x145350) con current+0x10/pending+0x14/attivo+0x18; LEZIONI: LIMM_16 = halfword scambiati all'indirizzo allineato; trampolino = b 32-bit (b_s 16-bit → loop sim)

**Domanda affrontata.** Punto aperto (a) dell'iterazione 45: chi consegna 0x4006 alle finestre e come 0x169D78 instrada gli eventi — più la chiusura dell'audit C1-C8 rimasto pendente dalla sessione interrotta.

**Risultato.** [Rapporto](S33_GUI_WM_Service_Dispatch_0x169D78_CPU_20261101.md), [script](../Python_Trace_Scripts/s33_verify_wm_service_dispatch_cpu.py), [prove](../Risultati/GUI_S33/wm_service_dispatch_cpu_20261101T142841334814Z/), [riesecuzione identica](../Risultati/GUI_S33/wm_service_dispatch_cpu_20261101T142847767747Z/).
- **0x169D78 decodificato per intero e CPU-provato** (8 casi su byte originali, finestra 0x169D78..0x169E18 tagliata prima della b finale, pool 0x16A128..0x16A174 e prologo 0x334120..0x33413A originali, stub agli indirizzi originali): hook [[0x367808]] (swallow 0x55AA5AA5, caso svc_hook), fast path nullo, switch sull'EVENTO con cmp 0x5401-3 diretti e jump table 0x169DDC per 0x4401-0x4409 (byte ×2 → stub ld_s 0x169DE6..0x169E0E → pool 0x16A138+4k'), default 0x16A6E4 per ogni altro evento; i servizi ricevono (node,event,arg) invariati (log CPU r0/r1/r2). Mappa CPU: 0x4401→0x16A05C, 0x4403/0x4404→DEFAULT, 0x4406→0x16A1FC, 0x4409→0x16A29C, 0x5401→0x16A834, altro→0x16A6E4.
- **CORREZIONE it.45** (errata applicata al MD it.45): «nodo≤8 → jump table» è falso; lo switch è sull'evento. Confermata indipendentemente dall'audit (C5).
- **Produttore 0x4006 trovato** (audit + riverifica byte): `mov_s r1,0x6; bset_s r1,r1,0xe; bl 0x169EB4` a 0xCB950 (desc=0, arg 0xFF, cluster CaptureMenu; subito dopo risolve current node e consegna 0x4114) e 0x20F972 (arg contatore 0..0x63). Altri bset segnalati dall'audit: 0x16E6A0, 0x653E30, 0x65BA36; 0x4001×4, 0x4002×29, 0x4003, 0x4005, asl-built 0x7C00/0x7D00. La consegna 0x4006 NON è più APERTA: produttore→0x169EB4→coda→ciclo→0x169E1C→current window→router→tabella→ponte D 0x7F877C.
- **Registri notifiche {handler,evento} nuovi**: p1 0x3E8BB8..0x3E8DC8, 66 record (0x4006→0x20F294, 0x4001→0x144F30, 0x4002→0x20EF00, 0x4005→0x20FDA4, 0x4410, tasto 0x80-0x900, sistema 0x7C40-0x7D10, 0x410A/0x4111/0x4120-0x4124); p3 0x7834C0 {handler,evento} e 0x783BE0 {evento,handler} (0x4006→0x654024/0x65CA60, 0x3B81→0x65C08C). NESSUNA LE ai confini p1: consumatore APERTO.
- **Contesto maestro 0x366E94** (pool 0x145350): +0x10 current (0x366EA4, scritto dal commutatore 0x145180 che consegna 0x4401-0x4409/0x4414/0x4415 via pool 0x145354..0x145378), +0x14 pending (0x366EA8), +0x18 controllo attivo (0x366EAC). Secondo lettore di [[0x366EA4]]: 0x1453FC (audit C8c, riverificato); NESSUN writer statico (APERTO).
- **LEZIONI DI BANCO**: (1) `add1_s` (0x7C14) nel sim/toolchain GNU scala ×2 (mappa 9/9 consistente solo con ×2 + CPU); (2) LIMM_16: costante a 4-allineato successivo con HALFWORD SCAMBIATI (0x169DA0: aa 55 a5 5a = 0x55AA5AA5); (3) il trampolino di taglio è un b 32-bit (`w,00,00,00`+nop, w=(target-(cut&~3))+1): la variante 16-bit b_s veniva letta come word spuria e mandava il sim in loop.

**Audit indipendente** (agente `router-audit-14`, revisione C1-C8 del verificatore it.45, decoder BL proprio): C1/C2/C3/C6/C7 CONFERMATI; C4/C5 PARZIALI con confutazione del claim 0x4006 (produttori bset sopra) e conferma della correzione switch-su-evento; C8: 7 LE di 0x169EB4 = pool jl_s (eventi 0x80/0x100/0x580/0x7CF6), 19 tail-b alle post API (nessun evento ponte), 3916 commenti GNU bl divergenti in regioni dati decodificate come codice (nessun impatto sui census). Esito audit registrato in PMB (outbox 378). Sezione Audit integrata nel rapporto e in [S33_GUI_Event_Router_Produttori_Ponte_CPU_20261101.md](S33_GUI_Event_Router_Produttori_Ponte_CPU_20261101.md).

**Comandi/esiti.** `python3 Python_Trace_Scripts/s33_verify_wm_service_dispatch_cpu.py` → **PASS_WM_SERVICE_DISPATCH 20261101T142841334814Z** + riesecuzione identica 142847767747Z (tutte le sezioni identiche, solo utc). Regressioni 5/5 PASS dopo: guard census 142853042095Z, flag matrix 142905347284Z, snapshot init 142905847979Z, raise pending 142906Z, event router producers 142911035356Z. Correzioni di banco documentate (asserzioni invariate): finestra 160 byte, fette cmp LIMM_16 a 6 byte, predicato LE 4-allineato, confini p1 0x3E8DC8, trampolino 32-bit, range PC sonda.

**Fonti precise.** p0: 0x169D78..0x169E18, tabella byte 0x169DDC, stub 0x169DE6..0x169E0E, pool 0x16A12C..0x16A170, prologo 0x334120..0x33413A, commutatore 0x145180, pool 0x145350..0x145378, resolver 0x1453F4/0x1453FC (pool 0x14579C), produttori 0xCB950/0x20F972; p1: registro 0x3E8BB8..0x3E8DC8; p3: 0x7834C0/0x783BE0; p5: 8 voci 0x4006. Evidenze in Risultati/GUI_S33/wm_service_dispatch_cpu_*.

**Limiti.** Statico + 8 casi CPU sintetici; nessun hardware/boot/scatto; NON_INSTALLARE; circa 10% invariato. Consumatore del registro {handler,evento} APERTO (nessuna LE ai confini); reattori (0x20F294) non eseguiti; writer di [0x366EA4] non trovato staticamente; produttori bset 0x16E6A0/0x653E30/0x65BA36 solo statici; schedulazione runtime non provata; chiamate indirette jl invisibili; il sim GNU è divergente su b 32-bit e (nuova lezione) su b_s 16-bit nei trampolini e sull'etichetta add1_s — ogni finestra va tagliata prima delle b e i trampolini sono a 32 bit.

**Prossimo passo (non ripetitivo).** (a) Consumatore del registro notifiche p1 0x3E8BB8..0x3E8DC8: cercare il percorritore {handler,evento} (candidati: inizializzatori verso array RAM [0x366E94+8/+0xC] — vedi 0x14507C(idx) che legge [base+2*idx] — o jl_s con base calcolata); provare in CPU il reattore 0x20F294 con evento 0x4006 e modo 0x82/alternativi per verificare l'inoltro alla finestra corrente. (b) Writer di [0x366EA4]: census dei lettori di pool 0x145350 e degli store indiretti nel commutatore 0x145180 (st_s r13,[r0,0x10]).

## Iterazione 45 — 1 novembre 2026 — EVENT ROUTER E PRODUTTORI PONTE: catena di consegna GUI decodificata (produttore→0x169EB4/0x169F40/0x169F00→insert coda 0x17BC7C/push-front 0x17BCE4→ciclo 0x15AF1C→extract 0x17BD4C→deliver 0x169E1C→resolver [[0x366EA4]]→0x169D78→router 0x7F6824→0x169F60 con LISTA DI ESCLUSIONE array 0x99ACAC→tabella 0x99AB8C→handler ponte 0x7F871C, 8 casi CPU con dispatch3181 completo e caso blocked; census produttori 0x3181×11/0x3301×4/0x3B81×1/0x3281×7; sessione interrotta per limite di output, audit completato in it.46

**Domanda affrontata.** Punto aperto (a) dell'iterazione 44: chi invia gli eventi del ponte alla finestra con tabella 0x99AB8C, partendo dall'array di 16 ID a 0x99ACAC e dal ciclo WindowManager.

**Risultato.** [Rapporto](S33_GUI_Event_Router_Produttori_Ponte_CPU_20261101.md), [script](../Python_Trace_Scripts/s33_verify_event_router_producers_cpu.py), [prove](../Risultati/GUI_S33/event_router_producers_cpu_20261101T134913644349Z/), [riesecuzione](../Risultati/GUI_S33/event_router_producers_cpu_20261101T134925410763Z/). **PASS_EVENT_ROUTER_PRODUCERS 20261101T134913644349Z** + riesecuzione identica + riesecuzione 140935889069Z in it.46. Catena di consegna completa (statica + 8 casi CPU su byte originali, fault 0xDEADA201..0xDEADA801); coda ad anello {arg0 u16, evento u16, arg u32} stride 12, 128 voci, indici read+0/write+2 NON scalati; 0x169F60: array 0x99ACAC = LISTA DI ESCLUSIONE (evento presente → NO dispatch); caso dispatch3181 esegue produttore→coda→router→tabella→handler 0x7F871C→transizione modo 0x2C→guardia:=[0x89A330]=7→forward; caso blocked con 0x3181 nell'array → handler mai chiamato. Prove salvate e audit chiuso in it.46: C1-C8 con confutazione del claim 0x4006 (produttori bset) e correzione switch-su-evento di 0x169D78 (errata nel MD). Sessione interrotta per assenza di output dopo l'attesa dell'audit: il log è in Risultati/Vibe_Offline/20261101T112158_933201Z_1265610/round_000013/console.log; lo script era già PASS con prove su disco, l'audit non era stato raccolto.


## Iterazione 44 — 1 novembre 2026 — PONTE 0x89A330 → guardia CaptureMenu CHIUSO: i consumatori della cella del gate 0x4405 sono sette handler fratelli della STESSA finestra (tabella 0x99AB8C completa: 35 coppie + terminatore 0x99ACA4 + array di 16 ID evento con i quattro slot pulsante); 0x3B81→0x7F8674 e 0x3181→0x7F871C copiano [0x89A330] nella guardia 0x365751 DOPO la transizione alla modalità desiderata — la guardia salvata RIENTRA nella guardia CaptureMenu; dispatcher 0x7F9468: 0/0x325,0x128,0x124 sulle risorse 0x4831/0x482E/0x482F; gate 0x7F936C legge [0x89A2FC+0x34] (stessa cella, base diversa); LEZIONE: il sim GNU diverge dai b 32-bit con displacement grande/negativo (wrap mod 8192, delta 0x2000) — finestre tagliate prima della b (verificatore Saved_Guard_Bridge PASS x3, audit C1–C9 integrato con 3 ponti estesi)

**Domanda affrontata.** Punto aperto (a) dell'iterazione 43: decodificare i contesti di 0x7F8694/0x7F8764 (lettori di [0x89A330] che alimentano il setter guardia 0xCA2F4) e di 0x7F947E (dispatch 0..4 sulla stessa cella) — gate, condizioni e ordine rispetto all'handler 0x4405/attesa 0x158d04 — per stabilire se la guardia salvata copiata dal gate rientra nella guardia CaptureMenu.

**Risultato.** [Rapporto](S33_GUI_Ponte_Guardia_Salvata_0x89A330_Handler_CPU_20261101.md), [script](../Python_Trace_Scripts/s33_verify_capture_saved_guard_bridge_cpu.py), [prove](../Risultati/GUI_S33/saved_guard_bridge_cpu_20261101T131950005757Z/), [riesecuzione identica](../Risultati/GUI_S33/saved_guard_bridge_cpu_20261101T132020022000Z/), [post-audit](../Risultati/GUI_S33/saved_guard_bridge_cpu_20261101T132744210279Z/).
- **Tabella eventi 0x99AB8C COMPLETA** (p5): 35 coppie (evento,handler) fino a 0x99AC9C, terminatore (0, 0x20E814) a 0x99ACA4, poi 8 word a 0x99ACAC..0x99ACC8 con **16 ID evento packed** (inclusi i quattro slot logici pulsante 0x580/0x581, 0x700/0x701, 0x2180/0x2181, 0x2700/0x2701). I quattro handler del ponte (0x3B81→0x7F8674, 0x3301→0x7F86C0, 0x3181→0x7F871C, 0x4006→0x7F877C) hanno ZERO chiamanti bl e UNA sola word LE ciascuno nella propria cella: callback puri della finestra che possiede 0x4405→0x7F6A90.
- **Ponte A/B (CPU, byte originali)**: transizione alla modalità DESIDERATA (getter 0xD0528/0x3657C8 → 0xCA404) e POI **guardia 0x365751 := [0x89A330]** via setter originale 0xCA2F4; notify 0x5E; forward condizionale (0x210BE4×2). Casi: [0x89A330]=7→guardia 7 (forward preso), =0→guardia 0 (forward NON preso), =3→guardia 3 con 0xCB5E4 che riceve r0=3 (il setter preserva r0). **La guardia salvata 0x3657CC (snapshot di 0xD0478, it.42) copiata dal gate 0x4405 in 0x89A330 (it.43) rientra così nella guardia CaptureMenu** — la condizione che nel modo 0x2C mantiene selezionabili le voci 0x0A/0xBB di 0x4801 (it.39–40). Ordine interno: PRIMA 0xCA404 (che può già ripristinare guard=7 dal flag 0x36580C), POI la sovrascrittura con [0x89A330].
- **Ponte C (0x3301)**: gate 0x7F936C; se ≠0→0x7F9BD4(ctx,1); guardia := 0; poi stb 2→[0x89A2FC+0x24] se [0x89A31E]≠0 (uscita senza transizione) oppure stb 1→[+0x2A] + transizione+forward. Entrambe le vie provate in CPU. **0x7F9BD4(ctx,0)**: altra via guardia:=0 + word [0x89A310]:=0.
- **Dispatcher 0x7F9468** (3 chiamanti: 0x7F83FE, 0x7F87C2 dentro 0x4006, 0x7F88D6): gate 0x7F936C; se 0: byte [0x89A330] → jump table 0x7F9492 (`0a 03 03 03 03`, add1) → valori 1..4=(0x325,0x128,0x124), 0 e >4=(0,0,0) → tre risorse **0x4831/0x482E/0x482F** via 0x145654+0x633768; con la query del gate che risponde 1 il dispatcher esce SENZA chiamate (caso negativo v1_q1skip).
- **Gate 0x7F936C**: pool reale 0x7F90B8=0x89A2FC; `ldb [r13,52]` = **[0x89A2FC+0x34] = 0x89A330** (stessa cella, base struct diversa da 0x89A318+0x18); se ∈{1,2} → 0x14918C([+0xC],3)==1 → gate 1. Epilogo condiviso 0x3341A4 (famiglia mov r12/r13,4; b 0x3341DA; ld.ab×2; j_s [blink]) eseguito con byte ORIGINALI.
- **LEZIONE DI BANCO (nuova)**: la `b` 32-bit a 0x7F86B6 (W=0xFF0F03CD, displacement negativo grande, PC≡2 mod 4) viene decodificata da GNU objdump come 0x7F6A80 ((PC&~3)−7220) ma dal sim come 0x7F8A80 ((PC&~3)+972): delta esatto 0x2000=8192, il sim applica al campo un **wrap mod 8192** invece dell'estensione di segno. I `bl` retrocessi alla stessa alignment (0x7F86B2→0x20E814) e i b/bne GNU-assemblati con displacement −16/−18 (micro-test bneg.s/bneg2.s) sono eseguiti CORRETTAMENTE dal sim: la divergenza riguarda i bit alti del campo. **Nessun caso CPU esegue una b 32-bit del firmware**: finestre tagliate prima della b, trampolino hand-encoded (W=d+1, d piccolo positivo, forma identica ai b con label GNU) verso il probe. Quale decodifica corrisponda all'hardware reale NON stabilito. Evidenza: estratto trace + micro-test nelle prove.

**Comandi/esiti.** `python3 Python_Trace_Scripts/s33_verify_capture_saved_guard_bridge_cpu.py` → **PASS_CAPTURE_SAVED_GUARD_BRIDGE 20261101T131950005757Z**; riesecuzione **132020022000Z** identica; post-audit (solo docstring corretto: 35 coppie/terminatore 0x99ACA4/array da 0x99ACAC) **132744210279Z**, asserzioni congelate invariate. Correzioni di banco durante lo sviluppo (documentate, asserzioni invariate): jl_s richiede r0-r3/r12-r15; `st r,[r,r]` rifiutato dal vecchio as (stub riscritti con cmp/beq); probe troppo grande per il gap prima del pool → trampolino; Runner crea la directory out (non pre-crearla). Regressioni tutte PASS: guard setter census **132027Z**, flag mode matrix 14 casi **132042Z**, snapshot record init 4 casi **132055Z** (primo tentativo con nome file errato, documentato), service raise pending **132043Z**.

**Agente e MCP.** **Agente `bridge-audit-45`** (tools.agents.spawn, atteso e integrato; «task con agente explore» inesistente, come documentato): metodo indipendente (sha256 blocchi, ridisassembly ex-novo, census propri con target ricalcolati, LE scan a ogni offset, tracer registro→pool, evidenze congelate lette senza rieseguire) → **C2–C9 CONFERMATI byte-esatti; C1 confutato SOLO nel docstring** (corretto e rieseguito). **CONTROESEMPI ACCOLTI E RIVERIFICATI IN COORDINATORE (byte-esatto)**: tre ulteriori handler ponte nella stessa finestra — 0x0100→0x7F7EB0 (pool 0x7F7B84, `ldb [r14,52]` a 0x7F7F00, setter a 0x7F7F04), 0x0180→0x7F7FAC (pool 0x7F7FFC, ldb a 0x7F7FDA, setter a 0x7F7FDE), 0x0400/0x0480/0x0500→0x7F850C (pool 0x7F830C, ldb a 0x7F8574, setter a 0x7F8578) — **almeno sette handler della finestra fanno il ponte** (conclusione rafforzata). Altri lettori di 0x89A330: 0x7F6C84 (dentro l'handler 0x4405), 0x7F9B34, 0x7F9DF2. Scrittori confermati solo i due del gate. 0x20E814: 215 chiamanti bl in p4, «forward» resta interpretazione contestuale. Server MCP: `mcp_pmb_nikon` (prepare iniziale + record_batch finale; REA non presente tra i connettori). Strumenti: bash/python3, objdump GNU, tools.agents. Nessun hardware/USB/SD.

**Fonti precise.** Payload4 (base 0x796800): 0x7F8674..0x7F86B8 (+pool 0x7F86BC=0x89A330), 0x7F871C..0x7F8776, 0x7F86C0..0x7F8718, 0x7F877C..0x7F87DC; 0x7F9468..0x7F94DE (+pools 0x7F94E4=0x89A330, 0x7F94E8=0x4831, 0x7F94EC=0x482E, 0x7F94F0=0x482F, jump table 0x7F9492); 0x7F936C..0x7F93A6 (+pool 0x7F90B8=0x89A2FC); 0x7F9BD4..0x7F9C30 (+pool 0x7F9CA4=0x89A310); pool 0x7F8370=0x89A31E, 0x7F830C=0x89A2FC, 0x7F8814=0x89A2FC, 0x7F85B0=0x681EEB; epiloghi condivisi 0x7F6A80/0x7F7408. Payload5 (base 0x897800): tabella 0x99AB8C..0x99ACA4, array ID 0x99ACAC..0x99ACC8. Payload0 (base 0xAD800): getter 0xD0528 (pool 0xD0530=0x3657C8), setter 0xCA2F4 (pool 0xCA30C=0x365751), prologhi 0x33412C/0x334128, epilogo 0x3341A4..0x3341E4.

**Limiti.** Statico + 10 casi CPU sintetici (getter/setter/prologhi/epilogo ORIGINALI; transizione, notify, forward, gate-query e risorse come stub recorder): nessun hardware, scatto, rendering, persistenza. **Chi invia gli eventi 0x3B81/0x3181/0x3301/0x4006 (e i ponti estesi) NON è tracciato**: l'ordine rispetto a 0x4405/0x158d04 è DATAFLOW, non schedulazione runtime dimostrata. Il target della `b` finale (epilogo 0x7F6A80/0x7F7408) non provato in CPU (v. lezione). Corpi oltre le finestre (0x210BE4, 0x14918C, 0x145654, 0x633768, 0x149028, 0x143afc, 0x176828, 0xC7E04, 0x14905C, 0xCD8CC, handler 0x3081/0x4001/0x4110/0x3281/0x4002) NON decodificati; significato risorse 0x4831/0x482E/0x482F, valori 0x325/0x128/0x124 e semantica dell'array di 16 ID APERTI. V1.1 vs V1.0. Circa 10% invariato; NON_INSTALLARE.

**Prossimo passo (non ripetitivo).** (a) **Produttori degli eventi del ponte**: chi invia 0x3B81/0x3181 (e i tre ponti estesi 0x0100/0x0180/0x0400) alla finestra — cercare nel router eventi/WindowManager (partire dall'array di 16 ID a 0x99ACAC e dai notify tipo 0x1453E4) per trasformare il dataflow «save→0x4405→0x89A330→0x3B81/0x3181→guardia» in una SEQUENZA runtime dimostrata; è il pezzo che rende il ciclo quantitativamente prevedibile per la GUI AkeruOS. (b) Alternativa: decodificare i tre handler estesi (0x7F7EB0/0x7F7FAC/0x7F850C) e le risorse 0x4831/0x482E/0x482F con i valori 0x325/0x128/0x124 (che cosa la finestra mostra in funzione di [0x89A330]). (c) Alternativa di lungo corso: descrittore finestra struct 0x99AB40 e registrazione WindowManager (it.43 (b), ancora aperta). Il ponte 0x89A330→guardia è CHIUSO: non rieseguire il verificatore né l'audit di questi claim.

## Iterazione 43 — 1 novembre 2026 — Restore 0x7F9F7C del blocco contesto CHIUSO: unico chiamante 0x7F6BB0 dentro l'handler dell'evento 0x4405 della finestra con tabella 0x99AB8C (che gestisce anche 0x2180→0x7F7F8C); gate 0x14504C(a,0x12)==3 → azzera 0x89A330, altrimenti copia la guardia salvata 0x3657CC; il restore NON avviene rientrando nel modo di scatto ma dopo la transizione a modo 3 e l'attesa 0x158d04(0x2600001,8,0,0x2710); dispatcher 6 valori + costante 0x64→0x14A900; consumer→celle 0xC8EC52/0x3676F8/0x367C05/0x367C06/0x365BBD (verificatore Capture_Restore_Caller_Census PASS x2, audit C1-C8 confermato)

**Domanda affrontata.** Punto aperto dell'iterazione 42: census dei chiamanti `bl` del restore 0x7F9F7C (p4) e del contesto 0x7F6ADE/0x7F6AE6 con classificazione dei gate — se il restore scatta rientrando nel modo di scatto (candidato: il modo 3 dei tre caller save_then_mode3) e quali consumer ricevono i valori salvati da 0xD0478.

**Risultato.** [Rapporto](S33_GUI_Cella_Desiderata_Restore_Census_CPU_20261101.md), [script](../Python_Trace_Scripts/s33_verify_capture_restore_caller_census.py), [prove](../Risultati/GUI_S33/capture_restore_caller_census_cpu_20261101T125629170398Z/), [riesecuzione identica](../Risultati/GUI_S33/capture_restore_caller_census_cpu_20261101T125636197637Z/) (casi CPU 30/32/11/13/12/113/113 istruzioni, fault identici; static byte-identico salvo utc).
- **Census**: 0x7F9F7C ha ESATTAMENTE un chiamante bl = **0x7F6BB0** (p4, incondizionato); ZERO parole LE 0x7F9F7C nei 16 payload e nell'intero firmware.bin (audit). La funzione contenitore **0x7F6A90 non ha chiamanti bl**: è un callback registrato — unica word LE a 0x99AB98 (p5) nella **tabella eventi 0x99AB8C**: 0x4401→0x7F6A50, **0x4405→0x7F6A90**, 0x4406→0x7F7218, 0x440E→0x7F7438, 0x440C→0x7F8394; stessa tabella: **0x2180→0x7F7F8C** (0x99ABD4/D8). Ogni getter del blocco ha un solo chiamante: sei dentro il restore (0x7F9F7E/86/9A/A2/AA/B2), 0xD04DC a 0x7F6AE6 fuori.
- **Restore = dispatcher senza branch** (0x7F9F7C..0x7F9FBC, 19 istruzioni): 0xD0520(**ldw_s.x**, halfword con estensione di segno, 0x3657CA)→0xCE1EC; 0xD04E8(0x3657D0)→0x17C5E4 con **r1=r2=-1**; **COSTANTE 0x64→0x14A900** (non un valore salvato — correzione di dettaglio verso it.42); 0xD0518(**ld 32-bit**, 0x3657D4)→0x163D6C; 0xD04F4→0x17E124; 0xD0500→0x17E36C; 0xD050C→0xDEBCC. **0x3657C8 e 0x3657CC NON sono ripristinate dal restore.**
- **Risposta alla domanda**: il restore NON avviene rientrando nel modo di scatto. L'handler 0x7F6A90 (evento 0x4405) prima transita al **modo 3** (mov r0,3; bl 0xCA404 a 0x7F6AF0), poi chiude le sottofinestre [0x99AAE8] via 0x145b08, azzera 0x89A318+0xA..0x19/0x89A334, richiede la risorsa 0x4A1C (0x145654/0x1450b8 con 360), **attende 0x158d04(0x02600001, 8, 0)** (pool 0x7F6E34, 0x7F6E38=0x2710), e SOLO POI chiama il restore. Il gate 0x7F6AD2..0x7F6AEE: risultato di **0x14504C(arg,0x12)** ==3 → [0x89A330]=0; !=3 → copia la **guardia salvata** (0xD04DC, byte 0x3657CC) in 0x89A330.
- **Consumer identificati** (finestre congelate): 0xCE1EC→stw [0xC8EC52] + tail 0xDE664/0xC979A; 0x17C5E4 agisce solo se byte==0xFE; 0x163D6C→st [0x3676F8]; 0x17E124→stb [0x367C05] + dispatch ≤0x10; 0x17E36C→stb [0x367C06] + validatore + dispatch ≤0xB; 0xDEBCC→valida 0xDEB70 poi stb [0x365BBD]. Post-restore: **0x7F9B00** legge [0x89A330] (pool 0x7F9B14) e ritorna 1 solo per valori {1,2} (3 chiamanti: 0x7F6BB4, 0x7F6BE0, 0x7F9B2A); **0xD0800** (9 chiamanti) legge 0x3657F4 (pool 0xD0818) dietro gate 0x15AD44, tail 0xCA384.
- **CPU 7 casi byte originali**: gate query=3 → 0x89A330 azzerato (fault 0xdead0000, 0x3657CC intatta = getter non chiamato, sentinelle intatte); query=4 → 0xdead0007 (guardia salvata copiata dal getter ORIGINALE 0xD04DC); 0x7F9B00 con [0x89A330]=1/2/3 → 1/1/0 (0xdead0001/0001/0000); restore_dispatch_a/b con marker distinti (0x1234/0x37/0x190/0x11/0x22/0x33 e 0x4321/0xC9/0x22C/0x77/0x88/0x99) → 0xdeadaa01: verifica per-slot ordine e argomenti, inclusi r1=r2=0xFFFFFFFF (0x17C5E4) e r0=0x64 (0x14A900). Scoperta tecnica: 0xD0520 = ldw_s.x (halfword CON segno; marker bit15=0), 0xD0518 = ld 32-bit (word a 4 byte).

**Comandi/esiti.** `python3 Python_Trace_Scripts/s33_verify_capture_restore_caller_census.py` → **PASS_CAPTURE_RESTORE_CALLER_CENSUS 20261101T125629170398Z**; riesecuzione **125636197637Z** identica. Correzioni di banco durante lo sviluppo (documentate, asserzioni congelate invariate): coppia 0x2180 letta a 0x99ABD4/D8; righe pool aggiunte alle finestre congelate CE1EC/163D6C/DEBCC/7F9B00; finestra D0800 estesa a 0xD0818; assembly del caso mai linkato nel primo build (entry default); pool del gate 0x7F6E20 aggiunto ai casi gate; marker ldw_s.x/ld 32-bit. Regressioni tutte PASS: guard setter census **125645380828Z**, flag matrix **125702318965Z**, snapshot record init **125703162581Z**, service raise pending **125704Z**, desired cell producer **125710935707Z**.

**Agente e MCP.** **Agente `restore-audit-44`** (tools.agents.spawn, atteso e integrato; «task con agente explore» inesistente, come documentato): metodo indipendente (362.109 branch con target ricalcolato (PC&~3)+disp, 13 finestre ridisassemble ex-novo, scan LE a ogni offset dei 16 payload E dell'intero firmware.bin, evidenze congelate lette senza rieseguire il verificatore) → **C1–C8 tutti CONFERMATI, zero controesempi di sostanza**. Aggiunte riverificate in coordinatore: lettori aggiuntivi di 0x89A330 = **0x7F8690/0x7F875E** (ldb [pool 0x7F86BC]) il cui byte va **direttamente al setter guardia 0xCA2F4** (0x7F8694, 0x7F8764) e **0x7F947E** (ldb [pool 0x7F94E4], cmp 4, dispatch 0..4) — PONTE NUOVO tra il gate del restore e la guardia CaptureMenu; secondo chiamante di 0x14A900 = 0x64EF94 (p2). Correzioni documentali: nessun file .trace nelle evidenze (cpu evidenza = verified_evidence.json + harness .s/.ld + .orig*.bin byte-identici); l'ordine consumer è nella sequenza bl statica, i casi CPU provano chi riceve quale argomento. Server MCP: `mcp_pmb_nikon` (prepare iniziale + record_batch finale; REA non presente tra i connettori). Strumenti: bash/python3, objdump GNU, tools.agents. Nessun hardware/USB/SD.

**Fonti precise.** Payload4 (base 0x796800): restore 0x7F9F7C..0x7F9FBC; handler 0x7F6A90 (prologo 0x7F6A90..0x7F6ABE: r14/r17/r18, 0xD1644, 0x143afc, 0x14504C(a,6)); gate 0x7F6AD2..0x7F6AF0 (pool 0x7F6E20=0x89A318); sito chiamante 0x7F6B9E..0x7F6BF2 (pool 0x7F6E2C=0x89A334, 0x7F6E30=0x4A1C, 0x7F6E34=0x02600001, 0x7F6E38=0x2710); 0x7F9B00 (pool 0x7F9B14=0x89A330); lettori guardia 0x7F8690/0x7F875E (pool 0x7F86BC), 0x7F947E (pool 0x7F94E4). Payload5 (base 0x897800): tabella 0x99AB8C, coppia 0x2180 a 0x99ABD4/D8, struct 0x99AB74=0x99AAE8, 0x99AB78=0x7F6824. Payload0 (base 0xAD800): cluster getter 0xD04C8..0xD0534 (pool 0xD04C8/CC/D0/D4/D8/0xD0530); consumer 0xCE1EC (0xCE208=0xC8EC52), 0x163D6C (0x163D84=0x3676F8), 0x17E124 (0x17E234=0x367C05), 0x17E36C (0x17E368=0x367C06), 0xDEBCC (0xDEBE4=0x365BBD), 0x17C5E4 (0x17C718=0xFFFF), 0xD0800 (0xD0818=0x3657F4), 0x14A900.

**Limiti.** Statico + 7 casi CPU sintetici (query 0x14504C e consumer sostituiti da stub in copia; pool e getter originali); nessun hardware, scatto, rendering, persistenza. Schedulazione runtime dell'handler 0x7F6A90 NON provata: chi invia 0x4405 a questa finestra resta APERTO; il collegamento save→restore via modo 3 resta ipotesi coerente, non catena dimostrata. teste dei consumer congelate, corpi oltre (jump table, 0xDEB70, 0xDE664, 0x14A900) NON decodificati; attesa 0x158d04/id 0x2600001 NON decodificata; unicità writer di 0x89A330 non esaustiva (raggio 8 istruzioni, 7 pool base 0x89A318); chiamate indirette statisticamente invisibili. V1.1 vs V1.0. Circa10% invariato; NON_INSTALLARE.

**Prossimo passo (non ripetitivo).** (a) **Ponte 0x89A330 → guardia**: decodificare i contesti di 0x7F8694/0x7F8764 (il byte [0x89A330] passato al setter 0xCA2F4) e 0x7F947E (dispatch 0..4 sulla stessa cella) — gate, condizioni e ordine rispetto all'handler 0x4405/attesa 0x158d04, per stabilire se la guardia salvata copiata dal gate rientra nella guardia CaptureMenu: chiude il collegamento restore→guardia/flag (it.39–41). (b) Alternativa: descrittore della finestra con tabella 0x99AB8C (struct 0x99AB40: 0x99AAE8/0x7F6824/0x99AB6C=0x402/0x99AB70=0x0021007E) e sua registrazione nel WindowManager, collegando il restore ai percorsi GUI (0x2180→0x7F7F8C già in tabella). Il census restore e il suo audit sono CHIUSI: non rieseguirli.

## Iterazione 42 — 1 novembre 2026 — Produttore della cella «modalità desiderata» 0x3657C8 CHIUSO: è la funzione di salvataggio 0xD0478 che copia la cella modalità 0xC8E80C al momento dell'uscita dal modo di scatto (5 chiamanti, 4 escono esplicitamente, 3 verso il modo 3); blocco contesto 0x3657C8..0x3657D4 con getter 0xD04DC..0xD0528 e restore 0x7F9F7C; CPU: copia originale, store r13+8, correzione getter 0xD0518 (WORD 0x3657D4 via pool 0xD04CC)

**Domanda affrontata.** Chiusura del tentativo interrotto della sessione precedente (run 1219–1224Z status=RUNNING senza verified_evidence.json; script 13:26Z mai rieseguito): punto aperto (a) it.41 — produttore runtime della cella 0x3657C8 (struct 0x365750+0x78), letta da 0xD0528 e passata da 15 feeder a 0xCA404, senza writer statico noto.

**Risultato.** [Rapporto](S33_GUI_Cella_Desiderata_Produttore_Save_Restore_20261101.md), [script](../Python_Trace_Scripts/s33_verify_capture_desired_cell_producer_cpu.py), [prove](../Risultati/GUI_S33/capture_desired_cell_producer_cpu_20261101T123804339327Z/), [riesecuzione identica](../Risultati/GUI_S33/capture_desired_cell_producer_cpu_20261101T123843298972Z/) (i run interrotti 1219–1224Z restano tentativi archiviati, NON prova).
- **Produttore = save 0xD0478** (p0): salva il blocco contesto 0x3657C8..0x3657D4 — 0x3657CA word←0xDE6D0, 0x3657D0 byte←0xDE398, 0x3657D4 word←0x14A1F8 (clamp ≤400), 0x3657CC byte←guardia (getter 0xCA310), 0x3657CD←0x17E238, 0x3657CE←0x17E460, 0x3657CF←0xDEBE8, **0x3657C8 byte←cella modalità 0xC8E80C** (ld_s a 0xD04BE, pool 0xD04D8) con `stb_s r0,[r13,0x8]` a 0xD04C2 (r13=pool 0xD04D0=0x3657C0); coda b 0xCA2CA→epilogo 0x33419C. La cella è uno **SNAPSHOT della modalità corrente preso uscendo dal modo di scatto**.
- **Unicità writer** (ambito dichiarato: 167 pool in [0x365740..0x365860], tracking registro invalidato, age 24): unico store con EA 0x3657C8 = **0xD04C2**; NON esclusi writer via puntatori in registri attraverso chiamate o aritmetica non-pool.
- **5 chiamanti bl** di 0xD0478: 0x20ED7A (notifica 0x7E via 0x1453E4), 0x65602C/0x65C3D4/0x8021FE (→ `mov r0,3`+bl 0xCA404, modo 3), 0x66361A (catena uscita 0xCB5E4/0x145C3C/0xCBDF8/0x177030). 4/5 escono esplicitamente; schedulazione runtime NON provata.
- **Getter blocco**: 0xD04DC(0x3657CC)/0xD04E8/0xD04F4/0xD0500/0xD050C/0xD0518(WORD 0x3657D4)/0xD0520 — un chiamante ciascuno; sei dentro il **restore 0x7F9F7C** (p4, catena 0xCE1EC/0x17C5E4/0x14A900(0x64)/0x163D6C/0x17E124/0x17E36C/0xDEBCC, NON decodificati); il settimo (0xD04DC) è chiamato a 0x7F6AE6 fuori dal restore, guardia salvata copiata in [pool 0x7F6E20=0x89A318]+0x18=0x89A330. 0xD0528 confermato: 21 chiamanti (15 feeder 0xCA404 + 6 consumer contesto 0x252C0E/0x25327A/0x7F6AF4/0x7F8ACC/0x7FAA50/0x7FBE3A).
- **CPU 4 casi byte originali** (finestra 0xD04BE..0xD04DB): 0x46 e 0x2C copiati nella cella (fault 0xdead0046/0xdead002c, vicini intatti); r13→scratch 0x366000 lascia la sentinella (0xdead00a5: store = r13+8, controllo negativo); probe getter 0xD0518 → **0xdead5dd4**: `ld r0,[pcl,-76]` (b4 17 00 f0) risolve **pool 0xD04CC=0x3657D4** e carica la WORD — **CORREZIONE della sessione interrotta**: il pool 0xD0514 (0x3657CF) è del getter 0xD050C; lezione it.40 sull'EA estesa alla forma ld 32-bit allineata (EA=PC+imm).

**Comandi/esiti.** `python3 Python_Trace_Scripts/s33_verify_capture_desired_cell_producer_cpu.py` → **PASS_CAPTURE_DESIRED_CELL_PRODUCER 20261101T123804339327Z**; riesecuzione **123843298972Z** (static_evidence identici salvo utc). Corretto prima dell'esecuzione un solo commento obsoleto nello script (pool 0xD0514→0xD04CC del caso getter; asserzioni invariate). Regressioni tutte PASS: guard setter census **123949856825Z**, flag mode matrix **124002005140Z**, snapshot record init **124002508343Z**, service raise pending **124003Z**.

**Agente e MCP.** **Agente `desired-cell-audit`** (tools.agents.spawn, atteso e integrato; «task con agente explore» inesistente, come documentato): metodo indipendente (hash manifest 16 blocchi, ridisassembly ex-novo 16 payload, dataflow proprio, confronto esatto valore) → **C1–C7 CONFERMATI, C8 nessun controesempio** (nessun secondo getter, nessun [rN,0x78] pertinente, nessun bl/jump-table/limm alternativo; falsi positivi ;0xd04780/8a/8c di p9 scartati). Due correzioni documentali accolte e riverificate in coordinatore: basi p2=0x5FE800/p4=0x796800 (lo script non ne contiene di errate) e attribuzione restore limitata ai sei getter dentro 0x7F9F7C. Server MCP: `mcp_pmb_nikon` (prepare iniziale + record_batch finale; REA non presente tra i connettori). Strumenti: bash/python3, tools.agents. Nessun hardware/USB/SD.

**Fonti precise.** Payload0 (base 0xAD800): 0xD0478 save, 0xD04C2 store, 0xD04BE ld_s, pool 0xD04C8/CC/D0/D4/D8/0xD0530, getter 0xD04DC..0xD0528, caller 0x20ED7A; p2 (base 0x5FE800): 0x65602C/0x65C3D4/0x66361A; p4 (base 0x796800): 0x8021FE, restore 0x7F9F7C, contesto 0x7F6ADE..0x7F6AF0 (pool 0x7F6E20=0x89A318→0x89A330), non-feeder 0x7F6AF4/0x7F8ACC/0x7FAA50/0x7FBE3A; p1 (base 0x360800): byte statico 0x3657C8=0x2C.

**Limiti.** Statico + 4 casi CPU sintetici con fixture (0xC8E80C, blocco salvato): nessun hardware, scatto, rendering, persistenza. Writer via puntatori cross-call non esclusi. Schedulazione dei 5 caller del save NON provata; chiamanti del restore NON censiti; consumer del restore NON decodificati. Circa10% invariato; NON_INSTALLARE.

**Prossimo passo (non ripetitivo).** Census dei chiamanti `bl` del **restore 0x7F9F7C** (p4) e del contesto 0x7F6ADE/0x7F6AE6 con classificazione dei gate: se il restore scatta rientrando nel modo di scatto (il modo 3 in cui i tre caller save_then_mode3 collocano la macchina è il candidato naturale) e quali consumer (0xCE1EC, 0x163D6C con la word ≤400, 0xDEBCC) ricevono i valori salvati — chiude il ciclo save/restore collegandolo ai 15 feeder di 0xCA404.

## Iterazione 41 — 1 novembre 2026 — Transizione di modalità 0xCA404: census dei 63 chiamanti con classificazione dell'argomento (8 verso 0x2C, 8 verso il modo 3 che preserva la guardia, 15 verso la nuova cella «modalità desiderata» 0x3657C8), reachability della switch guardia 0xCBC00 RISOLTA con correzione della it.40 (due bl caller che passano la guardia corrente; CPU con byte originali 3→4/{0,1,2,4}→0/>4 nessuna scrittura)

**Domanda affrontata.** Prossimo passo (a)+(b) dell'iterazione 40: census dei 63 chiamanti bl della transizione di modalità 0xCA404 e classificazione del valore passato (chi porta a/da 0x2C), più reachability della switch 0xCBC00 e contesto guard==4.

**Risultato.** [Rapporto](S33_GUI_Transizione_Modalita_Censimento_Chiamanti_CPU_20261101.md), [script](../Python_Trace_Scripts/s33_verify_capture_transition_caller_census.py), [prove finali post-audit](../Risultati/GUI_S33/capture_transition_caller_census_cpu_20261101T115840936113Z/) (prima esecuzione [114158737678Z](../Risultati/GUI_S33/capture_transition_caller_census_cpu_20261101T114158737678Z/), riesecuzione identica [114219085464Z](../Risultati/GUI_S33/capture_transition_caller_census_cpu_20261101T114219085464Z/)).
- **63 chiamanti** bl di 0xCA404 (p0:15, p2:10, p4:38), lista congelata con finestre byte-esatte e proprietà «nessun writer di r0 tra produttore e chiamata». Classi: **8 passano costante 0x2C** (p0 0xC9FDA, 0xD236E, 0x1360DA, 0x1E132C; p2 0x65C670; p4 0x7D4F58, 0x80D45C, 0x8022B8), **8 passano 3** (il modo per cui 0xCA404 NON azzera la guardia), 7 passano 4, 3 passano 0xA, 1×0x21, 1×0x6F, 1×0x70, **2 refresh** col getter 0xCAD30 (early-exit), **15 passano la cella 0x3657C8** via getter 0xD0528 adiacente, 5 passano [r14,0xA] del contesto CaptureMenu (2 gated ==0x15, 1 gated ≠corrente), 1 passa il 3-vie [0x899844+0x10/0x11] (selettore +0x12), 6 passano l'argomento r1 (r14), 1 [r14,-222], 2 [0x367A34+8] gate +0x1e==1 (writer statico adiacente 0x174794–0x17479C scrive 0xA/0x4; pool reale 0x174564=0x367A34, commenti objdump ld.as non scalati), 1 r13 gated ∉{[r13,9],0x15,0x1F,0x79,0x7B,0x6E}, 1 extb(r13).
- **Sito 0x8022B8 (post-audit, direzione corretta)**: dispatcher su r13; i tre ID pulsante logico 1792/0x2180/0x2700 DEVIANO su altri handler (jl_s); la transizione a 0x2C avviene per gli ALTRI ID evento e solo se modo corrente ≠0x2C.
- **NUOVA CELLA 0x3657C8** (struct 0x365750+0x78, stessa struct di guardia +1 e flag +188): getter 0xD0528 (`ld_s r0,[pcl,0x8]`→pool 0xD0530, unica word LE nei 16 payload; `ldb_s`; `j_s`; nop_s a 0xD052E); byte statico payload1 = **0x2C** (come 0xC8E80C); 21 chiamanti bl totali, 15 feeder di 0xCA404; **nessuno scrittore statico diretto** (zero `[rN,120]` nelle 25 finestre dei pool struct; audit esteso a ±512 byte dai 31 riferimenti ai pool). Ipotesi: «modalità desiderata/ultima modalità di scatto»; produttore runtime APERTO.
- **CORREZIONE it.40 — switch 0xCBC00**: reachability NON indeterminata: **due bl caller** in p2 (0x660B8C, 0x663220), entrambi con `bl 0xca310` (getter guardia) immediatamente prima → la switch è un **trasformatore di stato della guardia**: 3→4, {0,1,2,4}→0, >4 nessuna scrittura. Gate corretti post-audit: 0x660B8C chiama se `0xce238` ritorna 4 oppure [0x681FF0+0x13]≠0 (il ramo modo 0x7A/0x7B con 0x15b024 esce senza chiamare); 0x663220 se modo∉{0x38,0x39} e [0x682098+1]≠0. «Unico produttore statico di guard=7 = 0xCA4BE» it.40 CONFERMATO. Il falso riferimento `;0xcbc00e` (V00CB7EE8) è in p9 (0xC8F800..0xF1FE00), non la switch in p0; tutte le 9 occorrenze LE di 0xCBC00 sono ≡3 mod 4 → nessuna jump table.
- **CPU con byte ORIGINALI 0xCBC00..0xCBC3B** (PT_LOAD a 0xCBC00, guardia 0x365750 sentinelle 0xA5, stack 0x365900 — nota banco: il sim esige `.stack` sopra tutte le sezioni o `init_stack` azzera la memoria): r0=0/1/2/4 → guardia 0 (fault 0xdead0000, 19 istruzioni), r0=3 → 4 (0xdead0004, 18), r0=5 → nessuna scrittura (sentinella 0x37, 11), caso neighbors: +0/+2 intatti (28). Roundtrip byte verificato su ogni ELF.

**Comandi/esiti.** `python3 Python_Trace_Scripts/s33_verify_capture_transition_caller_census.py` → **PASS_CAPTURE_TRANSITION_CALLER_CENSUS 20261101T114158737678Z**, riesecuzione **114219085464Z**, post-audit **115840936113Z** (exit 0; docstring 0x8022B8 corretta e gate 0x7CB62E esteso a 0x7CB610–0x7CB61A; asserzioni congelate invariate). Regressioni tutte PASS: guard setter census 114226104068Z, flag matrix 14 casi 114238025825Z, snapshot record init 4 casi 114238521591Z, service raise pending 114239Z.

**Agente e MCP.** **Agente `transition-audit-43`** (tools.agents.spawn; «task con agente explore» non esiste in questo ambiente, come documentato): **C1–C7 CONFERMATI, C8 nessun controesempio reale**, con metodo indipendente (regex propria + ridisassemblaggio ex-novo dei 16 payload + identità listing↔payload; encoding BL validato su 114.683 campioni; LE 0x000CA404 unica occorrenza in tabella dati p9; 6 falsi branch in tabelle dati; nessun secondo getter di 0x3657C8; nessuno scrittore ±512B dai 31 riferimenti pool; casi CPU verificati sulle evidenze congelate dopo che il suo banco loopava per errore del banco stesso). Cinque correzioni di documentazione accolte e riverificate in coordinatore (gate 0x660B8C invertito + ramo 0x15b024 non abilitante; direzione 0x8022B8; gate 0x7CB62E completo; 25 finestre non 24; nop_s). Server MCP disponibile e consultato: `mcp_pmb_nikon` (prepare iniziale + record_batch finale; server REA non presente tra i connettori). Strumenti: bash/python3 (verificatori, regressioni, finestre GNU), tools.process (regressioni in background), tools.agents (audit atteso e integrato). Nessun hardware/USB/SD toccato.

**Fonti precise.** Payload0 (base 0x0AD800): transizione 0xCA404, getter 0xD0528 (pool 0xD0530=0x3657C8), switch 0xCBC00..0xCBC3B (pool 0xCBC38=0x365750, tabella 0xCBC1C=[3,3,3,6,3], store 0xCBC24/0xCBC2A), siti per classe in tabella S[] dello script, event-dispatcher 0x8022B8 (gate 0x80228E–0x8022B6), reset 0xC9D58→0xC9D84(3,1) e setter 0xCD89C([0xC8EB18], pool 0xCD8B4), writer [0x367A34+8] 0x174794–0x17479C (pool ld.as 0x174564). Payload1 (base 0x360800): struct 0x365750..0x365850, byte 0x3657C8=0x2C statico. Payload2 (base 0x5FE800): caller switch 0x660B8C (pool 0x660BEC=0x681FF0) e 0x663220 (pool 0x663320=0x682098), setter guardia const3_if_guard_4 0x653E02/0x654E84 (it.40). Payload4 (base 0x796800): 38 chiamanti, 3-vie 0x7CAED0 (pool 0x7CAE9C=0x899844). Payload9 (base 0xC8F800): falso riferimento 0xCB7EE8→0xCBC00E; LE 0xCA404 a 0xEF3AE2 in tabella dati.

**Limiti.** Statico + 7 casi CPU (byte switch originali; pool/stack sintetici); argomenti calcolati non circoscritti tranne [0x367A34+8] ({0xA,0x4} dal writer adiacente, senza escludere writer runtime); nessuno scrittore statico di 0x3657C8 ma aritmetica di puntatore/bulk-copy non escluse; jump indiretti runtime non coperti; 0x2C come «modalità di scatto» resta interpretazione coerente con it.39/40, non etichetta Nikon; gate su funzioni non decodificate (0xce238, 0x15b024, 0xc9d84) documentati non decodificati; reachability runtime (scheduler/WindowManager/eventi reali) NON dimostrata; V1.1 campione vs macchina V1.0. Statico+CPU emulata, nessun hardware, NON_INSTALLARE, circa 10% invariato.

**Prossimo passo (non ripetitivo).** (a) **Produttore runtime della 0x3657C8**: con lo scrittore statico diretto escluso, cercare copie bulk della struct 0x365750 o i 6 chiamanti non-feeder di 0xD0528 (0x252C0E, 0x25327A, 0x7F6AF4, 0x7F8ACC, 0x7FAA50, 0x7FBE3A) per stabilire chi scrive la «modalità desiderata» e quando diverge da 0xC8E80C: è il pezzo che rende prevedibili i 15 feeder. (b) In alternativa decodificare i gate contesto dei due caller della switch (0xce238, 0x15b024, struct 0x681FF0/0x682098) per collegarli agli handler AutoScene/CaptureMenu già studiati (punto guard==4 it.40). Il census transizione/switch e l'audit di questi claim sono CHIUSI: non rieseguirli.

## Iterazione 40 — 1 novembre 2026 — Guardia CaptureMenu: censimento del setter 0xCA2F4 (27 siti classificati; unico produttore statico di guard=7 = restore 0xCA4BE nella transizione 0xCA404), funzione di transizione della modalità 0xCA404 con salvataggio/ripristino del flag 0x36580C, regola EA ld.as a PC 2 mod 4 provata in CPU, 0xC8E80C = TBIB 8+0xC usato a runtime come cella modalità (verificatore Capture_Guard_Setter_Census PASS post-audit; chiusura del lavoro interrotto in TRE round: audit completato con agente guard-audit-42, controesempio scrittori diretti integrato)

**Domanda affrontata.** Punto aperto (a) dell'iterazione 39: chi può portare la guardia `0x365751` a 7 — la condizione che in mode 0x2C mantiene selezionabili le voci 0x0A/0xBB della lista 0x4801 — e come la guardia si coordina con la cella modalità 0xC8E80C. Il lavoro tecnico era già completo in due round interrotti senza output (round_000006: terminato in wait 600 s dell'agente `guard-audit-40` mai tornato, rapporto scritto con sezione audit segnaposto; round_000007: terminato durante le regressioni dopo aver rieseguito il verificatore 112121924544Z e avviato `guard-audit-41`, mai tornato). In questa sessione: riesecuzione indipendente completa, nuovo audit, integrazione e documentazione.

**Risultato.** [Rapporto](S33_GUI_CaptureMenu_Guardia_Setter_Census_CPU_20261101.md) (audit integrato), [script](../Python_Trace_Scripts/s33_verify_capture_guard_setter_census.py), [prove](../Risultati/GUI_S33/capture_guard_setter_census_cpu_20261101T112305687536Z/) (chiusura; le esecuzioni PASS dei round interrotti 110537213758Z, 111303504606Z e 112121924544Z sono conservate, classificazione byte-identica — differiscono solo utc e hash dei .command.json con percorsi auto-referenziali).
- **Setter 0xCA2F4(v)**: solo `stb_s r0,[r1,0]` con base pool 0xCA30C = 0x365751; getter 0xCA310 stessa cella (ld NON scalato, byte fc 17 00 f0). Census bl su listing+ridisassemblato (doppio metodo, `$` come ancora): setter 27 (p0:4/p2:12/p4:11), getter 58 (11/41/6), transizione 0xCA404 = 63 (15/10/38), getter modalità 0xCAD30 = 434 (85/291/58).
- **27 siti classificati byte-esatti**: unico sito statico con guard=7 è il restore **0xCA4BE** dentro 0xCA404; il valore 3 arriva solo dai due siti condizionati a guard==4 (0x653E02/0x654E84); 9 siti calcolati non limitati a un insieme di valori (limite esplicito); 0x659580 identità + copia in 0x681F5C+9 (pool 0x659594); teardown 0xC9DEA (guard=0) + 0xC9DF0 (flag=0).
- **Transizione 0xCA404**: change-detection; uscendo da 0x2C salva (guard==7) come 1/0 in 0x36580C (stb r0,[r1,188] a 0xCA496/0xCA49E, pool 0xCA5D4=0x365750); se nuovo modo != 3 azzera la guardia (0xCA4A8); memorizza il nuovo modo in 0xC8E80C (0xCA4AE, pool 0xCA5D0); se flag==1 e nuovo==0x2C ripristina guard=7 (0xCA4BE). Casi speciali 0x38/0x6C/0x6E/0x5/0x7D/3/0x2C.
- **Flag 0x36580C**: un solo pool (0xCA18C, payload0); lettori/scrittori: restore 0xCA4AA e teardown 0xC9DF0; nessun altro store a +188 nelle finestre dei 24 siti dei 14 pool di 0x365750; nessun limm verso le tre celle.
- **Regola EA ld.as a PC 2 mod 4 provata in CPU**: EA=(PC&~3)+imm*4; caso A marker alla EA scalata 0xCE4 → fault 0xdead0000 (pc 0x1026), controllo negativo B marker solo a 0xF39 → fault 0xdead0004 (pc 0x101a), exit 11, encoding 39 17 00 f6 byte-identico a 0xCA4AA. Il pool reale del restore è 0xCA18C=0x36580C, NON il commento objdump ;0xca3e1.
- **CORREZIONE it.39**: 0xC8E80C HA uno scrittore statico (0xCA4AE, sfuggito al censimento di it.39) ed è **usato a runtime come cella modalità di scatto corrente** dalla transizione 0xCA404 (63 chiamanti bl, save/restore della guardia): ritirare la parte «non modalità runtime» dell'interpretazione it.39; il byte è del record TBIB 8 (magic C1C2C3C4 a +0x4, valore statico 0x2C) e gli altri 7 pool toccano solo +1/+3/+7/array 0xC8EB30+; il significato fisico dei singoli modi resta APERTO.
- **CONTROESEMPIO AUDIT (nuovo)**: la guardia ha due scrittori diretti oltre al setter — switch ingresso **0xCBC00** (tabella 0xCBC1C, r0∈0..4, base pool 0xCBC38=0x365750): `stb_s r1,[r2,1]` a 0xCBC24/0xCBC2A scrive direttamente 0x365751 con **solo 0** (r0∈{0,1,2,4}, target 0xCBC22 via add1 ×2) **o 4** (r0=3, target 0xCBC28); mai 7 → «unico produttore statico di guard=7 = 0xCA4BE» CONFERMATO e rafforzato; reachability di 0xCBC00 indeterminata; il valore 4 collega ai siti const3_if_guard_4 (produttore del contesto guard==4 candidato). L'agente aveva la mappa r0→valore scambiata; corretta in coordinatore con verifica byte (finestra allineata 0xCBC00..0xCBC30, byte tabella [03,03,03,06,03], semantica add1) e censimento indipendente: unici store [rN,1] entro 12 righe dai load dei 14 pool = 0xCBC24/0xCBC2A.

**Comandi/esiti.** Questa sessione (tutte senza pipe): `s33_verify_capture_guard_setter_census.py` → **PASS_CAPTURE_GUARD_SETTER_CENSUS 20261101T112305687536Z** (exit 0; confronto ricorsivo con 110537213758Z: delta solo utc/hash comandi); regressioni **PASS**: flag matrix 14 casi 20261101T112306442802Z, snapshot record init 4 casi 20261101T112307559937Z, service raise pending 20261101T112308Z. Round interrotti (già osservati nei log): census 111303504606Z e 112121924544Z PASS; flag matrix 111324680216Z PASS; snapshot 111330450836Z PASS; raise pending 112141Z PASS; le due regressioni lanciate alla fine del round_000007 non hanno lasciato evidenze su disco e sono state rieseguite qui.

**Agente e MCP.** **Agente `guard-audit-42`** (tools.agents.spawn; «task con agente explore» non esiste in questo ambiente, come documentato): C1–C7 CONFERMATI byte-exact con metodo indipendente (byte TBM + SHA, ridisassemblato proprio, scan LE propri, censimento pool+aritmetica su tutto il listing); C8: il controesempio 0xCBC00 sopra + conferma nessun puntatore-funzione ai quattro target + nessun altro mov7; correzioni di dettaglio accolte e riverificate in coordinatore (magic TBIB a +0x4; liveness r13 a finestra; listing nasconde istruzioni nelle regioni .long; docstring verificatore «16 sites» impreciso, classi reali 14, asserzioni interne corrette — file non modificato per non invalidare gli hash congelati). L'agente ha inoltre registrato in autonomia un esito nel PMB (outbox 371, riferito dall'agente stesso). `guard-audit-40`/`guard-audit-41` (round interrotti) mai tornati: documentati come tentativi incompleti. Server MCP disponibile e consultato: `mcp_pmb_nikon` (prepare iniziale di questa sessione + record_batch finale); server REA non presente tra i connettori di questa sessione. Strumenti: bash/python3 (verificatori, regressioni, confronti JSON), objdump GNU via helper aligned_window, tools.process per i verificatori in background, tools.agents per l'audit. Nessun hardware/USB/SD toccato.

**Fonti precise.** Payload0 (base 0x0AD800): setter 0xCA2F4 (pool 0xCA30C), getter 0xCA310, transizione 0xCA404..0xCA4C8 (pool 0xCA5D0=0xC8E80C, 0xCA5D4=0x365750, 0xCA18C=0x36580C), teardown 0xC9DB6/0xC9DEA/0xC9DF0, switch 0xCBC00..0xCBC36 (pool 0xCBC38=0x365750, tabella 0xCBC1C, store 0xCBC24/0xCBC2A), identità 0x659580 (pool 0x659594=0x681F5C), siti calcolati 0x6648C4/0x664938/0x6649A4/0x7F7F04/0x7F7FDE/0x7F83C4/0x7F8578/0x7F8694/0x7F8764 (pool 0x7F86BC=0x89A330). Payload8 (base 0xC8E800): record TBIB 8, magic +0x4, byte 0xC8E80C=0x2C. Evidenze: Risultati/GUI_S33/capture_guard_setter_census_cpu_20261101T112305687536Z/ (casi ld_as in ld_as_scale4_marker* e ld_as_unscaled_control*).

**Limiti.** Statico + 2 casi CPU sintetici con pool propri (stesso encoding del firmware, non firmware in banco); 9 argomenti calcolati del setter non circoscritti (guard=7 «runtime» via siti calcolati non escluso); reachability di 0xCBC00 indeterminata (nessun chiamante statico trovato, potenziale entrata solo via salto calcolato); finestre di esclusione a raggio limitato (48 byte / 12 righe), basi indirette non esaustivamente escludibili; nessuna esecuzione di 0xCA404 con stato reale (scheduler, WindowManager, eventi); V1.1 campione vs macchina V1.0. Statico+CPU emulata, nessun hardware, NON_INSTALLARE, circa 10% invariato.

**Prossimo passo (non ripetitivo).** (a) **Census dei 63 chiamanti di 0xCA404 e dei valori di modalità passati** (in particolare chi porta a/da 0x2C): è il pezzo che chiude il ciclo «snapshot → coda → dispatcher → AutoScene/manager → CaptureMenu → transizione → guardia/flag → flag bit 1 liste»; le classi dei 27 siti setter (14 const0*, 2 const3_if_guard_4, 1 const7, 1 identità, 9 calcolati) e i 63 chiamanti della transizione vanno collegati ai percorsi GUI già studiati. (b) In parallelo: reachability della switch 0xCBC00 (chi la invoca con r0∈0..4) e il significato del contesto guard==4. (c) Alternativa di lungo corso: walker tabelle classe alta (it. 38). Il punto censimento setter/transizione è CHIUSO, non rieseguire i census già fatti; non ripetere l'audit di questi claim.


## Iterazione 39 — 1 novembre 2026 — CaptureMenu: produttore del flag bit 1 = 0x7CB1B4 con condizioni decodificate (mode 0xC8E80C = record TBIB 8+0xC, guardia 0x365751 con setter 0xCA2F4); matrice CPU 14 casi con getter ORIGINALI (verificatore Capture_Flag_Mode_Matrix PASS post-audit; chiusura del lavoro interrotto della sessione precedente)

**Domanda affrontata.** Chiusura del lavoro della sessione interrotta (2026-11-01 10:41, idle_timeout dopo lo spawn dell'audit `flag-update-audit-2` mai tornato; il verificatore era già PASS ma il risultato non era auditato né documentato): chi produce il bit 1 dei flag word a record+0x18 delle liste CaptureMenu (0x9801C0/0x4800 e 0x980268/0x4801) e sotto quali condizioni — il lato produttore del bit che nella pressione successiva blocca le voci 0x0A/0xBB.

**Risultato.** [Rapporto](S33_GUI_CaptureMenu_Flag_Produttore_Matrice_Modalita_CPU_20261101.md), [script](../Python_Trace_Scripts/s33_verify_capture_flag_mode_matrix_cpu.py), [prove](../Risultati/GUI_S33/capture_flag_mode_matrix_cpu_20261101T104243668736Z/) (riesecuzione indipendente di questa sessione; prima esecuzione della sessione interrotta in `capture_flag_mode_matrix_cpu_20261101T103519423275Z/`, esito identico).
- **0x7CB1B4** (unico chiamante 0x7CB076, nel gestore 0x7CB03C dell'evento 0x4405 della tabella 0x982384 del descrittore 0x9802AC, ctx 0x899858): (a) primo loop azzera bit1 di tutti i record del controllo [[0x899858]+4]=[0x89985C] via 0x631E98(record,0); (b) ID 0x4801: bit1=1 per record con dest +0x14 ∈ {0xBB,0x0A} se mode≠0x2C oppure (mode==0x2C ∧ guard==7); (c) ID 0x4800: bit1=1 per record con categoria +0x10==2 se mode∈{0x14,0x1F,0x6D,0x68,0x05,0x7D}, ==3 se mode∈{0x14,0x05,0x15,0x7E}; (d) 0x631E98 tocca SOLO bit1 di [record+0x18] e solo se diverso. Matrice CPU 14 casi con **getter ORIGINALI** 0xCAD30 (byte a 0xC8E80C, ld.as pool 0xCAAC4) e 0xCA310 (byte a 0x365751, pool 0xCA30C); conteggi traccia confermano confronti short-circuit (cat2 6 modi, cat3 4; guard solo se mode==0x2C); record dell'altro controllo intatti; stack preservato.
- **CROSS-LINK**: 0xC8E80C = record TBIB 8 +0xC («NotRunOneCard», magic C1C2C3C4), lo stesso byte classificato da 0x16E440 (iterazione 27), valore statico V1.1 0x2C → il selettore è il byte di variante/configurazione di boot, non una modalità di scatto runtime. Sul dump: 0x4800 mai settato, 0x4801 solo con guardia 7.
- **[0x89985C] scritta solo da 0x7CB118** (st_s r0,[r14,4] a 0x7CB15A/0x7CB196 = ritorno di 0x145654(arg, 0x4800/0x4801); ramo arg4 prima chiama 0x145764(a,0x4800), 0x145b08(a,0x4800,1), 0x145b08(a,0x4801,0); ramo arg5 0x145764(a,0x4801), 0x145b08(a,0x4801,0), 0x145b08(a,0x4801,1)) — conferma la mappa argomento→risorsa.
- **Censimenti audit**: 0xC8E80C NESSUNO scrittore statico (434 bl al getter; lettori inline 0xCA418/0xCA726/0xD04C0; scritture banco 0xC8E8xx a +1/+3/+7/array 0xC8EB30+, mai +0xC) → produttore runtime (loader TBIB); 0x365751 getter 0xCA310 (58 bl) E setter 0xCA2F4 (27 bl, stb_s) → la guardia HA un produttore software identificabile. Flag iniziali nel dump 8,0,0 / 8,0,0,0 (bit1 mai all'origine; correzione minore all'audit che diceva 0,0,0,0). 0x631E98: 128 bl ma altri menu usano celle proprie.

**Comandi/esiti.** `python3 Python_Trace_Scripts/s33_verify_capture_flag_mode_matrix_cpu.py` → **PASS_CAPTURE_FLAG_MODE_MATRIX 20261101T104243668736Z** (exit 0, 14 casi; identico alla 103519Z della sessione interrotta). Regressioni rieseguite tutte PASS: snapshot_capture_record_init 4, snapshot_capture_followup_key 4, gui_key_queue_capture_original_items 8, gui_autoscene_key_reenter 9, autoscene_capture_entry 4. **Agente `flag-audit-3`** (tools.agents.spawn, revisione statica indipendente con objdump; «task con agente explore» non esiste in questo ambiente, come documentato): punti 1–3 CONFERMATI con byte, punto 4 nessun controesempio statico (unicità assoluta non dimostrabile: data-flow del WindowManager 0x169f60 non tracciato), punto 5 censimento completo; aggiunte riverificate in coordinatore (tabella eventi 0x982384, scrittori [0x89985C], setter 0xCA2F4). Sessione interrotta documentata: audit flag-update-audit-2 mai tornato, script non trattato come verificato prima della riesecuzione.

**Fonti precise.** Aggiornamento 0x7CB1B4..0x7CB2E4 (pool 0x7CB1AC=0x899858, 0x7CB1B0=0x4801, 0x7CB2E4=0xCAD30); selezione 0x7CB03C/0x7CB118..0x7CB19C; getter 0xCAD30..0xCAD36 (pool 0xCAAC4=0xC8E80C), setter 0xCAD38 (pool 0xCAD58=0x365753), stub 0xCAD5C; guardia 0xCA310 (pool 0xCA30C=0x365751), setter 0xCA2F4; helper 0x631E98; record 0x98016C+28k (cat 0,2,3; dest 0x87,0x9D,0x9D) e 0x9801F8+28k (dest 0x87,0x07,0x0A,0xBB); controlli 0x9801C0/0x980268, array 0x9802A0, descrittore 0x9802AC, tabella eventi 0x982384; record TBIB 8 0xC8E800..0xC8E80C.

**Strumenti/MCP.** Server MCP disponibile e consultato: `mcp_pmb_nikon` (prepare iniziale + record_batch di 5 voci, chiamate effettive con esiti verificabili). Agente: `flag-audit-3` via tools.agents.spawn, atteso e integrato. Strumenti usati: bash/python3 (verificatori e regressioni), arc-elf32-objdump GNU (finestre 0x7CB1B4/0x7CB118/0xCAD30/0xCA310), static_common (spot check dei claim audit). «task con agente explore» non esiste in questo ambiente (come documentato nelle iterazioni precedenti). Server MCP REA non presente tra i connettori disponibili in questa sessione; lo skill reverse-engineer-anything non era necessario per questa chiusura. WD-level: nessuno strumento ha toccato hardware, USB, SD o firmware originali.

**Limiti.** Ingresso diretto 0x7CB1B4 (init classe 15), niente catena AutoScene/manager in questo banco; unica fixture 0x1457D4 che legge [0x89985C]+4 mentre l'originale legge 0x366EAC (pool 0x1457D0) — le due celle potrebbero divergere su fotocamera; produttore runtime di 0xC8E80C e significato fisico di modi/guardia APERTI; 0x145764/0x145b08 non decodificati. V1.1 vs V1.0. Statico+CPU emulata, nessun hardware, NON_INSTALLARE, circa 10% invariato.

**Prossimo passo (non ripetitivo).** (a) **Chi produce la guardia 0x365751**: census dei 27 chiamanti del setter 0xCA2F4 (e dei 58 del getter 0xCA310) per identificare chi porta la guardia a 7 — è la condizione che nel modo 0x2C del dump decide se le voci 0x0A/0xBB di 0x4801 restano bloccate; offline e byte-verificabile. (b) In alternativa il walker delle tabelle di classe alta dell'iterazione 38 (0x2643C0/0x423B10, sempre aperto). Il punto produttore-flag è CHIUSO, non rieseguire la matrice.

## Iterazione 38 — 1 novembre 2026 — lato raise dei pending del framework service-request: i tre chiamanti di 0x16D4D8 passano id 0xFFFFxxxx che non possono mai matchare (raise = no-op runtime); trigger del vettore 6 SOLO hardware; router a classi alte e tabelle di servizio 0x424E00/0x424F00/0x425000 fuori dall'array (verificatore Service_Raise_Pending PASS post-audit)

**Domanda affrontata.** Prossimo passo (a) dell'iterazione 36 (voce sotto, 22 ottobre): chi alza a runtime i bit pending — i tre chiamanti di 0x16D4D8 per gli id passati e il sito LE 0x1A14A8 = 0xFED3818 — per attribuire l'evento che pilota il vettore 6 (pending 0xFEF0074, id 0x610) e la richiesta iris 0x3002 (pending 0xFED3818 bit 2).

**Risultato.** [Rapporto](S33_Service_Raise_Pending_Vettore6_e_Iris.md), [script](../Python_Trace_Scripts/s33_verify_service_raise_pending.py), [prove](../Risultati/Runtime_Kernel/Service_Raise_Pending/latest.json) (evidenza **20261101T102211Z**; riesecuzione indipendente dell'audit **20261101T102314Z** identica).
- **0x16D4D8 raise generico**: loop sulle sei tabelle generiche (array 0x3F6CC8), `cmp_s r0,r3` a **32 bit completi** (nessuna maschera su r0; CMP_S b,h = b−h per manuale ARCompact) contro id halfword (record table+12+8k, `add3_s` scala 8); trovato → sezione critica 0x1786E8 + `sth.di 1<<bitB` su [[table+0]]; non trovato → pool 0x16D6D0 = 0x200601. I **tre chiamanti** (census {0x16F0F6, 0x2331B4, 0x238B56}) passano costanti **0xFFFF9007 / 0xFFFF8008 / 0xFFFF800B** (pool 0x16F11C / 0x2331AC / 0x238B68 nei delay slot; `ld` semplice NON scalato, bytes f4 17 00 f0 a 0x2331B8, prova assembler f0/f6) che **non possono mai eguagliare** record id (84 record in 0x401..0xA10): le tre raise falliscono sempre (0x200601 ignorato) = **no-op runtime**. Gli stessi valori SONO id validi per i router (classe id&0xFF00 → 0x9000/0x8000): il trigger reale passa dai servizi di classe; le raise sembrano residui di refactoring (intent non provabile staticamente).
- **Trigger del vettore 6 = SOLO HARDWARE**: scansione LE di 0xFEF0074 in payload0 → esattamente {0x263F30 (W1C clear-all 0x263F08 dell'init, scrive 0xFFFF), 0x2640B8 (getter bit 9), 0x2640D4 (W1C bit 9, sth.di 0x200)}; **zero limm middle-endian** verso 0xFEF0074 (audit, convenzione limm verificata sul byte di `and r1,r0,0xff00`). Nessun software alza i bit di 0xFEF0074 (incluso bit 15 = id 0x610 → walker 0x264250 → dispatcher 0x242488 → 0x241E5C → 0x140704): il framework è interamente interrupt-driven (software arma enable al ready, hardware alza pending, i walker consumano con W1C).
- **Router 0x16D5BC mappa completa**: `and r1,r0,0xff00`; basse 0x0400..0x0A00 → sei tabelle; **alte 0x1000/0x2000/0x5000/0x6000/0x7000/0x8000/0x9000/0xA000/0xB000 → servizi diretti** con extw_s r0 (id&0xFFFF) nei delay slot (0x1000→0x26671c/0x2667b0, 0x2000→0x265fe8/0x26605c, 0x5000→0x2668d8/0x266940, 0x6000→0x266170/0x2661d8, 0x7000→0x24d388/0x24d3f0, 0x8000→0x266380/0x2663ec, 0x9000→0x266af0/0x266b5c, 0xA000→0x266d0c/0x266d74, 0xB000→0x26658c/0x2665f4); classe ignota → 0x200601 (pool 0x16DB20); 0x3000/0x4000 → 0x2422e8/0x242380.
- **Tabelle di classe alta FUORI dall'array** (parse payload1): **0x424E00** (pending 0xFEF0228, enable 0xFEF022C, 16 record id 0x6001..0x6010 bit 15..0) del raiser 0x2660E8 (pool 0x266120) del servizio classe 0x6000 0x266170 (alla prima chiamata registra il watchdog 0x16D898(0x90D, 0x26627C) + enable 0xFF, gate 0x36B330); **0x424F00** (0xFEF0048/0xFEF0324, id 0x8001..0x8010) del raiser 0x266300 (pool 0x266330) e del register di classe alta **0x266444(id,fn)** (`st.di fn,[record+16]`, pool 0x2664A0); **0x425000** (0xFEF044C/0xFEF0448, 13 record id 0xB001..0xB00D) classe 0xB000. L'init lens **0x23912A** registra 0x3001 (helper 0x23914C: b.d 0x242414, fn pool 0x239154 = 0x23915C, id pool 0x239158) E **0x266444(0x800B, 0x238C88)** + evento SET 0x200000C bit 0; l'handler 0x800B 0x238C88 chiama 0x238B34 (terzo chiamante della raise fallimentare).
- **Sito 0x1A14A8 (unico LE verso 0xFED3818)**: dentro l'handler **0x1A1490** registrato sotto **id 0x3004** da 0x1A082C (gate 0x368500, register 0x242414(0x3004, 0x1A1490) + ready 0x2422e8(0x3004); census 0x1A082C = {0x1A0AA2, 0x1A1474}). Corpo: `sth.di 1 → 0xFED3818` = W1C acknowledge del **bit 0 = id 0x3004, il proprio** (mappa bit 0x424500: 0x3004→0, 0x3002→2, 0x3001→3, 0x3003→1, 0x3005→4, 0x3006→5, 0x3007→6; correzione audit alla prima stesura che diceva 0x3001), poi poll **0xFED18C8/0xFED18CC** (banco strobe 0xFED1xxx: and, bmsk 4 bit, se ≠0 `jl_s [[0x368510]]`), poi coppie 0xFED1910/14/18 (maschera 0x1DF). **Registrazioni famiglia iris complete**: 0x3001→0x23915C (lens; ready 0x23917C {0x238D02,0x238D10}, unregister 0x239194 {0x238662,0x238BE6,0x238D32,0x238D4A,0x238D92}), 0x3002→0x241E5C (iter. 34), 0x3004→0x1A1490. Il pending iris 0xFED3818 resta scritto dal software SOLO via request setter 0x242224 al ready (kick iniziale che processa lo stato corrente) e W1C (dispatcher + handler 0x3004); le ripetizioni successive nascono dall'hardware 0xFED3xxx.

**Comandi/esiti.** `python3 Python_Trace_Scripts/s33_verify_service_raise_pending.py` → **PASS_SERVICE_RAISE_PENDING_STATIC 20261101T102211Z** (exit 0; 26 finestre GNU allineate, 27 pool LE raw, parse 4 tabelle payload1 + array 0x3F6CC8, 11 scan LE congelate, census bl 8 target, modello funzionale raise: 3 id fallimentari + controllo 0x610→bit 15 di 0xFEF0074). Prove ISA in sessione: pdftotext manuale ARCompact (CMP_S 32-bit); arc-elf32-as + objdump su `ld`/`ld.as [pcl,-12]` (f0 non scalato vs f6 scalato). **Agente `raise-audit-38b`** (tools.agents.spawn; «task con agente explore» non esiste in questo ambiente, come documentato; il primo `raise-audit-38` era stato terminato dal limite turni senza esito): riesecuzione **PASS 20261101T102314Z** identica (26/27/11/8; la cartella della riesecuzione è stata creata dallo script stesso, `latest.json` aggiornato da esso); **C1–C4 CONFERMATI byte-exact**; correzioni accolte: bit 0 di 0xFED3818 = id 0x3004 (non 0x3001), aggiunta scansione limm 0xFEF0074 (zero occorrenze), "84 record". Nessuna asserzione indebolita.

**Fonti precise.** Payload0 base 0x0AD800: raise 0x16D4D8..0x16D5B6 (pool 0x16D580=0x3F6CC8, errore 0x16D6D0=0x200601), caller 0x16F0EC..0x16F118, 0x2331A0..0x2331C8, 0x238B34..0x238B6C; router 0x16D5BC..0x16D7E8 (pool 0x16D6D4..0x16D6E8, 0x16DB20); servizi classe 0x266170..0x2661D8, 0x2660E8..0x266150, 0x266300..0x266354, 0x2663EC..0x26643E, 0x266444..0x266482; W1C 0x263F08..0x263F44, bit9 getter/clear 0x2640B0..0x2640E0; handler 0x1A1490..0x1A14F0, init 0x1A082C..0x1A0864; lens 0x23912A..0x239178, 0x238C88..0x238CC8. Payload1 base 0x360800: array 0x3F6CC8; tabelle 0x424B18, 0x424E00, 0x424F00, 0x425000.

**Limiti.** Statico, nessun hardware/runtime, NON_INSTALLARE, circa10% invariato. Identità fisica 0xFED3xxx/0xFEF0xxx APERTA (inferenza controllori interrupt); W1C = inferenza forte dal pattern. **Walker delle tabelle di classe alta non decodificati** (0x2643C0 legge [0x423B10] via LIMM = callback singolo, vettore 7 a doppio installatore TIMER1; 0x2643E0 cammina 0x424BA4 = vettore 8; 0x264498 non guardato). Corpi dei restanti servizi di classe alta e tabella classe 0x9000 non decodificati. V1.1 campione vs macchina V1.0.

**Prossimo passo (non ripetitivo).** (a) **Chi serva le tabelle di classe alta**: decodificare i walker candidati 0x2643C0 (LIMM 0x423B10) / 0x2643E0 / 0x264498 e la struttura 0x423B10, per chiudere la mappa vettore→tabella del framework e il doppio installatore del vettore 7 (aperto da iterazioni 36/29). (b) In alternativa il gemello TIMER0/scheduler tick (punto (b) dell'iterazione 29, sempre aperto). Entrambi offline e byte-verificabili; il punto raise/pending è CHIUSO, non rieseguire i census già fatti.

**23 ottobre2026 — R0/R1/R4, registro/open/close SD integrati e modi FAT.** [Lifecycle e proprietà](S33_Dumper_RAM_SD_Registro_Apertura_Close_e_Ownership_Integrati.md):17casi CPU ritornati,31finestre GNU/29istruzioni. 2A3C5C/1F21F8/12DBFC/12CE8C/12D604/1F22C0 originali sui13scenari file e4errori di proprietà. Preclose3015 nullo→FFFFFFFF conserva handle/slot/oggetto;retry libera una volta. Ready0→1A0000C consuma wrapper/slot/cella ma conserva oggetto privato,count1:noncleanup normale. 4immagini positive fsck0,7negative FF7 respinte;regressione13PASS. [Modi](S33_Dumper_RAM_SD_Modi_Apertura_FAT_e_Gate_Backend7.md):20casi/20immagini fsck0;w/w+troncano,n/n+collidono,x/x+generanoTMP e saltano collisione. Backend7 provato solo con gate369400=0,n/w condividono create+lookup e rifiutano1A00003;volume attivo resta aperto. Prossimo adapter con stati di proprietà/backend verificati e contesto backend7 attivo. Tappe offline FS88%,write75%,eventi63%,adapter20%,hardware0%;non sicurezza firmware. Obiettivo42b56cc8attivo,NON_INSTALLARE,GNU/C/originali invariati.

**Checkpoint23ottobre2026 — fileFAT n/write/close/riapertura.** [Rapporto](S33_Dumper_RAM_SD_File_FAT_Creazione_Scrittura_Close_e_Riapertura.md),prova20261023T185804Z:13casi,4positivifsck0,3collisionisenzascrittura e1negativoframmentatoFF7atteso;81timeout/8100tick,regressione24PASS. ModelloDMAesplicito,nessunhardware. Superatoilconfine1F4958/21A4B8/creazioneFAT;prossimo1F21F8/12DBFC/12D604registro/slot/ownership,poi backend7/modi eadapter. Nonridurresuccessoar0=0;verificarecount,fileerror,close ecatenaFAT. Obiettivo42b56cc8attivo,NON_INSTALLARE.

**Checkpoint23ottobre2026 — write/PMSD→motori→rilettura.** [24casi e rapporto](S33_Dumper_RAM_SD_Motori_Write_PMSD_e_Rilettura.md),prova20261023T182409Z;13riletture/11264byte,15catture12800byte,regressione36PASS. Scheda=finestraRAM senzaFAT,DMAassente;nohardware. Primo componente mancante1F4958→21A4B8 ecluster2A0D70/2A0C14,poi creazione2ABCD4oltreguardia,allocazioneFAT/sync/close/riapertura eadapter. Mantenere intero obiettivoE2E dell’allegato42b56cc8,senza promuovere conteggio0 o rilettura di settori a persistenza file. NON_INSTALLARE.

**Dumper SD: catena asincrona ed eventi originali — 23 ottobre 2026, R0/R1/R4.** [Rapporto](S33_Dumper_RAM_SD_Catena_Asincrona_Eventi_RTOS_Originali.md), [13 scenari](../Risultati/Runtime_Kernel/RAM_Dumper_SD_Read_Async_Events/20261023T134341Z/verified_evidence.json):10ritorni+3wait accodati interrotti prima2313AC.25A83C/acquire/start/dispatcher/callback/SET/WAIT/query/CLEAR/release originali nella stessa esecuzione. Tabellaeventi statica base372A48,85record;SDrow36=373228/E00005. Stalebits rimossi,bit1estraneo preservato;modoauto-clear1consuma completion primaquery ma waitriesce. NessunIRQ/masked/nostatus→task1069 e1waiter con endByte1,nessun ritorno. Clockprofile0/1000/1000→deadline100/0/0,prodottiDSPmodellati. Prossimo2313AC/deadline/wakeup/timeout perraggiungere266E9C nella catena,piùAPIstatuscallback reali. Nessunhardware/BIN,NON_INSTALLARE,circa10% invariato.

**Dumper SD: avvio, callback e contatore originali — 23 ottobre 2026, R0/R1/R4.** [Rapporto](S33_Dumper_RAM_SD_Avvio_Receive_Callback_e_Contatore_Originali.md), [33 casi](../Risultati/Runtime_Kernel/RAM_Dumper_SD_Read_Start/20261023T132917Z/verified_evidence.json):13start/dispatch+20progress,tutti ritornati.28080C/programmatori/2822C4/setter/267F20→jl2689F6→25ADBC/25ADC4 eseguiti;eventoE00005/40o40000registrato alconfine158CBC. Slot36B358/35C/360,bytefine calcolato prima della notifica da residuo+8−step+C,non dati pronti.266E9C mappa6oggetti→halfwordMMIO<<7,senzaownershipcheck. Mask/no-status/nullcallback distinti; codaaltreIRQmascherataFE1000C=7,pendingFE10008noncampionato. Buffer resta31. Prossimo integrare25A83C/oggetti/start/progress/callback/release eAPIeventi originali;nessunhardware/BIN,NON_INSTALLARE,circa10% invariato.

**Dumper SD: oggetti di ricezione originali — 23 ottobre 2026, R0/R1/R4.** [Rapporto](S33_Dumper_RAM_SD_Oggetti_Ricezione_Acquisizione_e_Rilascio.md), [18 casi oggetti](../Risultati/Runtime_Kernel/RAM_Dumper_SD_Read_Object/20261023T131159Z/verified_evidence.json), [21 chiamante+oggetto](../Risultati/Runtime_Kernel/RAM_Dumper_SD_Read_Async_Object/20261023T131447Z/verified_evidence.json), regressione21PASS.2801F0/27FCD4 selezionano512CC8/512CEC/512D10,passo24hex;pubblicanoF4240,id,total,step.281158/281064 azzerano id+4 ehandle anche con errorepost;precedente releasefixture che conservavahandle non era contratto reale. Confermati earlyregister/enable/clear con id202/203 non ripulito nel chiamante,non motore fisico attivo.30stagnanti e41attese riprodotti;start/progress/eventi/semafori/hookstop fixture,buffer resta31. Prossimo28080C/266E9C,callback eultimo uso buffer,poi eventi e arbitraggio reali. Nessunhardware/BIN,NON_INSTALLARE,circa10% invariato.

**Dumper SD: chiamante asincrono — 23 ottobre 2026, R0/R1/R4.** [Rapporto](S33_Dumper_RAM_SD_Lettore_Asincrono_Attese_e_Uscite_Parziali.md), [21 scenari](../Risultati/Runtime_Kernel/RAM_Dumper_SD_Read_Async/20261023T130343Z/verified_evidence.json):20ritorni+1attesa interrotta.25A83C/25A444/25A464 ealias2812B8 originali; servizi/eventi inferiori fixture, buffer1024 resta31.30controlli consecutivi senza progresso→E01520, cambiamento dopo10 permette41attese; progresso continuo osservato fino63query. Errori register/enable/clear dopo acquire saltano release e ripristino nel chiamante, non diagnosi di leak globale. Finish errore→unregister due volte; errore unregister non propagato. Prossimo2801F0/27FCD4 e28080C/281158 reali nel modello, ownership/callback/eventi;nessunhardware/BIN, NON_INSTALLARE,circa10% invariato.

**Dumper SD: comandi e controllo originali — 23 ottobre 2026, R0/R1/R4.** [Rapporto](S33_Dumper_RAM_SD_Comandi_Risposte_e_Controllo_Originali.md), [40 casi isolati](../Risultati/Runtime_Kernel/RAM_Dumper_SD_Command/20261023T094241Z/verified_evidence.json), [16 scenari integrati](../Risultati/Runtime_Kernel/RAM_Dumper_SD_Read_Command_Chain/20261023T095145Z/verified_evidence.json). Eseguiti 2E52F4,25A278,25A5F8,25A3E0,2E5234/2E51EC e25AA8C/25A158 nella catena r/FAT/PMSD/SD/PIO/close. Tipo0 scarta errore/timeout dopo8000poll; reset iniziale count alto fisso0FF01854 anche con selettore800. Limiti gate2000 eseguiti. Tre nuovi errori comando/risposta: dati E00100/E00200 propagati dopo3tentativi con buffer invariato; FAT E00100 diventa lookup02.15ritorni/4buffer liberati+1ciclo interrotto; regressioni4×13 PASS. CampioniMMIO e servizi residui simulati, nessuna prova fisica. Prossimo25A83C/2801F0 asincrono e produttoreflag49; nessun nuovo BIN, NON_INSTALLARE,circa10% invariato.

**Dumper SD: motori read e copia CPU originali — 23 ottobre 2026, R0/R1/R4.** [Rapporto](S33_Dumper_RAM_SD_Lettura_PIO_Motori_e_Completamento_Originali.md), [20PIO](../Risultati/Runtime_Kernel/RAM_Dumper_SD_Read_PIO/20261023T091814Z/verified_evidence.json), [28motori](../Risultati/Runtime_Kernel/RAM_Dumper_SD_Read_Engine/20261023T093432Z/verified_evidence.json), [13catena r/FAT/PIO/close](../Risultati/Runtime_Kernel/RAM_Dumper_SD_Read_PIO_Chain/20261023T092810Z/verified_evidence.json). B15B4/B16D0,preparazione2E514C/100poll,descrittori2E509C,25AA54,25A74C/25A690 e25A658 eseguiti; loadMMIO e storebuffer originali alimentati da campioni. Due saltiFAT=2048halfword; errorePIOFAT E01510 ancora→02. Buffer completo può precedere completamento; single senza secondo pollbit8,multi stopE00200 accettato fuori confine. Range rifiutato emette0D. Dispatchercomandi/controllo/cache/servizio e DSP restano fixture. Prossimo2E52F4/25AA8C,asincrono e produttore49. Nessunhardware/BIN,NON_INSTALLARE,circa10% invariato.

**Dumper SD: PMSD/DEVSD e conteggi — 23 ottobre 2026, R0/R1/R4.** [Rapporto](S33_Dumper_RAM_SD_Catena_PMSD_DEVSD_e_Contratto_Conteggi.md), [22 casi trasferimento](../Risultati/Runtime_Kernel/RAM_Dumper_SD_Partition/20261023T090629Z/verified_evidence.json), [13 r/FAT/PMSD/SD/close](../Risultati/Runtime_Kernel/RAM_Dumper_SD_Read_SD_Chain/20261023T090629Z/verified_evidence.json), [13 intermedi](../Risultati/Runtime_Kernel/RAM_Dumper_SD_Read_Chain/20261023T090710Z/verified_evidence.json). Originali2015/16 e due semafori, offsetPM2048 e3tentativi su errore. DEVSD countintero/0 e PMSD copiaerrore; flag49==1 salta read/write ma riporta countintero/stato0 e lascia bufferread invariato. Produttoreflag aperto. FAT0 corrotta ancora accettata dar come file root; erroreFAT ancora02.12ritorni/4bufferliberati+1ciclo interrotto. MotoriSD/DSP fixture. ProssimoB15B4/B16D0 e produttore49; nessunhardware/BIN, NON_INSTALLARE, circa10% invariato.

**Dumper SD: FAT e identità directory — 23 ottobre 2026, R0/R1/R4.** [Rapporto](S33_Dumper_RAM_SD_Catena_FAT_Multisettore_e_Identita_File.md), [34 casi avanzamento/FAT](../Risultati/Runtime_Kernel/RAM_Dumper_SD_Cluster/20261023T083807Z/verified_evidence.json), [13 catena multisettore](../Risultati/Runtime_Kernel/RAM_Dumper_SD_Chain/20261023T084542Z/verified_evidence.json), [7 r/driver/close](../Risultati/Runtime_Kernel/RAM_Dumper_SD_Read_Device/20261023T084542Z/verified_evidence.json).2ABC68 e1F25D8/1F250C originali: voce12bit a cavallo512, due salti FAT, cache e rami errore. ErroreFAT01A00021 può diventare01A00002; FAT0 corrotta può ritornare file omonimo root con successo; ciclo2→3→2 osservato fino a12callback, stop esplicito. Root piena senza marcatore termina01A0000D. r/driver/close ora integrati su albero monosettore (un settore per directory): tre buffer liberati sotto semaforo, celle puntatore restano vecchie. ProdottoDSP simulato, driver/pool fixture. Prossimo unire FAT multisettore+r/close e contratto PM/DEVSD; nessunhardware/BIN, NON_INSTALLARE, circa10% invariato.

**Dumper SD: lettore/cache e trasferimento originali — 23 ottobre 2026, R0/R1/R4.** [Rapporto](S33_Dumper_RAM_SD_Settori_Cache_e_Trasferimento_Originale.md), [28 casi lettore/flush](../Risultati/Runtime_Kernel/RAM_Dumper_SD_Sector_Reader/20261023T082425Z/verified_evidence.json), [25 trasferimento](../Risultati/Runtime_Kernel/RAM_Dumper_SD_Transfer/20261023T082950Z/verified_evidence.json), [20 lookup fino alla callback dispositivo](../Risultati/Runtime_Kernel/RAM_Dumper_SD_Lookup_Device/20261023T082950Z/verified_evidence.json). Integrata catena2A3360→walker→scanner→2A1178→2A0C60→226204/1F3524, driver sintetico. Confermati copie mirror anche su errore write, flush su indirizzo rifiutato con errore sovrascritto01A0000D, residuo positivo con errorehandle0→stato0. OOM257/falso record0 ancora riproducibile. MULUDW3342A8 resta prodotto simulato, non prova DSP. Regressioni20lookup+7r/close PASS; profilo intermedio20. Prossimo2ABC68/FAT e raccordo r/driver/close; nessun hardware o modifica BIN, NON_INSTALLARE, circa10% invariato.

**Dumper SD: catena integrata e falso successo — 23 ottobre 2026, R0/R1/R4.** [Rapporto](S33_Dumper_RAM_SD_Lookup_Integrato_e_Falso_Successo_Parser.md), [20 lookup integrati](../Risultati/Runtime_Kernel/RAM_Dumper_SD_Lookup_Tree/20261023T081346Z/verified_evidence.json), [7 sequenze r/close](../Risultati/Runtime_Kernel/RAM_Dumper_SD_Read_Tree/20261023T081333Z/verified_evidence.json). Coordinatore→walker→scanner sullo stesso albero di settori. Correzione prioritaria: OOM257 parser con scratch0 può restituire record vuoto/stato0, accettato dar e inserito in lista; non solo01A00002 come col finder fixture. Confermato anche con errore alloc nonzero registrato da231158 nel task. No create/no settori modificati nel modello. Cache/settori/pool restano fixture; prossimo identità record e2A1178/cache/cluster. Nessunhardware/BIN, NON_INSTALLARE, circa10% invariato.

**Dumper SD: directory e scanner originali — 23 ottobre 2026, R0/R1/R4.** [Rapporto](S33_Dumper_RAM_SD_Directory_e_Scanner_Record_Originali.md). [20casi coordinatore+walker](../Risultati/Runtime_Kernel/RAM_Dumper_SD_Directory/20261023T000027Z/verified_evidence.json), [8scanner separati](../Risultati/Runtime_Kernel/RAM_Dumper_SD_Record_Finder/20261023T075642Z/verified_evidence.json), regressione18passata. Walker2A318C decodifica cluster e comprime record nullo/errore/allocazione fallita in1→01A00003. Scanner2A2D88 trova nomi brevi su settore sintetico e al marcatore0 può lasciare stato invariato: inizializzarlo. Due gruppi non ancora integrati; cache/cluster/SD restano fixture. Prossimo albero sintetico con catena completa e raccordor; nessun hardware/BIN, NON_INSTALLARE, circa10% invariato.

**Dumper SD: lookup e parser originali — 23 ottobre 2026, R0/R1/R4.** [Rapporto](S33_Dumper_RAM_SD_Lookup_Parser_Errori_e_Buffer.md), [18 casi CPU](../Risultati/Runtime_Kernel/RAM_Dumper_SD_Lookup/20261022T235541Z/verified_evidence.json).2A3360/29FFB0/29FF74 e259A58 eseguiti; walker directory/finder record restano fixture. Nomi e base assoluta/relativa, guardie e cleanup verificati. Errore allocazione257 del parser non controllato: con scratch0 diventa01A00002 dopo finder su nome vuoto; prime/terze allocazioni fallite restano01A00006. Scratch0/A5 cambia callsite del finder alla radice, non risultato nel dataset. Prossimo2A318C/2A2D88 e integrazione r; nessun hardware/BIN, NON_INSTALLARE, circa10% invariato.

**Dumper SD: riferimento r esistente — 23 ottobre 2026, R0/R1/R4.** [Rapporto](S33_Dumper_RAM_SD_Handle_Lettura_e_Protezione_Volume.md), [12 casi originali](../Risultati/Runtime_Kernel/RAM_Dumper_SD_Read_Pin/20261022T234815Z/verified_evidence.json). Parserr→21A0D0→lookup2A3360 conr5=0, senza create; oggetto modo0 nella lista che blocca volume close/225A60. r+modo2 e attributi/errori/poolnull/notready verificati; flagcontext+720 ripristinato. Caso con nomi distinti: r conservato durante n open/close, lista1→2→1→0. Lookup/pool/cache fixture; no concorrenza/backend7/12. Cinque chiamate helper backend GNU-verificate, negativo LE/LIMM limitato. Prossimo:2A3360 e altri scrittori/backend/sincronizzazione. Nessun hardware/BIN, NON_INSTALLARE, circa10% invariato.

**Dumper SD: oggetti file e guardia volume — 23 ottobre 2026, R0/R1/R4.** [Rapporto](S33_Dumper_RAM_SD_Lista_File_e_Guardia_Chiusura_Volume.md), [sei sequenze CPU](../Risultati/Runtime_Kernel/RAM_Dumper_SD_File_Lifetime/20261022T234314Z/verified_evidence.json). Nel backend1 context+108 è count della lista a+100: open callback n→2AC528 inserisce, close callback→21AD30→2AC564 rimuove. Volume close rifiuta01A00010 con uno/due oggetti, consente dopo ultimo rilascio; due ordini verificati.225A60 rifiuta anch'esso con oggetti vivi prima delle modifiche. Pool/create/cache/clock fixture, non tutti i percorsi o backend. Prossimo r/open-existing come handle di appoggio e altri mutatori; nessun hardware/BIN, NON_INSTALLARE, circa10% invariato.

**Dumper SD: mount e close del volume — 23 ottobre 2026, R0/R1/R4.** [Rapporto](S33_Dumper_RAM_SD_Mount_Chiusura_e_Stabilita_Backend.md), [16 nuovi casi](../Risultati/Runtime_Kernel/RAM_Dumper_SD_Mount/20261022T233548Z/verified_evidence.json). Mount1F3EF0 prende context+388 per selezione backend, ma pubblica+424 prima della wait; errore queryA0A1 salta il post nel modello. Callback close1F48A4→1F46C4: backend7 azzera+424 dopo il post, backend1 riacquisisce e usa gate originale halfword+108 (0→pulizia,1→01A00010). Ready/backend conservati nei casi provati. Open generico rilascia kernel+334 prima della callback (statico). Non prova race/deadlock fisici: I/O/heap/parsing ordinario fixture. Prossimo: scrittori+108, lifetime handle e chiamanti close. Nessun hardware/BIN, NON_INSTALLARE, circa10% invariato.

**Dumper SD: semaforo e inizializzazione — 23 ottobre 2026, R0/R1/R4.** [Rapporto](S33_Dumper_RAM_SD_Semaforo_Campo_Temporaneo_e_Inizializzazione.md), [22 casi CPU](../Risultati/Runtime_Kernel/RAM_Dumper_SD_Mutex/20261022T232905Z/verified_evidence.json). Contesto852 byte azzerato da allocatore originale; campo760/backend+0x70 iniziali0 e semaforo+388 iniziale1. n/d usano lo stesso semaforo; d ripristina campo760 prima del post, n conserva il valore. Seconda wait dello stesso task si accoda: evitare prelock seguito da open che riacquisisce. Quattro costruttori con primitive critiche originali: nullo secondario non propagato; errore registrazione con servizi simulati lascia nesting1, non diagnosi globale. Prossimo: mount/unmount e stabilità backend. Nessun hardware/BIN, NON_INSTALLARE, circa10% invariato.

## Continuazione offline — 23 ottobre 2026: handle SD e correzione identità NAND

Due avanzamenti verificati senza fotocamera:

- [Handle SD, errori e close](S33_Dumper_RAM_SD_Handle_Errori_e_Chiusura.md):25casi originali P-code, di cui16wrapper,3closegenerico,6selezionebackend. Open può fallire dopo pubblicazione handle; close può conservare o consumare secondo il confine raggiunto. Il backend7 ha produttore nel montaggio (record+4==7 e record+12>=04000000), quindi B: non prova esclusività di mode3. EsitoPASS, servizi esterni fixture; niente FAT/SD fisica.
- [Correzione cluster25F338](S33_Correzione_Identita_Cluster_25F338_NAND.md):10finestre GNU,9callsite,3nuove pagine dump confrontate. DEVNAND e updater raggiungono il cluster storicamente chiamato «MCU obiettivo». Attribuzioneottica ritirata; byte e manifest storici conservati,9rapporti annotati e disposition separata. IrideGPIO e dispatcherMCUCTRL restano prove distinte.

Prossimo: stabilità dei campi backend/new-only sotto sincronizzazione e mappa RAM completa. Non usare il clusterNAND come protocollo lente. Goal attivo, NON_INSTALLARE, circa10% invariato.


## Dumper di tutta la RAM su SD richiesto dall'utente — 22 ottobre 2026

[Rapporto](S33_Dumper_RAM_Completa_SD_Prototipo.md), [C/adapter](../AkeruOS/ram_dump.h), [prove](../Risultati/Runtime_Kernel/RAM_Dumper/20261022T082454Z_3a51a23c/verified_evidence.json). `make -C AkeruOS ram-dump-verify`: 28 casi host, streaming di 128 MiB sintetici con 4 KiB di buffer, 20 file invalidi respinti; oggetto ARC compilato. La selezione iniziale di sole strutture iris/timer è stata corretta dopo il messaggio utente: obiettivo RAM completa, una prima cattura, mappa fisica obbligatoria senza assumere 128/256 MiB contigui. Trigger futuro `B:AKERUDMP.ON`; nessun adapter o hook Nikon già installato. Prossimo: mappa completa, binding file esclusivo/attesa RTOS e task con memoria propria. Nessuna operazione hardware o incremento percentuale funzionale; NON_INSTALLARE.

## Aggiornamento emulatore richiesto dall'utente — 22 ottobre 2026

[Rapporto](S33_Emulatore_Runtime_GPIO_Timer_Service_Request.md), [runner](../Python_Trace_Scripts/s33_run_runtime_devices.py), [evidenze](../Risultati/Runtime_Kernel/Emulator_Devices/20261022T074943Z_ca5b13e3/verified_evidence.json). `make -C AkeruOS runtime-devices-verify`: **39 casi PASS_CONDITIONAL_RUNTIME_MODEL** in P-code con istruzioni Nikon originali. Profilo MMIO opzionale e riutilizzabile, dispatch service-request su due livelli, Big/Small e completion, tick TIMER1 one-shot/periodico, store Main FE400xx e guardie MMIO. Nessuna modifica GNU o firmware; lock/delay e sorgenti/callback sintetiche dichiarate nel rapporto. Nessun nuovo boot completo o incremento della percentuale funzionale. Prossimo: risolvere setter/acknowledgement FED3818 e sostituire callback nulla col consumatore completo con provider espliciti. Non riprendere dallo store TBIB FE40004: esistono già prove GNU storiche che lo superano; il suggerimento dell'iterazione 19 era superato.

## Iterazione 36 — 22 ottobre 2026 — framework service-request: dispatcher dell'id 0x3002 = catena interrupt vettore 6 → walker 0x264250 (tabella 0x424B18, callback id 0x610) → dispatcher nidificato 0x242488 (tabella 0x424500, id 0x3002 = 0x241E5C) → 0x140704 (verificatore Service_Request_Framework PASS)

**Domanda affrontata.** Prossimo passo (a) dell'iterazione 34: il dispatcher dell'id 0x3002 — chi invoca a runtime 0x241E5C, il consumatore di [0x392AC0+0x1C] (=0x140704, committente dei bit iris id-1/2/4). NB documentale: l'iterazione 35 non ha lasciato voci (come 33/32/30/28).

**Risultato.** [Rapporto](S33_Framework_Service_Request_Vettori_e_Dispatcher_0x3002.md), [script](../Python_Trace_Scripts/s33_verify_service_request_framework.py), [prove](../Risultati/Runtime_Kernel/Service_Request_Framework/latest.json) (evidenza **20261022T030248Z**; 030233Z conferma identica; 025910Z–030204Z = calibrazioni fallite della prima stesura, conservate).
- **Framework service-request a due livelli, guidato da interrupt.** Tabelle di registrazione STATICHE in payload1 con record 8 byte `{id hh, bitB b, bitA b, fn dw}` (regola `add3` = terzo operando ×8, già byte-provata nell'interpolazione) e header `{+0 ptr pending, +4 ptr enable, +8 count}`: **0x424500** famiglia iris (pending **0xFED3818**, enable **0xFED3814**, 7 record ids 0x3007..0x3004 bit 6..0, fn=0; classe B {+140 0xFED3834, +144 0xFED3830, +148 count 8}, record da +152 ids 0x4001..0x4008), **0x424B18** classe 0x6xx (0xFEF0074/0xFEF0028, 16 record ids 0x0610..0x0601 bit 15..0), più 0x424A00/0x424A8C/0x424BA4/0x424C30/0x424CBC (array 0x3F6CC8).
- **Servizi (tutti byte-exact)**: 0x242414(id,fn)=register; **0x242224(id,flag)=request setter** (pending 0xFED3818 + enable 0xFED3814); **0x2422e8(id)=ready** (bit in 0x36A6CC word +0/+2; alla prima registrazione installa il dispatcher nidificato 0x242488 come callback id 0x610 via 0x16D898(0x610,0x242488) e lo abilita con 0x16D7E8(0x610,0xFF)); 0x242380=unregister; API generiche 0x16D898/0x16D7E8/0x16D840/0x16D5BC (router per classe id&0xFF00: 0x3000 e 0x4000 → 0x2422e8/0x242380) / 0x16D4D8(id)=raise generico.
- **La catena runtime di 0x241E5C**: interrupt **vettore 6** → walker **0x264250** (pervcorre 0x424B18; record 0x610 = {0x242488, bit 15/15}; jl [fn] se enable 0xFEF0028 bit15 E pending 0xFEF0074 bit15, poi W1C-clear del pending) → dispatcher nidificato **0x242488** (pervcorre 0x424500; record 0x3002 = {0x241E5C, bit 2/2}; enable 0xFED3814 bit2, pending 0xFED3818 bit2; jl_s [fn] + W1C) → 0x241E5C → jl_s.d [0x392AC0+0x1C] = 0x140704. **L'arm avviene già all'init** (0x241E94 → 0x2422e8(0x3002) → 0x242224(0x3002,1): pending+enable bit2 settati); il trigger del lato 0x610 è il bit 15 di 0xFEF0074 (hardware o 0x16D4D8(0x610)).
- **Init 0x16D3F0** (chiamato da 0xC5D80, stesso padre del setup iris 0x140568): sr 0xfff8,[aux_irq_lev]; azzera ~18 maschere 0xFEF0xxx (0x263E24); W1C clear-all dei pending (0x263F08 scrive 0xFFFF); installa i walker come vettori {2←0x16DAF0, 4←0x2640E0, 5←0x264198, **6←0x264250**, 7←0x2643C0, 8←0x2643E0, 9←0x264308, 0xA←0x264498} con **8 chiamate INDIRETTE jl_s.d [r13]** a 0x231428 (register_vector; r13 = pool 0x16d510); costruisce trampolini j+limm-ME in RAM bassa (builder 0x16D3D8, basi 0x400/0x1400); flag [0x367884]=1.
- **PRECISAZIONE all'iterazione 29**: il census bl di 0x231428 = {0x145F80 TIMER1, 0x29F6A0 TIMER0} vale SOLO per le chiamate dirette; le 8 chiamate indirette dell'init erano invisibili a quel census. **Vector 7 ha DUE installatori statici** (init→0x2643C0, arming TIMER1 0x145F80→0x146104): precedenza runtime order-dependent (APERTO).
- Census bl congelati: 0x242224={0x242370,0x242402}; 0x2422E8={0x16D74C,0x1A084E,0x239188,0x241EA2}; 0x242380={0x15AA14,0x16D754,0x2391A0}; 0x16D3F0={0xC5D80}; 0x16D4D8={0x16F0F6,0x2331B4,0x238B56}; 0x16D898=43, 0x16D7E8=44, 0x16D840=49, 0x16D5BC=2; 0x242488 e 0x264250 POINTER-ONLY (zero branch di qualsiasi forma; pool 0x2424a0/0x16d518); 0x242414: bl {0x16D9B6,0x1A083E,0x241E98} + tail b.d 0x23914E.

**Comandi/esiti.** `python3 Python_Trace_Scripts/s33_verify_service_request_framework.py` → **PASS_SERVICE_REQUEST_FRAMEWORK_STATIC 20261022T031030Z post-audit** (exit 0; 030248Z/030233Z = PASS pre-audit della stessa sessione; le cartelle 025910Z–030204Z sono le calibrazioni fallite della prima stesura: census 0x242380 esteso ai tre chiamanti reali {0x15AA14, 0x16D754, 0x2391A0}, conteggi census corretti 43/44/49/2 (solo forme bl), bl.d nel corpo 0x242414, immediati decimali del router (1536=0x600), finestra raise_16d4d8 divisa (il percorso "trovato" sta dopo il pool a 0x16D584), conteggio sth.di del clear-pending (la sesta store stride il pool ed è asserita byte-exact a 0x263F1C). Nessuna asserzione indebolita. Verificatore: sha firmware + blocchi manifest, 36 pool LE dai byte raw, parse delle 7 tabelle payload1, census 15 target, scansioni negative LE/ME, 19 finestre GNU allineate, modello funzionale completo (register→ready→arm→raise→walk→0x241E5C→0x140704 con W1C). **Agente `svc-framework-audit-36`** (tools.agents.spawn, configurazione ereditata; «task con agente explore» non esiste in questo ambiente, come documentato), atteso e integrato: **claim 1–10 e 12 CONFERMATI** (12 = inferenza statica così etichettata; precisazioni accolte: bit ready saltato per id di confine 0x3000/0x4000; W1C del pending anche a fn nullo, e walker in early-exit quando la pending locale si azzera; id 0x3002 della register proviene dal pool 0x241F7C nel delay slot; conteggi bl-only 43/44/49/2, con i tail b/b.d 44/44/51/2; 0x263E24 = esattamente 18 sth.di; trampolini a 0x418..0x450/0x1418..0x1450; 0x231428 LE solo al pool 0x16d510; gate [0x367884] + identity 0x13030513 su 0x16D7E8/0x16D898); **claim 11 CONTRADDETTO IN PARTE E CORRETTO**: nel router 0x16D5BC NON esiste la classe 0x0700 — mappatura corretta 0x0400→0x424A00, 0x0500→0x424A8C, 0x0600→0x424B18, 0x0800→0x424BA4, 0x0900→0x424C30, 0x0A00→0x424CBC (id 0x07xx → default d'errore; il `cmp 0x7000` è la classe ALTA 0x7000 → 0x24D388/0x24D3F0). Docstring verificatore, rapporto §2/§7 e MDs/AGENTS.md corretti; verificatore rieseguito PASS post-audit (le finestre asserite sul router erano già corrette).

**Fonti precise.** Payload0 base 0x0AD800: register 0x242414..0x242486, request setter 0x242224..0x2422E4, ready 0x2422E8..0x24237E, unregister 0x242380..0x242412, dispatcher 0x242488..0x242572 (loop A 0x2424B0..0x242508, loop B 0x242512..0x24256E), router 0x16D5BC..0x16D7E8, enable/disable/register 0x16D7E8/0x16D840/0x16D898, raise 0x16D4D8..0x16D582 (found 0x16D584..0x16D5B6), init 0x16D3F0..0x16D4D6, builder 0x16D3D8..0x16D3EC, walker 0x264250..0x264304 e 0x2640E0..0x264194, clear 0x263E24/0x263F08; pool 0x16D50C..0x16D580, 0x2424A0..0x2424AC, 0x24225C/0x242294. Payload1 base 0x360800: tabelle 0x424500..0x4245D8, 0x424B18.., 0x424A00/0x424A8C/0x424BA4/0x424C30/0x424CBC, array 0x3F6CC8.

**Limiti.** Statico, nessun hardware/runtime, NON_INSTALLARE, circa10% invariato. Semantica W1C dei pending 0xFED3xxx/0xFEF0xxx = inferenza forte dal pattern (init scrive 0xFFFF; il servizio riscrive il bit e azzera la copia locale), non prova elettrica. Chi alza a runtime il bit 15 di 0xFEF0074 e il bit 2 di 0xFED3818 NON chiuso (chiamanti 0x16D4D8 {0x16F0F6, 0x2331B4, 0x238B56} da decodificare per gli id passati; sito LE 0x1A14A8 = 0xFED3818). Mappa vector→linea hardware = inferenza comportamentale (intvec APERTO). Vector 7 a doppio installatore. Trampolini RAM bassa (0x400/0x1400) descritti, target 0x265xxx non decodificati. V1.1 campione vs macchina V1.0.

**Prossimo passo (non ripetitivo).** (a) **Chi alza i bit pending a runtime**: decodificare i tre chiamanti di 0x16D4D8 per gli id passati e il sito 0x1A14A8 (0xFED3818), per attribuire l'evento fisico che pilota il vettore 6 e la richiesta 0x3002; chiude il lato "trigger hardware" della catena iris. (b) In alternativa il gemello TIMER0/scheduler tick (punto (b) dell'iterazione 29, ancora aperto; ora con la mappa dei vettori del framework nota). Entrambi offline e byte-verificabili; il punto dispatcher-id-0x3002 è CHIUSO, non rieseguire i census già fatti.

## Iterazione 34 — 22 ottobre 2026 — consumatori runtime delle registrazioni iris: MCUCTRL_Task 0x15A80C attende l'evento 0x3200002 e invoca [0x5545F8+0x18]=0x1406D0 via handler 0x242104; 0x241E5C invoca [0x392AC0+0x1C]=0x140704 (verificatore Registration_Consumers PASS post-audit)

**Domanda affrontata.** Prossimo passo (a) dell'iterazione 31 (le iterazioni 32/33 non hanno lasciato voci, come la 30/28): chi consuma a runtime le registrazioni — lettori/invocatori di [0x5545F8+0x18] (=0x1406D0, cella scritta da 0x22C3BC) e [0x392AC0+0x1C] (=0x140704, cella scritta da 0x16ACDC(7,2,ptr)) — e chi attende l'evento 0x3200002 bit 10.

**Risultato.** [Rapporto](S33_Iride_Consumatori_Registrazioni_Evento_3200002.md), [script](../Python_Trace_Scripts/s33_verify_iris_registration_consumers.py), [prove](../Risultati/Runtime_Kernel/Event_3200002_Consumers/latest.json) (evidenza **20261022T024538Z post-audit**; 023935Z pre-audit). PASS alla prima esecuzione completa dopo tre calibrazioni (finestra 0x242040 estesa a 0x2420D0 per includere il corpo 0x2420B4; pattern `bl\s+-?\d+` per offset negativi; scansione LE a ogni offset).
- **Il consumatore è MCUCTRL_Task 0x15A80C** (record payload1 0x372508: id 0x3200001, entry, stack 0x800, priorità 6): loop = `0x158D04(0x3200002, 0x60F7F773, 0, 0)` (attesa) → `0x158E28(0x3200002, &sp)` (lettura bit) → `0x158CE0(0x3200002, bit)` (auto-clear) → dispatch: bit0→0x241EC4, 4/5/6→0x241F88, **8/9/10→0x242104**, 12..15→0x2416F8, 20..23→0x241E58 (stub VUOTO 2 byte `j_s [blink]`), bit29→0x241F0C+0x241FC8, bit30 clear→loop.
- **Handler 0x242104 = consumatore di [0x5545F8+0x18]**: bit8 → valore corrente (0x2D62B0) == coppia [+0x2C/+0x2E] e modo [+0x20]==2 → snapshot 0x2B7190 (scrive valore→[+0x30], >>16→[+0x28], &0xFFFF→[+0x2A]) → contatore [+0x38]++ → **jl_s.d [+0x18] con r0=[+0x30]**: il trigger runtime del commit del complemento (0x1406D0→[0x366DE8](~x,0)→0x16EC38) è chiuso. Bit9 → nuovo valore in [+0x2E]/[+0x2C] e armamento [+0x20]=2; bit0xA → stop 0x2B7204+0x2B712C+0x242094 e byte [0x5545F8+0] 0→1.
- **0x241E5C = consumatore di [0x392AC0+0x1C]**: v=0x169870(), SET evento bit1, jl_s.d [+0x1C] con r0=v&7, r1=v&0xF (→ 0x140704 → celle id-1/2/4). Puntatore in pool 0x241F78, registrato sotto id 0x3002 da 0x241E94 (unico chiamante 0x16AA72, dentro la funzione init 0x16A9F8 della famiglia 0x16Axxx).
- **Secondo slot 0x392AC0+0x18**: 0x16AAB4 registra (se cella vuota, gate byte [+0x2A] → SET evento bit0); 0x241EC4 (handler bit0 del task) invoca [+0x18] con r0=[+0xC] (valore da 0x16ABC0), gate [+0x2A] intorno alla chiamata.
- **Produttori evento 0x3200002**: bit8/9 = 0x242040 (0x2D6200 bit0/bit1, r1=256/512; registrato come callback da 0x2420D0 via 0x16D898(1545,fn), pool 0x242210; 0x2420D0 chiamato solo da 0x22C3AE); **bit10 = 0x22C3BC (iterazione 31) E 0x22C56C** (arg→[0x5545F8+8], r1=1024); bit0 = 0x16AAB4; bit1 = 0x241E5C; bit4 = 0x16C68C (gate byte 0x392D70+0x19/+0; **chiamato dal setup iris 0x140568 a 0x1405D6**); bit6 = 0x16C70C (stesse gate).
- **Negativi**: zero branch di qualsiasi forma verso 0x1406D0/0x140704 in tutto il listato (unico hit verso 0x140704 = V00D3F696 REGION TBM_09 = dati, classificato con finestra allineata); 0x241E5C/0x242040/0x16AAB4/0x22C56C senza chiamanti bl (solo puntatore; **0x16AAB4 installato da 0x16A9F8 via pool 0x16ADC8 nella tabella famiglia a struct+0x10** — correzione/aggiunta audit); **0x242104 ha esattamente UN chiamante bl: il task 0x15A8B6** (la prima stesura lo elencava per errore tra i pointer-only, corretto dall'audit); zero LE/limm-ME verso 0x5545F8/0x392AC0 fuori dai pool asseriti (hit LE 0x1406D0@0x2B7475 = straddle istruzioni). Precisazione audit sullo slot +0x18: lo store [+0xC] di 0x16ABC0 è sul percorso r0>0 e i due chiamanti statici noti passano r0=0 → scrittori statici di [+0xC] = init 0x241E94 (=0x20) e 0x16C6AC.

**Comandi/esiti.** `python3 Python_Trace_Scripts/s33_verify_iris_registration_consumers.py` → PASS_IRIS_REGISTRATION_CONSUMERS_STATIC **20261022T024538Z post-audit** (exit 0; 023935Z = pre-audit della stessa sessione; `latest.json` punta alla post-audit): 14 finestre GNU allineate (13 payload0 incl. init 0x16A9F8 + 1 classificazione dati payload9), ~36 pool raw LE, census 18 target con aspettative congelate, scansioni negative LE/limm su 16 payload, modello maschera/dispatch. Calibrazioni della prima stesura: finestra 0x242040 estesa a 0x2420D0 (corpo 0x2420B4), pattern `bl\s+-?\d+` per offset negativi, scansione LE a ogni offset. **Agente `reg-consumers-audit-34`** (tools.agents.spawn, configurazione ereditata; «task con agente explore» non esiste in questo ambiente, come documentato nelle iterazioni precedenti), atteso e integrato: claim 1/2/3/5/7 CONFERMATI byte-exact; claim 4 CONFERMATO CON PRECISAZIONE ACCOLTA (lo store [+0xC] di 0x16ABC0 è sul percorso r0>0 e i due chiamanti statici noti passano r0=0 → scrittori statici di [+0xC] = init 0x241E94 (=0x20) e 0x16C6AC; §6 del rapporto corretto); claim 6 CONFERMATO CON UNA CORREZIONE ACCOLTA (la prima stesura elencava 0x242104 tra i «senza chiamanti bl»: ha esattamente UN chiamante, il task 0x15A8B6 — §8 e verificatore corretti); precisazioni di etichetta (chiamante 0x16AA72 dentro fn 0x16A9F8) e guardia bit9 sul confronto snapshot accolte; NOTA AGGIUNTIVA ACCOLTA: **pool 0x16ADC8 = 0x16AAB4 installato da 0x16A9F8 nella tabella famiglia a struct+0x10** → 0x16AAB4 raggiungibile via dispatch calcolato, ora asserito con finestra dedicata. Verificatore corretto e rieseguito PASS senza indebolire asserzioni. Conferma finale identica **20261022T024726Z** (ultima cartella, `latest.json` punta qui; 024538Z = post-audit, 023935Z = pre-audit, 0238xx–023911Z = calibrazioni fallite della prima stesura, conservate).

**Fonti precise.** Payload0: task 0x15A80C..0x15A912 (pool 0x15AAE0..0x15AB0C), handler 0x242104..0x2421FC (pool 0x242200..0x242220), producer 0x242040..0x2420D0, 0x241E5C..0x241EC4 (pool 0x241F70..0x241F80), 0x241EC4..0x241F10, 0x16AAB4..0x16AAF0 (pool 0x16ADC0..0x16AE04), 0x16C68C..0x16C728 (pool 0x16C7C0/0x16C7E4), 0x22C56C..0x22C58C (pool 0x22C584/0x22C588), 0x2B7190..0x2B71F0 (pool 0x2B7234), setup 0x140568..0x1405E8 (pool 0x1405E8/0x1405EC). Payload1: record 0x372508. Payload9 (base 0xC8F800): sito dati 0xD3F650..0xD3F6E0.

**Limiti.** Statico, nessun hardware/runtime, NON_INSTALLARE, circa10% invariato. Il dispatcher dell'id 0x3002 (chi chiama 0x241E5C a runtime) e la famiglia provider del valore 0x2D62xx NON decodificati: strato successivo. Bit 1/16/17/18 della maschera senza dispatch nella finestra del loop; percorso di uscita del task non decodificato. Census lineari = candidi; siti della catena tutti in finestre dedicate. V1.1 vs V1.0.

**Prossimo passo (non ripetitivo).** (a) Dispatcher dell'id 0x3002: servizio 0x242414 e chiamanti {0x16D9B6, 0x1A083E, 0x23914E, 0x241E98} — chi invoca 0x241E5C chiude il trigger runtime di 0x140704. (b) In alternativa il gemello TIMER0 (handler 0x29F740) come tick dello scheduler Nikon (punto (b) dell'iterazione 29, ancora aperto). Entrambi offline e byte-verificabili; il punto consumatori-registrazioni è CHIUSO, non rieseguire i census già fatti.

## Iterazione 31 — 22 ottobre 2026 — iris: scrittori della coppia di stato 64-bit = setter 0x16E3A2 + commit 0x16EC38 (cella 0x366DE8/invoker 0x1406D0) + complementare 0x16F8EC di init; normalizzatore 0x16E6E0 decodificato (verificatore Iris_State_Pair PASS post-audit)

NB documentale: l'iterazione 30 non ha lasciato voce in questo file né prove in Risultati/ (come la 28); si riparte dal prossimo passo dell'iterazione 29.

**Domanda affrontata.** Punto (b) dell'iterazione 27 / prossimo passo (a) dell'iterazione 29: chi scrive a runtime la coppia di stato 64-bit (struct 0x3678E4 +0xC/+0x10) consumata da 0x16F86C — da cui nascono i bit 16/21/15 letti dal pannello iris come richieste 8/9/0xA.

**Risultato.** [Rapporto](S33_Iride_Scrittori_Coppia_Stato_64bit.md) (§9 = revisione indipendente), [script](../Python_Trace_Scripts/s33_verify_iris_state_pair_writers.py), [prove](../Risultati/Lens_MCU_Interface/Iris_State_Pair/latest.json) (evidenza **20261022T022435Z post-audit**; 021333Z = pre-audit della stessa sessione).
- **Tre scrittori statici, census completo** (chiamanti di 0x16F86C = {0x16E3FA, 0x16EC74, 0x16F90A}): **setter 0x16E3A2(secondary,value)** (tabella record 0x392F04, bit alla posizione rec[+8] via __ashldi3 0x334E9C, commit 0x16F86C(·,·,1); NESSUN chiamante statico: zero bl/b, zero word LE, zero limm nei 16 payload, zero jump table — dispatch calcolato o codice morto); **commit 0x16EC38(lo,hi)** (registrato dall'installer 0x16E2F4 via 0x140634 nella cella **[0x366DE8]**, pool 0x16E390; invocato solo da **0x1406D0(x) = [0x366DE8](~x, 0)** = commit del complemento); **complementare 0x16F8EC** (solo init, caller 0x16E336; bl_s 0x16F86C interno a 0x16F90A).
- **Normalizzatore 0x16E6E0(&pair)** decodificato: struct 0x367898 (gate byte 0x3678A2, mirror halfword 0x36789C), maschera **0xFE31B188** su lo (complemento 0x01CE4E77, bit cancellati {0,1,2,4,5,6,9,10,11,14,17,18,19,22,23,24} — NESSUN bit di record è toccato), gate==1 → azzera gate + forza bit0=1 e SALTA magic e validazione; altrimenti bit0 cancellato; campiona via __lshrdi3 0x335C4C shift 5/10/15/20 con maschere 0xC/0xC/3/3 (`bmsk_s ,0x1` = 2 bit, correzione audit) → bit campionati **{7,8,12,13,15,16,20,21}**; bypass magico (0xFE003000,0); validazione «al più un bit campionato», altrimenti ritorna 0 senza scrivere; accettazione → *(&pair)=(lo',hi'), mirror=bit0, ritorno 1.
- **Catena di registrazione**: setup **0x140568** (chiamato da 0xC5D88, stessa funzione padre di 0xC5D9E che installa 0x16E2F4) registra **0x1406D0** via 0x22C3BC (ptr a [0x5545F8+0x18] solo se cella vuota; event SET 0x158CBC(0x3200002,1<<10), r1=1 nella chiamata del setup) e **0x140704** via 0x16ACDC(7,2,ptr a [0x392AC0+0x1C]; halfword **7** a +0x14 — correzione audit, non 3); 0x140704(bits) invoca bit2→[0x366DE0]=**0x16ECB4** (id-4), bit1→[0x366DE4]=**0x16EC88** (id-2; correzione audit: la prima stesura aveva le due funzioni invertite), bit0→[0x366DDC] (id-1; ld.as −69 a 0x14073E → pool 0x140628, regola (PC&~3)+campo×4 riconfermata; cella SENZA registranti nei 16 payload). Servizi di registrazione: 0x140634→[0x366DE8], 0x1405F8(1/2/4)→[0x366DDC]/[0x366DE4]/[0x366DE0], 0x148F64→[0x366F78].
- **Conseguenza iris**: la maschera NON cancella i bit 16/21/15 ma tutti e tre SONO CAMPIONATI dalla validazione → ogni singola richiesta 8/9/0xA può nascere dal setter, dal commit o dal complementare di init, mentre una commit con DUE richieste simultanee (es. bit16+bit21) è RIFIUTATA senza scritture; il setter 0x16E3A2 non passa dal normalizzatore e non è vincolato. Origine chiusa staticamente nel perimetro {0x16E3A2, 0x16EC38, 0x16F8EC}. Record statici payload1 riverificati: coerenza 16/16 (bitpos = posizione del bit della maschera, 32+bit per la halfword alta).
- **Correzioni in corsa** (mie, documentate): complemento della maschera = 0x01CE4E77 (non 0x01CE4777; il bit 8 NON è cancellato e sopravvive, come 16/21/15); aritmetica ld.as 0x14073E → 0x140628 (errore di sottrazione iniziale, regola pcl standard intatta).

**Comandi/esiti.** `python3 Python_Trace_Scripts/s33_verify_iris_state_pair_writers.py` → **PASS_IRIS_STATE_PAIR_WRITERS_STATIC 20261022T022435Z post-audit** (conferma finale identica 20261022T022732Z, ultima cartella, `latest.json` punta qui; 021333Z pre-audit; le cartelle 0211xx–0212xx sono calibrazioni della prima stesura): 13 finestre GNU allineate, 23 pool raw LE, census 14 target con aspettative congelate, scansioni negative LE/limm/branch su 16 payload, modelli (setter sui 16 record reali, normalizzatore con sweep 2^16 sui bit campionati {7,8,12,13,15,16,20,21}, coerenza record-bit/maschera). Calibrazioni della prima stesura: `\b` dopo `]` rimosso ovunque (lezione nota), census 0x14066C esteso ai 3 chiamanti reali {0x16B7CE, 0x16E31A, 0x174E72}, asserzione cleared corretta dopo ricalcolo del complemento 0x01CE4E77. **Agente `iris-pair-audit-31`** (tools.agents.spawn, configurazione ereditata; «task con agente explore» non esiste in questo ambiente, come documentato nelle iterazioni precedenti), atteso e integrato: claim 1/2/4/5 CONFERMATI; precisazioni materiali ACCOLTE e riverificate sui byte dal coordinatore: (a) `bmsk_s ,0x1` maschera 2 bit → campionati {7,8,12,13,15,16,20,21} (il validatore copre anche i bit 16/21: commit con due richieste iris simultanee rifiutata senza scritture); (b) celle id-2/id-4: 0x1405F8 case 2 → 0x366DE4, case 4 → 0x366DE0 (bit2 → 0x16ECB4, bit1 → 0x16EC88); (c) 0x16ACDC memorizza halfword 7 (bmsk &7), non 3; (d) campione bit3 non contato, ramo gate==1 salta magic+validazione; (e) ld morte nel setter (carichi non inizializzati, innocui); (f) 0x22C3BC memorizza il ptr solo se la cella è vuota, r1=1 nella chiamata setup → evento pubblicato; (g) census 0x16F86C/0x16F8EC esatto anche con scanner brute-force dell'agente (unico extra hit p09@0xD70F6E = coincidenza dati fuori sync). Verificatore corretto e rieseguito PASS.

**Fonti precise.** Payload0 base 0x0AD800: setter 0x16E3A2..0x16E41A, commit 0x16EC38..0x16EC86, normalizzatore 0x16E6E0..0x16E82E, installer 0x16E2F4..0x16E384 con pool 0x16E388..0x16E39C, setup 0x140568..0x1405E6 con pool 0x1405E8..0x1405F4, reg 0x1405F8/0x140634/0x148F64, invoker 0x1406D0..0x14074E con pool 0x140624..0x14064C, getter 0x14066C, servizi 0x22C3BC (pool 0x22C474=0x5545F8, 0x22C484=0x3200002) e 0x16ACDC (pool 0x16ADC0=0x392AC0); payload1 base 0x360800: record 0x392F04 (16×20B).

**Limiti.** Statico, nessun hardware/runtime, NON_INSTALLARE, circa10% invariato. Il setter 0x16E3A2 non ha chiamanti censibili (dispatch calcolato: punto cieco, o codice morto). I consumatori delle registrazioni 0x22C3BC/0x16ACDC (chi legge [0x5545F8+0x18] e [0x392AC0+0x1C]) NON identificati: è lo strato successivo. Cella id-1 0x366DDC senza registranti. Coppia iniziale di boot da 0x14066C→0x22C434() non derivabile. Census lineare = candidati (siti della catena in finestre dedicate). V1.1 vs V1.0.

**Prossimo passo (non ripetitivo).** (a) **Chi consuma le registrazioni**: identificare i lettori di [0x5545F8+0x18] e [0x392AC0+0x1C] — il task/monitor che attende l'evento 0x3200002 bit10 e chiama 0x1406D0: chiude il trigger runtime del commit della coppia. (b) In alternativa il gemello TIMER0 (handler 0x29F740) come tick dello scheduler Nikon (punto (b) dell'iterazione 29, ancora aperto). Entrambi offline e byte-verificabili; il punto scrittori coppia è CHIUSO, non rieseguire i census già fatti.

## Iterazione 29 — 22 ottobre 2026 — TIMER1: consumatore runtime della tabella slot 0x4437F4 = tick 0x146104 via dispatch eccezioni kernel (verificatore Timer1_Deferred PASS post-audit)

**Domanda affrontata.** Il prossimo passo (a) dell'iterazione 27 = punto (b) dell'iterazione 23: chi consuma a runtime la tabella slot 0x4437F4 del servizio callback differiti 0x145F28 (chi fa scadere gli slot e chiama gli handler differiti, incluso 0x235AF8/0x235AE4 della famiglia iris). NB documentale: l'iterazione 28 non ha lasciato voce in questo file né nuove prove in Risultati/; si riparte dal punto aperto dell'iterazione 27.

**Risultato.** [Rapporto](S33_Timer1_Callback_Differiti_Dispatch_Kernel.md), [script](../Python_Trace_Scripts/s33_verify_kernel_timer1_deferred.py), [prove](../Risultati/Runtime_Kernel/Timer1_Deferred/latest.json) (evidenza **20261022T020135Z post-audit**; 0154xx-015530Z calibrazioni).
- **Il consumatore è il corpo tick 0x146104**: il post 0x145F28 (count [0x366EBC]+8==0) arma TIMER1 e registra l'handler con **0x231428(7, 0x146104, 0)** (pool 0x14623C), poi count1=0x1000000-scala e control1=3.
- **0x231428 = register_vector(code,handler,arg)**: tabella kernel [0x369348]+0x238, stride 12, bound +0x22C/+0x230, ritorna il precedente. Census payload0: SOLO 2 chiamanti (0x145F80 TIMER1/7; 0x29F6A0 TIMER0, handler 0x29F740).
- **Dispatch kernel**: 16 stub 0x0B2F74..0x0B3052 (cause r1=0..0xF) → entry comune 0x0B3054 (mov r4=r1) → 0x0B3150: entry=[kernel+0x238]+(causa-[kernel+0x22C])·12, jl_s.d [handler] con r0=[entry+8].
- **Tick 0x146104** (sezione critica; handler chiamati DENTRO): count<=0 → control1=2; re-arm count1+=0x1000000-scala (clamp 0xFFFFFB); loop1: [slot+0xC]-=scala, scadenza bit4, periodici (bit7) ricaricano da [slot+8], one-shot bit3 + count-- → control1=2 a zero; loop2 (0..9): bit4 → jl_s [slot+0x10].
- **Layout slot CORRETTO (raffina iterazione 23)**: +0 flags{bit0 attivo, bit3 rilascio, bit4 scadenza, bit7 periodico}, +4 seriale, +8 ricarica/iniziale (post scrive lo stesso valore a +8 e +0xC), +0xC conto vivo, +0x10 handler.
- Census TIMER1 payload0: control1={0x145F74,0x145F94,0x1460A0,0x146134,0x146184,0x1461D0,0x1F0BA0,0x29F6DC}, count1={0x145F6C,0x145F90,0x146126,0x14613C,0x1F0BAC,0x1F0BD2}, limit1={0x145F64}; fuori cluster solo init kernel 0x1F0B74 e blocco TIMER0 0x29F6BC..0x29F6F6.
- Scala = 0x12ca28(0) (MMIO 0x0FE800F8 bit7→12/13 → lettore tabelle 0x17A000 payload1) / divisore da byte modo [0x366EBC]+9 (0→10000, 1→100000, altro→1000).

**Comandi/esiti.** `python3 Python_Trace_Scripts/s33_verify_kernel_timer1_deferred.py` → PASS 20261022T020135Z post-audit (015530Z pre-audit): 16 finestre GNU ARC700 allineate, 8 pool raw LE, byte immediata mov_s r12,0x4437f4, census (aux TIMER1, chiamanti 0x231428, pool 0x146104), modello funzionale tick casi A-E. Agente: `timer1-slot-audit-29` via `tools.agents.spawn` (DISPONIBILE), atteso e integrato: claim 1-7 CONFERMATI, precisazioni accolte (divisore scala dipendente dal byte modo; a 0x29F6C4 si scrive control0, la disabilitazione TIMER1 è a 0x29F6DC; 0x17A000 è lettore di tabella in payload1). Verificatore aggiornato con le precisazioni e rieseguito PASS.

**Fonti precise.** Main payload0 base 0x0AD800: post 0x145F28/0x146044/0x14605C, tick 0x146104..0x1461E0, pool 0x146234..0x146250, register_vector 0x231428, stub 0x0B2F74..0x0B3052, entry 0x0B3054, dispatch 0x0B3150..0x0B31B8, kernel [0x369348]+0x22C/+0x230/+0x238, freq 0x12CA28 (pool 0x12CA38=0x0FE800F8) e 0x17A000, TIMER0 0x29F694..0x29F6F6, init kernel 0x1F0B74..0x1F0BD2. TBIB twin: 0x1013D64 (kernel 0x104126C), non riverificato.

**Limiti.** Statico, solo payload0, nessuna esecuzione/hardware. "Vettore 7 = TIMER1" è inferenza comportamentale (wiring intvec ARC700 APERTO). Tick in secondi non derivato (MMIO + tabella frequenze runtime). Chiamate calcolate jl [reg] a 0x231428 non censibili. Circa10% invariato, NON_INSTALLARE.

**Prossimo passo (non ripetitivo).** (a) Punto (b) dell'iterazione 27: **chi scrive a runtime la coppia di stato 64-bit** della shadow iris (chiamanti del consumatore 0x16F86C: 0x16E3FA, 0x16EC74, 0x16F90A; 0x16F8EC scrive la coppia complementare forzando tutti) — bit 16/21/15 originano le richieste 8/9/0xA. (b) In alternativa, il gemello TIMER0 (handler 0x29F740) come tick dello scheduler Nikon: mappa dei servizi timer del kernel utile al futuro task cooperante R3. Entrambi offline e byte-verificabili; il punto TIMER1/slot è CHIUSO, non rieseguire i census già fatti.

## Iterazione 27 — 22 ottobre 2026 — classificatore boot-config 0x16E440 decodificato (byte del record TBIB 8) + audit iterazione 26 accolto: origine richieste iris 8/9/0xA chiusa staticamente (verificatori Boot_Config_Classifier e Iris_Shadow PASS)

**Domanda affrontata.** Due punti: (1) recupero documentale dell'iterazione 26 (checkpoint mancanti: voce Vibe, AGENTS.md) e completamento dell'audit indipendente interrotto; (2) punto aperto (a) dell'iterazione 26: decodificare il «dispatcher comandi 0x16E440» (candidato produttore delle richieste shadow 8/9/0xA).

**Risultato.** [Rapporto](S33_Boot_Config_Classifier_0x16E440.md), [script](../Python_Trace_Scripts/s33_verify_boot_config_classifier.py), [prove](../Risultati/Boot_Config/Classifier/latest.json) (evidenza **20261022T014741Z**; 014519Z–014726Z calibrazioni).
- **0x16E440 = classificatore PURO del byte 0xC8E80C**: argomenti morti (r0/r1 salvati a [fp,8]/[fp,12] mai riletti), getter 0xCAD30 (`ld.as [pcl,-155]` → pool 0xCAAC4 = 0xC8E80C), jump table 68 casi a 0x16E46C (byte-offset ×2), 25 valori non-zero → codici {1,2,5..9,0xD,0xE,0x10,0x12..0x1B,0x20,0x21}, default 0, NESSUNA scrittura → non è il produttore cercato.
- **0xC8E80C = record TBIB 8 (payload 8, base 0xC8E800, tipo 1, 0x600B, magic C1C2C3C4, «NotRunOneCard») + 0xC = 0x2C in V1.1 → codice 7**. Census pool: 8 siti payload0, zero altrove. Chiamanti: 0xCA284/0x20EDE0 (payload0), 0x7FF6C2/0x800174 (payload4 tuning) → richieste UI 0x1453E4(0x87, 0..7); 0xDC0B74 (payload9) falso positivo dati (word 0xD6F900CD; `fmul.f` su pcl; zero inbound). Pattern shadow[0x61] inerte.
- **Audit `iris-shadow-audit-27` (iterazione 26) COMPLETATO e accolto** con riverifica byte del coordinatore: record+8 = POSIZIONE DI BIT (via `__lshrdi3` 0x335C4C + `extb_s`); **tabella record 0x392F04 statica in payload1** (offset 0x32704): rec[1/2/3] → idx 8/9/0xA = bit 16/21/15 della coppia di stato 64-bit → origine richieste iris chiusa staticamente; EXPLICIT_IDX corretto (0x16E8F6=0x77, 0x16EF7A=0x65); sub3 ×8 = regola ISA; pannello = fn 0x2C5074, loop 0x2C50B6–0x2C517E. Revisione in §9 del [rapporto shadow](S33_Iride_Shadow_0x446808_Scrittore_e_Servizio_Diagnostico.md).
- Recupero iterazione 26 eseguito: voce iterazione 26 in questo file, checkpoint IRIDE SHADOW in MDs/AGENTS.md (poi corretto con le precisazioni dell'audit).

**Comandi/esiti.** `python3 Python_Trace_Scripts/s33_verify_boot_config_classifier.py` PASS (20261022T014741Z); `python3 Python_Trace_Scripts/s33_verify_lens_iris_shadow.py` PASS post-audit con EXPLICIT_IDX corretto (20261022T014758Z). Agente: `iris-shadow-audit-27` via `tools.agents.spawn` (task/agents DISPONIBILE in questa sessione), verdetto claim-per-claim integrato.

**Limiti.** Statico; nome fisico del byte record8+0xC e dei codici APERTO (inferenza: configurazione di variante); record 8 runtime potrebbe differire (loader TBIB); resta APERTO chi setta/azzera a runtime i bit 16/21/15 della coppia di stato e il consumatore della tabella slot 0x4437F4/TIMER1 (punto (b) iterazione 23). NB strumentale: errore iniziale di aritmetica esadecimale sul pool ld.as (0xCAAC4, non 0xCAC64) ha richiesto riverifica statistica della regola scalata su 2492 siti — sempre rileggere i pool dai byte prima di classificare. Circa10% invariato, NON_INSTALLARE.

**Prossimo passo.** (a) Consumatore runtime della tabella slot 0x4437F4 / interrupt TIMER1 (punto (b) dell'iterazione 23: chi fa scadere gli slot e chiama gli handler differiti — servizio 0x145F28). (b) In alternativa i 3 chiamanti del consumatore 0x16F86C (0x16E3FA, 0x16EC74, 0x16F90A) per identificare chi scrive la coppia di stato 64-bit da cui nascono i bit 16/21/15 delle richieste iris. Entrambi offline e byte-verificabili; non ripetere inventari già chiusi.

## Iterazione 26 (recupero documentale in iterazione 27) — 22 ottobre 2026 — iris shadow: scrittore della tabella 0x446808 e servizio byte diagnostici (verificatore Iris_Shadow PASS)

NB: la sessione dell'iterazione 26 è stata terminata dal runner per assenza di output DOPO aver prodotto rapporto/script/evidenze e voci in roadmap/percorsi/Stato_progetto, MA PRIMA di scrivere questa voce di checkpoint, PRIMA di aggiornare MDs/AGENTS.md (rimasto all'iterazione 23) e con l'agente di audit `iris-shadow-audit` ancora in corsa. Questa voce è stata scritta in iterazione 27 come recupero; l'audit è stato rilanciato come `iris-shadow-audit-27`. Nessun contenuto tecnico è stato modificato: i fatti sotto sono quelli dell'iterazione 26 così documentati.

**Domanda affrontata.** Punto aperto dall'iterazione 23: chi scrive la tabella shadow 0x446808 che il pannello diagnostico 0x2C5100 polla per le voci iris (indici 8/9/0xA)? Risultato completo in [rapporto](S33_Iride_Shadow_0x446808_Scrittore_e_Servizio_Diagnostico.md), [script](../Python_Trace_Scripts/s33_verify_lens_iris_shadow.py), [prove](../Risultati/Lens_MCU_Interface/Iris_Shadow/latest.json) (evidenza 20261022T013010Z; 012859Z–013000Z calibrazioni). PASS: 19 finestre GNU allineate + pool raw LE + census LE/limm su 16 payload + census chiamanti (15 target) + modello funzionale.

**Risultato (sintesi).** Scrittore unico del byte valore = 0x16F72C(secondary,idx,value,flag), store `stb_s r2,[0x446808+4·r1]` a 0x16F742 senza range check; init 0x16F638 (lp 128, LIMM 0x446808 a 0x16F646, voce {0,0xFF,1}); la shadow è il cache diagnostico di una macchina a stati 64-bit: 16 record 20B da 0x392F04 installati da 0x16E2F4 via 0x16F66C nella struct 0x3678E4, consumatore 0x16F86C sulle maschere cambiate, 0x16F8EC forza tutti, handler notifica 0x16E588, dispatch 0x16F6B0 su 0x446A08. Pannello 0x2C5100: voci 8/9/0xA = richieste servite dal pannello (9→0x18B85C(1), 0xA→0x18B85C(9), until-zero), NON telemetria; nessuno scrittore statico tocca 8/9/0xA.

**Comandi/esiti.** `python3 Python_Trace_Scripts/s33_verify_lens_iris_shadow.py` PASS (evidenza 20261022T013010Z, eseguita dalla sessione 26; in iterazione 27 non rieseguita prima dell'audit — vedi limite sotto).

**Limiti.** Statico; audit indipendente dell'iterazione 26 non completato alla terminazione; contenuto runtime della tabella record 0x392F04 non derivabile staticamente. Aperti: origine runtime delle richieste 8/9/0xA, dispatcher 0x16E440, consumatore slot 0x4437F4/TIMER1, sub3 ×8 derivazione.

**Prossimo passo.** Vedi iterazione 27 (questa sessione): audit `iris-shadow-audit-27` sulle conclusioni 26 + nuovo punto offline sul dispatcher 0x16E440 della stessa famiglia.

## Iterazione 23 — 22 ottobre 2026 — iris: lato completamento della mossa byte-exact (handler differiti, evento 0x10, chi azzera [0x36A464+6]; verificatore Iris_Completion PASS)

**Domanda affrontata.** Punto (a) aperto dall'iterazione 21 ([attuazione GPIO iris](S33_Iride_Attuazione_GPIO_0FF04024_e_Chiusura_Wrapper.md)): decodificare il lato completamento della mossa iris — handler 0x235AF8/0x235AE4, consumatore dell'evento 0x10 e chi azzera il byte di stato [0x36A464+6] — il pezzo che serve al «ritorno pronto» del percorso fotografico (R0/R1). NB numerazione: il runner dell'utente conta questa sessione come iterazione 23; nel file non esiste una voce 22 (sessione non registrata/interrotta; nessun file di iterazione 22 trovato con rg su MDs/). Questa sessione è stata inoltre interrotta una volta dal limite turni e ripresa; il verificatore era già stato scritto e calibrato fino al census 0x36A488.

**Risultato.** [Rapporto](S33_Iride_Completamento_Handler_Evento_e_Byte_Stato.md), [script](../Python_Trace_Scripts/s33_verify_lens_iris_completion.py), [prove](../Risultati/Lens_MCU_Interface/Iris_Completion/latest.json) (**evidenza valida 20261022T011924Z post-audit; conferma finale identica 20261022T011933Z, ultima cartella; le corse 011103Z/011112Z sono pre-audit della stessa sessione**).
- **Chi azzera [0x36A464+6]: il corpo di completamento 0x2359B0**, eseguito come callback differito: callback opzionale [0x36A464+0x3C] (jl_s [r0]), sezione critica 0x1786E8/0x179354, 0x0FF04024 `or 0x18` (ACCENDE entrambi i bit iris), attesa 500 via 0x23C620, sezione critica, `and -25` (SPEGNE bit 0/1/3/4), `mov r13,0; stb_s r13,[r14,0x6]` a 0x235A02 → **status=0 DENTRO la stessa sezione critica**, ritorno 0.
- **Handler differiti**: 0x235AE4 = 0x2359B0 → 0x23524C(2) (rilascio: 0x235C60→0x234CD0) → 0x235DE8 (azzera in-motion [0x36A488] sotto gate 0x2C4F90([0x36A484])) → ritorno; **0x235AF8** (scelto quando wait!=0, pool 0x235BCC) = 0x235AE4 + **evento SET 0x158CBC(1|1<<25, 0x10)**; 0x235AE4 è scelto quando wait==0 (pool 0x235BD0).
- **Evento 0x10** = bit 0x10 del gruppo eventi id 0x2000001: risoluzione 0x158C8C (tabella [0x372A48], stride 0x38, magic 0x45564E4C, bit31 a +8); i servizi 0x158CE0/0x158CBC operano sul puntatore entry+0xC (precisazione audit): CLEAR 0x158CE0→0x23C8AC `bic_s` su [entry+0x24] chiamato dalla request PRIMA del post; SET 0x158CBC→0x23C758 `or_s` su [entry+0x24] + risveglio lista waiter [entry+0x14]; WAIT 0x158D04 registra il waiter (blink a [event+0x2c], senza shift) — chiamato dalla request DOPO il post se wait e post-ok.
- **Post 0x145F28 = servizio callback differiti condiviso** (9 siti chiamanti censiti, iris = 0x235B86): oggetto servizio 0x366EBC (pool 0x146234; [+8] init/contatore, [+0xc] scala tick via divisione 0x335B34 per 0x2710, [+0x10] seriale), **TIMER1 ARC700** armato (sr limit1=0x1000000, count1, control1=2 poi 3), tabella slot 0x4437F4 (pool 0x146240) con 10 slot × 20 byte (flags +0, seriale +4, scadenza +8 dal timeout via millicode 0x336364/0x335D34, **handler a slot+16**: `st r18,[r13,16]`), errore handler nullo 2|1<<0x15, **servizio cancel 0x14605C** (trova slot per seriale, azzera flags, decrementa contatore; 3 chiamanti).
- **Setter 0x18B85C chiama SEMPRE la request con wait=1** (`mov_s r2,0x1` a 0x18B8AA, timeout r3=0x3A98) → **0x18B85C ritorna solo a mossa completata** (modello runtime: l'attesa è su evento 0x10; lo scheduler non è eseguito); commit del byte di stato [0x367FE8+2] solo se la request ritorna 1; su fallimento `bl 0x18B9D4` = corpo dell'handler eseguito SINCRONO (0x2359B0 + 0x23524C(2) + 0x235DE8) senza commit. Altri ingressi di completamento: 0x18B844 (0x2359B0 + 0x235188(2)), 0x18B6B4 (tipo 1: 0x2357C8 + 0x23524C(1) + 0x235DE8).
- **CORREZIONE all'iterazione 21**: il «contatore halfword [[0x36A464]+0x1c]++» era una doppia dereferenziazione che i byte non mostrano: entrambi i load prendono il VALORE del pool 0x235BC8 (=0x36A464) e accedono a [+0x1c]; il contatore È la halfword **[0x36A464+0x1c] = cella 0x36A480** — la stessa cella che la pre-guardia 0x235ABC confronta con h e che l'acquire 0x235A1C(2,&h) restituisce come handle (busy [+0x26], callback tipo [+0x34], `sth r0,[r16]` a 0x235A66): **guardia di generazione** (handle stantia rifiutata dopo l'incremento). Helper 0x18B954(idx,h): DOPPIA pre-guardia attorno al confronto idx vs stato [0x367FE8+2] (pool ld.as scalato 0x18B8F9→0x18B788=0x367FE8) + release 0x23524C(2).
- **Contorno**: marker [0x36A47E]=1 via 0x235A10 (dal claim wrapper 0x18B928 prima di 0x235A1C(2,idx)); [0x36A488] ha anche un gate di lettura in 0x2353C2 (pool 0x2353FC, dispatch logger 0x2C4C2C/0x2C4CF0); **pannello 0x2C5100 NON legge [+6]**: polla byte shadow 0x446808+4·idx via getter 0x16F920 (pool 0x2C519C; indici 8/9/0xA con loop until-zero) e poi impone 0x18B85C(1)/(9).

**Comandi/esiti.** `python3 Python_Trace_Scripts/s33_verify_lens_iris_completion.py` → **PASS_IRIS_COMPLETION_STATIC**, exit 0 (corse: 011103Z/011112Z pre-audit; **011924Z post-audit = evidenza valida**; conferma finale identica 011933Z). Nessuna asserzione indebolita. Correzioni di collaudo della prima stesura: `\b` dopo `]` rimosso ovunque (mai valido, lezione iterazione 21); `b_s` (non `b`) nel tail di 0x18B844; finestra epilogo wait estesa a 0x158E20; `bset_s r0,r0,0x15` (bit 0x15, non 0x25) nell'errore del post; **filtro census esteso alle forme `bl_s`/`bl_s.d`** (senza: census incompleti — 0x235ABC perdeva 0x235B28 e due chiamanti reali 0x18B968/0x18B980, 0x235AE4 perdeva 0x235AFA, 0x145F28 perdeva 0x146056); census 0x36A488 esteso al secondo pool 0x2353FC (gate, finestra dedicata); aggiunte finestre 0x18B954 (state-wait), 0x146044 (re-post wrapper, pool 0x146248=0x366ED0) e 0x14605C (cancel). Integrazioni post-audit (seconda stesura): asserzione `add_s r0,r0,0xc` in 0x158CBC (coordinate evento), finestra `state_minisetter_18b8d4` (getter 0x18B8D4 + mini-setter 0x18B8E0 di [0x367FEA], pool 0x18B8DC), precisazioni nel JSON (store [+6] dentro la seconda sezione critica; coordinate evento entry+0xC; 0x18B954 pre-guardie su rami distinti e wait=0 sul ramo idx≠stato). Verificatore: sha firmware + blocchi manifest; 25 pool raw LE; 31 finestre GNU allineate in `gnu_windows.txt`; modelli 65.536 valori (generazione, impulso GPIO, bit evento); census pool 7 celle (0x36A464=19 pool, 0x36A480/0x36A494/0x36A484/0x36A47E singoli, 0x36A482=4, 0x36A488=2) e census chiamanti 10 target (forme bl/bl.d/bl_s/bl_s.d).

**Revisione indipendente (agente iris-completion-audit, tools.agents.spawn, configurazione ereditata; atteso e integrato).** Ha riverificato byte-exact i punti 1–8 con finestre proprie e letture raw sha-verificate (nessun file scritto nel progetto; verificatore non rieseguito). Esito: **tutti i punti CONFERMATI**, tre precisazioni ACCOLTE: (2) la store [+6]=0 sta DENTRO la seconda sezione critica (prima dell'0x179354 a 0x235A04) e la `and -25` spegne anche i bit 0/1; il callback del completamento è a +0x3C, distinto dal +0x40 delle attuazioni; (5) 0x158CBC/0x158CE0 operano su entry+0xC: campo bit a entry+0x24, testa lista waiter a entry+0x14, registrazione waiter [event+0x2c] senza shift; (8) in 0x18B954 le due pre-guardie sono su rami distinti e il ramo idx≠stato inoltra la request con wait=0. Controprove CONFERMATE: (a) census dei 19 pool di 0x36A464 con finestra per sito → **gli unici accessi [+6] della famiglia sono tre scritture** (0x235946 Big=1, 0x2359A6 Small=1, 0x235A02 completion=0), nessun altro writer e **nessun lettore** via pool; (b) pool 0x36A480/0x36A488/0x36A47E esattamente quelli attesi, nessuna sede extra. Scoperte extra accolte: mini-setter 0x18B8E0/getter 0x18B8D4 di [0x367FEA] (scritture dello stato fuori da 0x18B85C), secondo referente della tabella evento 0x372A48 a 0x17B974, conferma indipendente delle regole ld_s/ld.as scalate. Lo strumento «task con agente explore» non esiste in questo ambiente; usato spawn come nelle iterazioni precedenti.

**Limiti.** Statico, nessun hardware/runtime, NON_INSTALLARE. **Chi esegue i callback differiti** (consumatore della tabella 0x4437F4, verosimilmente interrupt TIMER1) non identificato: la semantica «differito» poggia su layout slot + store handler + armamento timer, non su un chiamante provato. Blocco di 0x158D04 = modello runtime (registrazione waiter byte-verificata, scheduler no). Significato fisico dell'impulso or-0x18/attesa-500/and--25 = inferenza. Scrittore della shadow 0x446808 APERTO. Census periferici su listato lineare = candidati (siti della catena tutti in finestre dedicate). Caveat 0x2349C0 invariato. V1.1 campione vs macchina V1.0. Circa10% invariato.

**Prossimo passo (non ripetitivo).** (a) Identificare lo **scrittore della tabella shadow 0x446808** (chi copia lo stato iris nei byte che il pannello 0x2C5100 polla): ponte completamento→UI; (b) in alternativa il **consumatore della tabella slot 0x4437F4 / interrupt TIMER1** (chi esegue davvero i callback differiti). Entrambe offline e byte-verificabili. Il ramo obiettivo resta anche su: identità banco 0x0FE400xx (iterazione 19), sibling iris set/clear entrambi i bit, chiamanti fuori AE di 0x149530.

## Iterazione 21 — 22 ottobre 2026 — iris: attuazione GPIO diretta 0x0FF04024 bit3/bit4, chiusura negativa del «wrapper iris» (verificatore Iris_Actuation PASS post-audit)

**Domanda affrontata.** Il punto aperto più vecchio del ramo obiettivo, rinviato dalle iterazioni 1–19: quale dei 33 chiamanti della transazione 0x25F338 è il wrapper iris (BCIP_Aperture 0x9208, 1:Big 9:Small). Scelta del punto: è l'anello mancante del comando di apertura per il percorso fotografico (R0/R1) e chiude anche due affermazioni storiche superate.

**Risultato.** [Rapporto](S33_Iride_Attuazione_GPIO_0FF04024_e_Chiusura_Wrapper.md), [script](../Python_Trace_Scripts/s33_verify_lens_iris_actuation.py), [prove](../Risultati/Lens_MCU_Interface/Iris_Actuation/latest.json) (**evidenza valida 20261022T005922Z**, PASS exit 0 post-audit; la 20261022T005612Z della stessa sessione era la calibrazione pre-audit, cartella rimossa).
- **NEGATIVO strutturale: il wrapper iris NON esiste.** Zero `bl` dal blocco AE/iris 0x123000..0x126000 verso qualsiasi entry del cluster wire {0x25F338, 0x25CB54, 0x25CB3C, 0x25F6A4, 0x29DDD4, 0x25C4B4, 0x25C268, 0x25C3F8, 0x25C558, 0x25C1F0, 0x25C37C, 0x1EE148, 0x1EE730, 0x1ED11C, 0x25F3F4, 0x2606B4, 0x260C6C} (censimento asserito nel verificatore); l'agente ha ripetuto il negativo con BFS transitiva su 373 funzioni della chiusura AE: zero hit.
- **Catena byte-exact (payload0)**: AE 0x124D8A/0x124E04 (`mov r19,9; mov r0,9; bl 0x149530`), 0x124EEA (condizionale sotto `cmp_s r15,9`), log «Change Iris from MAX: %d To MIN: %d» (pool 0x124F64/0x124F6C → payload1 0x3860EE/0x38612C) → **0x149530(idx)** wrapper (push blink+r13, bl 0x18B85C, ritorna sempre 1) → **0x18B85C(idx)**: stato byte [0x367FE8+2], 0x235A1C(2,&h) [fallimento→corrente senza release], 0x235DA0() [fallimento→0x23524C(2)], fallimento request→0x18B9D4 → **0x235B0C(h,idx,1,0x3A98)**: PRE-GUARDIA 0x235B28 `bl_s 0x235ABC` (h vs [0x36A480], mismatch→0 senza attuare), sezione critica 0x1786E8/0x179354, busy 0x234F1C([[0x3EBD3C]+8]) (se occupato [0x36A482]=0x15), `cmp idx,0x9` → **0x235950 SMALL / 0x2358F4 BIG**: callback [0x36A464+0x40], `bclr bit0/bit1` di **0x0FEF0388**, RMW **0x0FF04024** `and -25`+`bset bit3`(Small)/`bit4`(Big), status [0x36A464+6]=1; poi contatore halfword [[0x36A464]+0x1c]++, evento 0x158CE0(1|1<<25,0x10), mailbox 0x145F28(0x36A494, 0x235AF8|0x235AE4, 0x3A98, 0), attesa finale 0x158D04(1|1<<25,0x10,1,0).
- **Encoding BCIP_Aperture SP2 1:Big/9:Small confermato all'attuazione**; pannello diagnostico 0x2C5100 («Iris status: Big/Small», payload1 0x406E89/0x406E9A) chiama 0x18B85C(1)/0x18B85C(9) e legge lo stato con il getter a indici 8/9/0xA.
- **CORREZIONI**: «nessun GPIO iris-specifico» del checkpoint diaframma/iride CONTRADDETTO (annotato nel suo §3); la freccia «AE/iris ──▶ hub OM» del rapporto contesti/API stato era INFERENZA (annotata nel suo §6).
- **Census**: 13 pool word LE 0x0FF04024 in payload0 (audit: scansione passo 1 byte, tutte 4-allineate), bit3/4 scritti SOLO dalla famiglia iris 0x234Dxx–0x235Dxx (set entrambi: 0x235438/0x2357C8/0x2359B0; pulisci entrambi: 0x235858/0x235BDC; caveat RMW a maschera registro 0x2349C0); 32 chiamanti 0x149530 (10 nel blocco AE), 21 di 0x18B85C, 2 di 0x235B0C, 1+1 dei percorsi.

**Comandi/esiti.** `python3 Python_Trace_Scripts/s33_verify_lens_iris_actuation.py` → PASS exit 0 tre volte: calibrazione 20261022T005612Z, **post-audit 20261022T005922Z (evidenza valida)** e conferma finale identica 20261022T010038Z (ultima cartella, `latest.json` punta qui). Correzioni di collaudo: offset decimali bl ai tre siti AE, regex `\b` dopo `]` rimossa, finestra Big estesa, `ld_s r15,[pcl,0x14]` nel percorso Small, classificazione pool su due finestre (testa + target del b_s), dettaglio `btst_s r0,0x1`. Integrazioni audit: pool 0x235AE0=0x36A480 + asserzione pre-guardia, prologo 0x149530 (`push_s r13`), pool 0x235868→fn 0x235858, rami di fallimento nel JSON. Nessuna asserzione indebolita. Agente `iris-actuation-audit` (tools.agents.spawn, configurazione ereditata; atteso e integrato): claim 1/5/7/8 CONFERMATI byte-exact, claim 2/3/4/6 confermati con precisazioni accolte; controprove richieste fatte (scansione passo byte, pool 0x124F64/0x124F6C letti ai siti). Lo strumento «task con agente explore» non esiste in questo ambiente; usato spawn come nelle iterazioni precedenti.

**Limiti.** Statico, nessun hardware/runtime, NON_INSTALLARE; semantica fisica dei bit3/4 di 0x0FF04024 e bit0/1 di 0x0FEF0388 = inferenza dal pattern RMW (non provata elettricamente; 0x0FF04024 ospita anche bit0 tasto logico 2 e bit7 lens-ready); RMW a maschera registro in 0x2349C0 può toccare bit3/4 a runtime; callback runtime `jl_s [r0]` e consumatori mailbox/evento non risolvibili staticamente; lato completamento NON verificato (chi azzera [0x36A464+6], handler 0x235AF8/0x235AE4, evento 0x10); census periferici su listato lineare con i siti chiave riverificati in finestre dedicate; V1.1 campione vs V1.0 macchina; circa10% invariato.

**Prossimo passo (non ripetitivo).** (a) Lato completamento della mossa iris: decodificare gli handler 0x235AF8/0x235AE4 e il consumatore dell'evento 0x10 per stabilire quando la mossa è finita (byte [0x36A464+6]: chi lo azzera) — serve al «ritorno pronto» del percorso fotografico; (b) in alternativa census dei 22 chiamanti di 0x149530 fuori dal blocco AE (0xDB46C..0x324A8C: script diagnostici, cattura, overlay) per attribuire gli altri impositori dell'indice iris. Entrambe offline e byte-verificabili. Il ramo Obiettivo resta anche su: identità banco 0x0FE400xx e chiamanti TBIB (iterazione 19).

## Iterazione 19 — 22 ottobre 2026 — banco 0x0FE400xx: census Main/TBIB e protocollo boot byte-exact (verificatore Bank_0FE400xx PASS post-audit; recupero della sessione 18 interrotta)

**Domanda affrontata.** Punto (b) dell'iterazione 14: identità e riferimenti del banco 0x0FE400xx, lo stesso dello scrittore Main 0x301EC0 (iterazione 8) e dell'arresto GNU DSPv5 in TBIB (0x4321→0x0FE40004 a 0x010091F8). La sessione precedente (round 18 del runner, interrotta per assenza di output) aveva già isolato i pool TBIB e la distinzione Main/TBIB nel solo reasoning; questa iterazione la porta a verificatore con asserzioni congelate. Nessuno script era stato lasciato dalla 18: il verificatore è nuovo.

**Risultato.** [Rapporto](S33_Obiettivo_Banco_0x0FE400xx_Census_Boot_e_Main.md), [script](../Python_Trace_Scripts/s33_verify_lens_bank_0fe400xx.py), [prove](../Risultati/Lens_MCU_Interface/Bank_0FE400xx/latest.json) (**evidenza valida 20261022T004729Z**, post-correzioni della revisione indipendente; 20261022T004653Z identica; le cartelle 003756Z/003835Z sono PASS PRE-audit con regex anti-limm vacua: il claim «zero limm» era vero — l'agente lo ha verificato con scansione raw ME — ma in quelle corse la prova dello script non scattava; la cartella 004544Z della corsa fallita con falso positivo `movl.cl 0xfe4` è stata rimossa perché vuota).
- **Census**: ogni word a passo 2 (LE + lettura halfword-scambiate limm-style) nei 16 payload verificati e nel corpo TBIB; classificazione contro i 17 listati GNU: riferimento REALE = load pcl (qualsiasi forma `ld*`) con commento `;0xSITE`; i commenti di branch non contano; filtro displacement ld_s ≤ 0x7C (il falso positivo payload10 0x1025734 `[pcl,0x154]` è dentro una regione dati).
- **Zero limm/movhi verso il banco** nei 17 listati (scansione immediati canonici completi 0xfe4xxxx + decimali nel range + movhi con operando 0xfe4; NB: `movl.cl r8,0xfe4` a payload10 0xFFA57E NON è un riferimento: carica la costante 16 bit 0xFE4).
- **Main**: SOLO i 4 pool del corpo 0x301EC0 (0x301EC8/0x301EDC lineari; 0x301EF0/0x301F04 nascosti dal pool dopo il `b_s`, provati con finestre allineate W3/W4/W5); unico altro pool load-referenziato = 0x26FF8C con valore LE 0x00270FE4 (coincidenza ME); **payload 1..15 zero riferimenti reali; NESSUN reader Main del banco**. Corpo 0x301EC0 completo: 0x4321→0x0FE40004, 0x6641→+08, 0xE972→+0C, 0xFFFF→+10, idioma identico al boot.
- **TBIB**: 74 siti, **37 pool reali** (36 lineari + 0x1009214 da finestra allineata) su **17 registri** +00/+04/+08/+0C/+10/+18..+34/+40..+4C, **+0x14 MAI riferito**; uniche letture = RMW `ldh.di` su +0x00; poll su **bit0 di 0x0FFCA008** (pool 0x1000D28/0x10014A8/0x1000D94, poll a 0x1000D74/0x1000F84/0x10016F8), stessa linea ausiliaria della porta obiettivo.
- **Routine 0x10091E4 decodificata**: +04=0x4321 (l'arresto GNU DSPv5 0x10091F8 è il PRIMO store), +08/+0C/+10=0xFFFF, +18..+24=0, +28=2, +2C=0x100, +30/+34=0, tail 0x103E158 → piano GNU «routine 0x10091E4 senza azzeramenti indiscriminati» **sbloccato offline**.
- **Compositori** 0x100929C→+08 / 0x10092D8→+0C: pacchetto ((r0<<13)&0xE000)|((r1<<8)&0x1F00)|((r2<<4)&0xF0)|(r3&0xF); i valori Main 0x6641/0xE972 sono dello stesso formato.
- **Strobe** su +00 (0x1000CF2/0x1001472): bset9+bset8+bclr9 (net 0x100); variante 0x1000FF6: bset9+bclr8. **Init A** (0x1000EEC..0x1000FEA, copia 0x100167C, variante C 0x1001710): +40=0x2020, +44=0xF80, +48=0x300, +4C=r16, +00=0xA poi 0x20A, RMW 0x0FE80070/74, poll, +40/+48=0x216F, +44/+4C=0x3F, 1→0x0FFCA008. NB strumentale: i value pool si leggono word LE dai byte raw (0x1000FA8 = 0x0000216F, non 0x6F21: errore corretto durante il collaudo).
- **Identità**: DDR ESCLUSO (registri BFN a 0x0FE2xxxx); identità siliconica APERTA (inferenza della revisione: blocco controllo sistema/clock-PLL/power; nessun datasheet SD10P220).

**Comandi/esiti.** `python3 Python_Trace_Scripts/s33_verify_lens_bank_0fe400xx.py` → PASS exit 0 più volte: 003756Z/003835Z (pre-audit), 004653Z/004729Z (**post-audit, evidenza valida**). Correzioni di collaudo della prima stesura: import coolpix-s33-re per s33_extract, sha→hashlib, LOAD_LINE keyed sul target del commento (non sull'indirizzo del load), attese lineari vs finestre allineate (0x301F0C, 0x100920C), value pool 0x216F. Correzioni dell'audit: regex anti-limm (vacua: objdump stampa `0xfe40004` senza zero iniziale e decimali), LOAD_LINE estesa a tutte le forme load pcl (`ld.as`/`ldb.di`), pool 0x1000D94 del poll init A, rimosso loop morto. Agente `bank-0fe400xx-audit` (tools.agents.spawn, configurazione ereditata; «task con agente explore» non esiste in questo ambiente): census rifatto da zero in /tmp, punti 1–7 CONFERMATI, tre precisazioni accolte. Lo strumento task/explore resta non disponibile: usato spawn come nelle iterazioni precedenti.

**Limiti.** Statico; nessun runtime/emulazione/hardware. Il negativo «nessun reader Main» non copre letture calcolate/DMA/alias. Siti LE «instr» di payload0 e analoghi non esclusi come pool nascosti con finestre allineate esaustive (solo i 3 casi noti): rischio residuo basso. Tratto TBIB 0x1000D84..0x1000EEC decodificato in modo inaffidabile nel lineare (r14 controllato solo su quel decode). r16 runtime, semantica dei bit strobe/ready e identità del banco = inferenza. V1.1 campione locale vs macchina V1.0. Circa10% invariato, NON_INSTALLARE.

**Prossimo passo (non ripetitivo).** Due opzioni: (1) GNU offline — integrare la sequenza 0x10091E4 nel profilo DSP (scritture halfword al banco modellate) e vedere fino a quale PC procede il TBIB; (2) statico — censire i chiamanti TBIB delle routine del banco (0x10091E4, sequenza A) per collegare l'init alla sequenza di boot e restringere l'identità. In alternativa il ramo obiettivo resta su: wrapper iris fra i 33 chiamanti di 0x25F338.

## Iterazione 16 — 22 ottobre 2026 — 0x2E5658, il post-helper della chiusura: funzione vuota byte-exact (nullsub) con census di 14 siti (verificatore Close_Helper PASS; sessione ripresa dopo limite turni)

NB numerazione: il runner dell'utente conta questa come iterazione 16; nel file non esistono voci 13 né 15 (sessioni interrotte o non registrate). L'ultima voce precedente è la 14.

**Domanda affrontata.** Punto (a) aperto dall'iterazione 14 ([Sender porta](S33_Obiettivo_Sender_Porta_0x0FF05000_Gate_Strobe.md)): byte-decodificare 0x2E5658, il target del `bl.d` finale del close helper 0x25CAF4 (delay slot `mov_s r0,0x1`, subito dopo il GATE SET), e il suo rapporto col gate appena riarmato.

**Risultato.** [Rapporto](S33_Obiettivo_Helper_0x2E5658_Post_Chiusura_Funzione_Vuota.md), [script](../Python_Trace_Scripts/s33_verify_lens_close_helper.py), [prove](../Risultati/Lens_MCU_Interface/Close_Helper/latest.json) (evidenza valida 20261022T001835Z: 18 finestre GNU dedicate — corpo, close helper, forwarder, bit7-ctxA e i 14 siti ciascuno allineato sul sito, senza straddle — + census dal decode lineare GNU del payload0 + modello effetto netto; la cartella 20261022T001634Z è la prima esecuzione pre-correzioni della stessa sessione).
- **0x2E5658 è una funzione vuota (nullsub)**: 20 byte (0x2E5658..0x2E566B), `st.aw fp,[sp,-4]` (word 0xB6C81CFC — prologo frame GCC stock, 6033 occorrenze della stessa word in payload0) + `mov fp,sp` + `mov sp,fp` + `ld.ab fp,[sp,4]` + `j_s [blink]` + `nop_s`. Prologo seguito subito dall'epilogo, NESSUN corpo: nessuna chiamata, nessun pool pcl, nessun MMIO, `r0` mai letto, foglia (no push blink). Effetto netto (modello): sp/fp ripristinati, r0 restituito invariato, unica scrittura scratch mem[sp-4]:=fp sotto uno sp fermo.
- **Censimento completo**: esattamente 14 siti `bl.d ;0x2e5658` nel payload0 (0x25CB02 nel close 0x25CAF4; 0x25D3D2/0x25D3F6 in 0x25D3AC; 0x2606CC/0x2607CC/0x26092A/0x260A18/0x260B0E/0x260B8C/0x260DF4/0x260E1A/0x260EE6/0x260F20 nel cluster 0x2606B4–0x260EBC; 0x29DDE0 in 0x29DDD4), tutti riverificati in finestra dedicata; nessun bl semplice, nessuna entry b/b.d, ZERO word LE e ZERO limm middle-endian a 0x2E5658 in tutti i 16 payload (convenzione limm validata dall'agente sull'esempio 0x29E846 `50 00 40 e9` = 0x0050E940).
- **Semantica**: il ritorno non è mai consumato (nessun cmp/tst su r0 dopo la chiamata; nota della revisione: in 13/14 siti il valore di r0 al ritorno deriva dal delay slot del chiamante stesso); 8/14 siti chiamano 0x2E5658 subito prima di GATE CLEAR (0x25DEAC) + sender 0x25CB3C (apertura di una NUOVA transazione), nel close helper la chiamata segue il gate-set finale: **marcatore di confine transazione senza effetto runtime in V1.1**. La chiamata `0x2E5658(1)` del close NON fa nulla: l'ultima azione reale della chiusura resta il GATE SET. L'ipotesi «0x2E5658 possibile lock/claim» dell'iterazione 1 è CONTRADDETTA dai byte.
- **Contesto bit7**: 0x25D3AC (chiamante) setta il bit 7 della halfword ctxA[+2] (0x50F52E) a 0x25D402..0x25D406 (`ld_s r1,[sp,0]` = ctxA via 0x25CAEC → `ldw_s/stw_s r0,[r1,0x2]` con `bset_s 7`): secondo ancore byte-verificato del busy bit letto dalla guardia 0x25CFE4 di 0x1EDED8 (errore 0x1B00001) — il ciclo busy ha ora scrittore e lettore entrambi byte-exact.
- **Separazione**: 0x2E5658 è funzione distinta dal forwarder dati 0x2E5648 (push blink → 0x334130 → 0x3042A8 → tail 0x33419C); l'etichetta «DataTransferForwarder» della finestra (0x2E5648,0x2E5658) del rapporto SD transfer copriva solo 0x2E5648.

**Comandi/esiti.** `python3 Python_Trace_Scripts/s33_verify_lens_close_helper.py` → PASS exit 0 due volte (prima stesura, evidenza 20261022T001634Z; e post-correzioni della revisione, **evidenza valida 20261022T001835Z**). Calibrazioni della prima stesura: regex `\t`→`\s+` per la helper `has` che appiattisce gli spazi; ancore per-sito ristrutturate sulle righe istruzione della finestra dedicata (il primo consumatore dopo il delay slot non sta a offset fisso); pattern di assenza ancorati al campo mnemonico (`\tbl\b` ecc.) per non catturare «blink». Correzioni successive della revisione: dimensione corpo 20 byte (non 18), sfumatura r0 (delay slot del chiamante) ora asserita nell'evidenza. Lo strumento «task con agente explore» richiesto non esiste in questo ambiente; usato tools.agents.spawn come nelle iterazioni precedenti.

**Fonti precise.** Payload0 (base 0x0AD800, blocco sha-verificato del manifest): 0x2E5658..0x2E566B corpo; 0x25CAF4..0x25CB0A close; 0x2E5648..0x2E5656 forwarder; 0x25D3AC..0x25D406 bit7; i 14 siti elencati sopra; decode lineare GNU del solo payload0 per il census (`objdump_text`), finestre dedicate per ogni sito. Semantica ISA: st.a pre-decremento con writeback, ld.ab post-incremento, delay slot D di j_s/bl.d.

**Limiti.** Statico, nessun hardware, NON_INSTALLARE; il corpo vuoto è byte-verificato in V1.1 (build diverse non dimostrabili da questo campione); lo scopo originale del nullsub (hook/trace compilato via) è inferenza; le funzioni contenenti i siti 0x2608A8–0x260EBC sono attribuite per ingresso (push_s blink) senza decodifica completa; valori runtime di r13/r14 non derivabili; riferimenti calcolati per via aritmetica a 0x2E5658 invisibili staticamente; V1.1 vs V1.0; circa10% invariato.

**Prossimo passo (non ripetitivo).** (a) Punto (b) dell'iterazione 14: censimento dei lettori/scrittori Main del banco 0x0FE400xx partendo da 0x301EC0 (0x4321→0x0FE40004, 0x6641→0x0FE40008, 0xE972→0x0FE4000C, 0xFFFF→0x0FE40010) e dall'arresto GNU DSPv5 in TBIB (0x4321→0x0FE40004 a 0x010091F8), per circoscrivere l'identità della periferica; (b) in alternativa, aggancio del wrapper iris fra i 33 chiamanti di 0x25F338 leggendo il byte [ctrl+1] scritto prima di ogni chiamata e confrontandolo col dizionario {00,10,30,50,60,70,80,D0,FF}. Entrambe offline e byte-verificabili.

**Revisione indipendente (agente close-helper-audit, tools.agents.spawn, configurazione ereditata; atteso e integrato).** Ha riesaminato i byte raw con finestre dedicate, senza eseguire il verificatore né scrivere file. Esito: **claim 1–5 CONFERMATI** (corpo, bl.d 0x25CB02 con delay slot, census 14/14 senza artefatti + zero riferimenti LE/middle-endian su 16 payload, modello di effetto netto con st.a/ld.ab confermati, separazione da 0x2E5648). Correzioni accolte: dimensione corpo 20 byte (0x2E566C−0x2E5658), sfumatura r0-delay-slot (13/14 siti; 0x26092A non tocca r0 nel delay slot). Non verificato dall'agente: esecuzione CPU reale, riferimenti costruiti aritmeticamente, contesto transazione dei singoli siti, identità del campione via firmware.bin (usa i blocchi sha del manifest).

## Iterazione 14 — 22 ottobre 2026 — sender porta obiettivo byte-exact: primitive 0x0FF05000, gate, strobe e sender 0x25CB3C/0x25CB54 (verificatore Port_Sender PASS; sessione ripresa dopo limite turni)

**Domanda affrontata.** Punto aperto (a) dell'iterazione 12 ([Split paths](S33_Obiettivo_Split_1EDED8_1EDFDC_Byte_Wire.md)): byte-decodificare il sender 0x25CB3C/0x25DF24/0x25E064 fino alla sequenza di halfword sulla porta 0x0FF05000 e al gate/strobe, chiudendo i residui 0x25DFxx/0x25DExx e il qualificatore della store di porta.

**Risultato.** [Rapporto](S33_Obiettivo_Sender_Porta_0x0FF05000_Gate_Strobe.md), [script](../Python_Trace_Scripts/s33_verify_lens_port_sender.py), [prove](../Risultati/Lens_MCU_Interface/Port_Sender/latest.json) (24 finestre GNU allineate, incluse finestre dedicate sull'istruzione di accesso perché il pool pcl inghiotte la store nella finestra lineare; 18 pool + 9 word raw + 17 risoluzioni ld_s letti dai byte raw del payload0; modelli Python su tutti i 65.536 valori del registro strobe). La catena dizionario→porta è ora interamente byte-exact:
- **Qualificatore di porta CHIUSO**: 0x25E064/0x25E078/0x25E0A4 = tre corpi identici `sth.di r0,[0x0FF05000]` (word raw 0x00241900; halfword .di dei 16 bit bassi di r0; pool 0x25E06C/0x25E080/0x25E0AC = 0x0FF05000 raw). **0x25E08C = `ldh.di` + `extb_s` nel delay slot del ritorno: ritorna SOLO il byte basso zero-extended** → il wire è un payload a 8 bit sul byte basso della porta a 16 bit.
- 0x25E0B8 = bit7 di 0x0FF04024 (ldh.di+lsr7+bmsk0 nel delay slot); 0x25E0D0 = getter della costante 0x0FF05000; 0x25E0D4(sel) = set/clear bit0 di 0x0FFCA008 (r0==1→clear).
- **Gate**: 0x25DEAC pulisce e 0x25DEE8 setta bit4 di 0x0FEF03A8 + bit6 di 0x0FF04034 (RMW halfword .di con bit da `mov r0,4/6`; pool 0x25DEB8/0x25DED0/0x25DEF4/0x25DF0C), avvolti dalla **coppia di sezione critica 0x1786E8/0x179354** (r1=[0x369348] pool 0x178718, contatore annidamento [[r1+0x1c]+0x68], `flag` di status32 salvato [r1+0x16] e ripristinato via ld.as [r1+141]→[r1+564]; il nome della coppia è inferenza).
- **Strobe su 0x0FF04020**: `and -769` (0xFCFF, pulisce bit8/9) + `bset 9`|niente|`bset 8`|niente → 0x25DF24 bit9 / 0x25DF4C clear / 0x25DF74 bit8 / 0x25DF9C clear; mutuamente esclusivi per costruzione su tutti i 65.536 valori (modello).
- **Sender byte 0x25CB3C(byte)**: strobe bit9 → 0x25E064(byte) → strobe clear (byte via r13 nei due delay slot). **Attenzione 0x25CB0C**: strobe bit9 → porta 0xFF → clear → poll bit7 fino 0xF4240 → close helper **0x25CAF4 = doppio strobe clear + GATE SET (0x25DEE8) + 0x2E5658(1)**: pattern gate-clear a apertura transazione / gate-set a chiusura.
- **Sender descrittore 0x25CB54(desc)**: r15=0x50F514 (pool 0x25CEC8), r14=0x25E078 (pool 0x25CECC); r16=(desc[1]+r57)&0xFFFF con r57 composto da DUE muludw (muludw(h(0x50F532)=ctxA[+6], desc[0]) → desc[+2]+r57 → extw_s → muludw(byte(0x50F531)=**ctxA[+5] cmd**, ·)) sotto ipotesi MULUDW condizionale; strobe bit8 (extw r16 nel delay); pacchetto un byte alla volta via jl_s.d [r14]: [0x00 extra sse bit0xA di h(0x50F52E)] + 0x00 + lo8(r16) + hi8(r16) + [desc[0] sse bit8 di h(0x50F52E)]; clear 0x25DF9C finale. NB lettura: bit0xA set → DUE 0x00 consecutivi, clear → uno solo.
- Pack3 0x25CBBC confermato logger posizione (out[0]=v, out[1]=v>>8, out[2]=(v>>14)|3).

**Comandi/esiti.** `python3 Python_Trace_Scripts/s33_verify_lens_port_sender.py` → PASS exit 0 tre volte (calibrazione, conferma integrità helper dopo l'agente, e post-correzione della polarità claim 10: **evidenza finale valida 20261022T001031Z**; le cartelle precedenti 20261022T0003xx–0007xx sono calibrazioni/pre-correzione della stessa sessione, nessuna è l'evidenza citata). Calibrazioni corrette durante il collaudo: word raw sth.di = 0x00241900 (ordine byte dei chunk objdump), pool gate_set 0x25DEF4/0x25DF0C aggiunti, finestre dedicate allineate sull'istruzione di accesso (0x25E070/0x25E084/0x25E0B0/0x25E098) perché il pool inghiotte la store, offset bset strobe lo+24, modello pacchetto (due asserzioni iniziali sbagliate riscritte). Lo strumento «task con agente explore» richiesto non esiste in questo ambiente; usato tools.agents.spawn/send_message come nelle iterazioni precedenti. Agente `port-sender-audit` (configurazione ereditata): verdetto integrato (vedi voce Revisione indipendente).

**Scoperta laterale dell'agente, verificata dal coordinatore con sha256.** Il campo `offset` di [S33-sections/TBM_blocks/manifest.json](../S33-sections/TBM_blocks/manifest.json) NON punta al contenuto in firmware.bin: il blocco 0 reale sta a **file offset 0x482b8** (slice [0x482b8,+0x2AE400) di OriginalSoftware_NikonS33_V1.1/firmware.bin sha-identica al file blocco 06754a1f…, mentre la slice a offset 512 NON combacia). L'agente aveva annunciato l'intenzione di «correggere l'helper»: VIETATO e non necessario — `verified_payloads` legge i file blocco separati, verifica size+sha256 e usa `load_address_candidate` (0xAD800) come base; il campo `offset` non è usato dalla pipeline (verificato con rg sul sorgente). Nessun file helper/manifest è stato modificato (mtime intatti + verificatore rieseguito PASS). Nota conservata qui e in AGENTS.md come caveat del manifest, non come difetto della pipeline.

**Limiti.** Statico, nessun hardware, NON_INSTALLARE; r57 del sender descrittore passa per due muludw (ipotesi MULUDW condizionale, CPU non provata); runtime (desc, ctxA[+5]/[+6], flag 0x50F52E, contatore sezione critica) non derivabile staticamente; 0x2E5658 cross-riferito per call site; semantica MCU di gate/strobe/bit7 = inferenza dal pattern RMW; naming coppia 0x1786E8/0x179354 = inferenza; corpi 0x25E10C/0x25E140 (banco 0x0FFCA00x) contesto non asserito; V1.1 vs V1.0; circa10% invariato.

**Prossimo passo (non ripetitivo).** (a) Byte-decodificare 0x2E5658 (post-helper della chiusura attenzione/transazione, unico anello mancante della coda 0x25CAF4) e il suo rapporto col gate appena riarmato; (b) in alternativa, censimento lettori/scrittori Main del banco 0x0FE400xx partendo da 0x301EC0 (identità periferica, aperto dall'iterazione 8). Entrambe offline e byte-verificabili.

**Revisione indipendente (agente port-sender-audit).** Tre turni (il primo interrotto dal limite turni sulla scoperta laterale del manifest, il secondo di chiarimento, il terzo di verdetto). Esito: **claim 1–9 CONFERMATI** (primitive porta/qualificatore, lettura solo-byte-basso, gate, strobe, sender byte, attenzione+close, sender descrittore, pack3); **claim 10 CONFERMATO CON UNA CORREZIONE ACCOLTA**: la polarità dello store del caller-PC era invertita — il blink va a `[struct+0x1c]+208` **solo se `[r1+0x18]==0`** (il `bne_s` a 0x17870C salta lo store quando ≠0). Corretti rapporto §6, evidenza del verificatore e aggiunte asserzioni che inchiodano la polarità (ldw/cmp/bne_s/st): **evidenza valida finale 20261022T001031Z** (le cartelle 0003xx–0007xx sono calibrazioni/pre-correzione della stessa sessione). Nota minore accolta: l'exit 0x179354 usa limm assoluto, il pool 0x178718 appartiene solo all'enter. Semantica dei delay slot (D/ND) assunta dall'agente dal manuale ISA ARCompact locale. Non verificato dall'agente: corpi 0x2E5658 e thunk millicode (destinazioni confermate), runtime r57/flag, semantica fisica MMIO.

## Iterazione 12 — 22 ottobre 2026 — percorso split 0x1EDED8/0x1EDFDC fino ai byte wire (verificatore Split_Paths PASS; sessione ripresa dopo limite turni)

**Domanda affrontata.** Punto aperto (a) dell'iterazione 11 ([Switch consumatore](S33_Obiettivo_Switch_Consumatore_Campi_Comandi.md)): byte-verificare 0x1EDED8/0x1EDFDC fino ai comandi wire del dizionario {00,10,30,50,60,70,80,D0,FF}. Apertura della sessione: recupero dell'iterazione 11 interrotta (rapporto/script/evidenze/roadmap/percorsi/Stato/AGENTS/mappa erano già scritti; mancava solo la voce in questo checkpoint, aggiunta col verificatore Switch_Consumer rieseguito PASS, evidenza 20261021T234156Z).

**Risultato.** [Rapporto](S33_Obiettivo_Split_1EDED8_1EDFDC_Byte_Wire.md), [script](../Python_Trace_Scripts/s33_verify_lens_split_paths.py), [prove](../Risultati/Lens_MCU_Interface/Split_Paths/latest.json) (19 finestre GNU allineate salvate come window_*.txt; 46 pool letti dai byte raw; 3 costanti ld.as a scala verificata; modelli Python su 65.536 valori). Il tratto split raggiunge il wire:
- **Dispatch split 0x1EE958 byte-exact**: casi 1..6 → 0x1EDED8(cmd·cum+arg2, chunks, r15, 0); caso 0 (richiede arg2==0) → ctxB[0xB4..0xC0]=4 word di arg1 → 0x1EDFDC(0, chunks, ptr, 0) → ctxB[0xAC]≤0x50 (sennò 0x1B00113) → hub 0x1EE148(0,0); 4 word tutte zero → ctxB[0xAC]=0 e uscita 0x1B00116.
- **0x1EDED8**: guardia busy = bit7 di h(0x50F52E) (0x25CFE4) → 0x1B00001; ready 0x25C800=(ctrl[+1]==0) / 0x25C80C=(ctrl[+1]==ctxA[+5]-1); coda 0x1EDC9C con retry 0x1B0000A×2 → 0x1B00009; passo 0x1EDD08 = 0x2606B4(off, 0x50E940, ctrl, extra) + query 0x260C6C; loop chunk r13 += ctxA[+0x10]<<9, finale 0x1EDE7C.
- **0x1EDFDC per passo**: gate bit0xA → record writer 0x25C1F0/0x25C37C (r19=4/2); bound di indice r13 < ctxB[0xD2]+r19 sennò 0x1B00108; passo = ctxB[8+2·r13] (0x1B0010A se zero); 0x25F6A4(0x50E940,ctrl) [0x50] + 0x25F28C [0x00/0xFF] + validatore 0x25CBF0 [byte+5==0xF0, 0x55/0xAA a +1/+2/+6/+7] + 0x29DDD4(ctrl) [0x60/0xD0] + 0x260C6C [0x70] + attesa 0x1EDC10 + LUT h(0x50E9C0+2·h(ctrl+4))=passo + 0x25CE18 [0xFF×count×16] + 0x25CF10 [posizioni 0x1000+2·cum pari, +6/+7/+0xB/+0xC, 0xFF a +4/+5] + bulk 0x2606B4(((cmd·r18+h(ctrl+1))<<9)·count+r16, 0x50E940, ctrl, 0) [0x80 + sender 0x25CB54, slot 512B a base+(slot<<9)] → 0x1B0000A.
- **Byte dizionario iniettati (byte-verified)**: 0x70 a 0x25CFC4 e 0x260C78 via 0x25CB3C→0x25E064 (porta, errore 0x1B00007); 0x80 a 0x2606DA; 0xF0 pattern a slot+5 (0x25CF6C); 0xFF fill (0x25CE18, 0x13A954(0x50D940,0xFF,count<<9), invalidazione slot 0x2606B4); 0x55/0xAA marcatori risposta. Transazione passo 0x1EDB48 = 0x25F338(0x50D940, 0x50E980, 0x36B254, 0) retry×2 con 0x25CBD0/0x25CCA0/0x25CCFC (0x29DEEC via registro); 0x2607B4+0x260C6C; codici 0x1B00010/0x1B0000F. Nuove celle: 0x50D940, 0x50E980, 0x50E9C0 (LUT condivisa col ramo NAND), mirror 0x36B24C/0x36B250↔0x3692E8/EA, 0x3F668C, tabelle 0x50F514/0x50F520.

**CORREZIONE (dalla revisione indipendente).** La «finestra accettata arg2<cmd·param<arg2+chunks» delle iterazioni 9–11 era INVERTITA: con la semantica ARC700 (C=1 su borrow; binutils bhs=F_NOTCARRY, blo/bnc=F_CARRY) `bhs_s` a 0x1EE974 accetta quando cmd·param ≥ arg2+chunks e 0x1B00116 scatta per arg2<cmd·param<arg2+chunks. Corretti: rapporto iterazione 11 §5, la sua §9 (agente switch-consumer-audit mai restituito; revisione rifatta qui), roadmap/percorsi/Stato/AGENTS. Semantica ARC consolidata: ADD1 = b+(c<<1); SUB/CMP C=1 su borrow; bnc≡bhs.

**Comandi/esiti.** `python3 Python_Trace_Scripts/s33_verify_lens_switch_consumer.py` → PASS exit 0 (recupero iterazione 11, evidenza 20261021T234156Z). `python3 Python_Trace_Scripts/s33_verify_lens_split_paths.py` → PASS exit 0 dopo calibrazione dei pattern objdump (offset 0 senza 0x, bl con target decimale+;hex, finestra dedicata per 0x1EE9C4 inghiottita dal junk del pool) e le correzioni della revisione (evidenza valida 20261022T000020Z, esecuzione finale post-correzioni; le cartelle precedenti sono le esecuzioni di calibrazione fallite, nessuna evidenza). Agente `split-paths-audit` (tools.agents.spawn, configurazione ereditata): primo turno interrotto dal limite turni, verdetto richiesto con send_message e integrato (rapporto §10). Lo strumento «task con agente explore» richiesto non esiste in questo ambiente; usato spawn/send_message come nelle iterazioni precedenti.

**Limiti.** Statico, nessun hardware, NON_INSTALLARE; MULUDW = ipotesi condizionale; runtime di cmd/count/flag/stato/mirror/LUT non derivabile staticamente; la base di 0x2606B4 nel caso 0 somma il valore del puntatore alle 4 word di arg1 (senso fisico aperto); il qualificatore della store di porta (halfword .di vs word) resta da decodificare; corpi 0x29DEEC/0x260624/0x260678/0x260698/0x2607B4/0x2608A8/0x260AD0/0x25DFxx/0x29DE80 e sito 0x25CCA0 (add1 r13,r14,r14) non decodificati; semantica 0x50/0x60/0xD0/0x00 cross-reference dell'iterazione Contesti; V1.1 vs V1.0; circa10% invariato.

**Prossimo passo (non ripetitivo).** (a) Byte-decodificare il sender 0x25CB3C/0x25DF24/0x25E064 fino alla sequenza di halfword sulla porta 0x0FF05000 e al gate/strobe (chiude 0x25DFxx e il qualificatore .di); (b) in alternativa, lettori/scrittori Main del banco 0x0FE400xx partendo da 0x301EC0 (identità periferica, aperto dall'iterazione 8).

## Iterazione 11 — 22 ottobre 2026 — switch 0x1EE730 consumatore dei campi comando, split in chunk e copia risposta→ctxB (recuperata dall'iterazione 12; verificatore Switch_Consumer PASS)

**Recupero.** La sessione dell'iterazione 11 è stata interrotta per assenza di output dopo aver già scritti rapporto, script, evidenze (10 timestamp 20261021T2332xx-2334xx), roadmap, percorsi, Stato_progetto, AGENTS e mappa_ram; mancava solo la voce in questo checkpoint. Il verificatore `s33_verify_lens_switch_consumer.py` è stato RIESEGUITO in questa sessione (iterazione 12): PASS exit 0, evidenza 20261021T234156Z. La §9 del rapporto (revisione agente) è rimasta in sospeso: l'agente `switch-consumer-audit` dell'iterazione 11 non ha mai restituito output; la revisione indipendente è stata rifatta dall'iterazione 12 (vedi voce Iterazione 12).

**Risultato.** [Rapporto](S33_Obiettivo_Switch_Consumatore_Campi_Comandi.md), [script](../Python_Trace_Scripts/s33_verify_lens_switch_consumer.py), [prove](../Risultati/Lens_MCU_Interface/Switch_Consumer/latest.json) (38 finestre GNU allineate + 3 jump table dai byte raw + modelli Python). Sintesi: i 7 casi dello switch 0x1EE730 accoppiano i cumulativi ctxB[0xC4..0xD0] e i parametri [0xD2..0xDE] con cmd(=ctxA[+5])·campo (muludw); budget → split 0x1EE958 con chunks=ceil(arg3/(ctxA[+0x10]<<9)) e finestra arg2<cmd·param<arg2+chunks; caso 0 → ctxB[0xB4..0xC0] + 0x1EDFDC + ctxB[0xAC]≤0x50 + hub 0x1EE148; casi 1..6 → 0x1EDED8(cmd·cum+arg2, chunks, arg1, 0). Bit0xA set → transazione 0x25F338(0x54D8A8,0x50E940,{0,4,0}) + copia 244 byte da 0x54DAB2 (record di risposta) DENTRO ctxB 0x50F420 + seconda dispatch fase 2 (jt a 0x1EE852). Gemello query 0x1ED11C (jt a 0x1ED17C, output [arg4]). Chiamanti switch su payload0 = 10 siti (wrapper 0x1EEA4C, 0x261104/0x2611A6, 7 siti orchestratore 0x29E9C4 con budget ricomposto 3+p1+2p2+2p3+p4+p5 ≤ ctxA[+8] e r21=(cmd<<9)·ctxA[+0x10]). Millicode 0x334120/0x334104 salvataggi, 0x3342A8 = moltiplicazione 32×32 GCC.

**Limiti.** Statico; MULUDW = ipotesi condizionale; runtime cmd/budget/count/bit0xA non derivabili staticamente; aritmetica frame 0x29E9C4 non del tutto risolta; NON_INSTALLARE; circa10% invariato.

**Prossimo passo.** Byte-verificare 0x1EDED8/0x1EDFDC fino ai byte wire del dizionario {00,10,30,50,60,70,80,D0,FF}; alternativa: lettori/scrittori Main del banco 0x0FE400xx.

## Iterazione 9 — 22 ottobre 2026 — intake comando 0x25C038: campi comando ctxB 0x50F420, magic «P1IDSTR», add2 ×4 (verificatore Cmd_Intake PASS)

**Domanda affrontata.** Punto aperto 10 dell'iterazione 8 ([Semantica record 22 byte e 0x301EC0](S33_Obiettivo_Semantica_Record_Orchestratore.md)): byte-verificare 0x25C038, l'intake candidato del blocco argomenti a 6 word nei campi comando del contesto. Apertura della sessione: recupero dello stato dell'iterazione 8 interrotta (rapporto, roadmap, percorsi, Stato_progetto, AGENTS, mappa e checkpoint erano già scritti; l'agente `orch-args-audit` dell'iterazione 8 non ha mai restituito output e la sua revisione resta non integrata; i claim chiave dell'iterazione 8 erano comunque coperti dagli assert byte-exact del verificatore Orchestrator_Args, rieseguito PASS in quell'ambito — non rieseguito qui perché non toccato dalle modifiche).

**Risultato.** [Rapporto](S33_Obiettivo_Intake_Comando_0x25C038_P1IDSTR.md), [script](../Python_Trace_Scripts/s33_verify_lens_cmd_intake.py), [prove](../Risultati/Lens_MCU_Interface/Cmd_Intake/latest.json) (4 finestre GNU allineate; ~150 siti di istruzione verificati per indirizzo; regola (raw&0x1f)*2 sugli offset ldw_s/stw_s; modello Python delle due varianti con wraparound 16 bit).
- **Correzione dell'iterazione 8: l'intake riceve ctxB, non ctxA.** In 0x29E680 il delay slot del `bl.d 0x25c038` carica `ld_s r0,[sp,0]`, e [sp,0] è riempito dal resolver stub 0x25C020 (pool 0x25C3A0 = 0x50F420); ctxA 0x50F52C va a [sp+4] via 0x25CAEC (pool 0x25CEC4). Entrambi i resolver sono stub a 3 istruzioni con lo store nel delay slot di `j_s.d [blink]`. CHIUSURA con l'iterazione 2: i parametri halfword 0xD2..0xDE letti dallo switch 0x1EE730/0x16F41C in 0x50F420 sono scritti da 0x25C038 — il collegamento statico argomenti → contesti → dispatch è chiuso.
- **Mappa halfword blocco→ctxB** (ldw_s = load halfword; offset stampato = (raw&0x1f)*2, verificato per ogni sito): +0/+2/+4→0xAE/0xB0/0xB2; +6→0xD2; +8→0xD4 E 0xD6; +0xA→0xD8 E 0xDA; +0xC→0xDC; +0xE→0xDE; +0x10/+0x12→0xE8/0xEA; **a5 (+0x14) mai letta**. I cinque parametri p1..p5 (offset 6..14) sono le stesse halfword che 0x29E8F0 scala con ceil(h/8) sullo stesso flag.
- **Bound:** 4+p1+2·p2+2·p3+p4+p5+10 ≤ ctxA[+8] (unsigned, bls_s); i due `add1_s r1,r1,r0` a 0x25C054/0x25C058 valgono b+(c<<1) e RADDOPPIANO p2/p3 (bound = 0xC4_clear + p1 + 14; coerente col totale clear 0xC4=2p2+2p3+p4+p5). Violazione → ritorno 0x1B00106 (pool 0x25C3A4) via coda 0x25C1E8. NOTA: la prima stesura di questa voce aveva `p1+p2+p3+p4+p5` senza i fattori 2: CONTRADDETTO dalla revisione indipendente dell'agente e corretto (vedi sotto); il verificatore ora calcola e asserisce il bound con i fattori 2.
- **Magic «P1IDSTR\0»:** memcpy(ctxB+0, 0x351718, 8) dopo il bound e memcpy(ctxB+236, 0x351718, 8) in coda; gli 8 byte a 0x351718 sono la stringa "P1IDSTR\0" seguita da spazi. Il cluster 0x25Cxxx è il servizio record di comando P1IDSTR; record stride 236 con magic in testa e in coda.
- **Due formule cumulative** nei campi ctxB 0xC4..0xE6 (r2 = ctxB+180), selezionate dal bit0xA di ctxA[+2]: clear → 0xC4=2p2+2p3+p4+p5, 0xC6=0, 0xC8..0xD0 cumulate, 0xE2=0xC4+p1+5, 0xE4=0xE2+margine, 0xE6=(ctxA[+6]−0xE4)&0xFFFF; set → 0xC4=1, 0xC6=p1+3, cumulate, 0xE2=p1+3+2p2+2p3+p4+p5, 0xE6=0. Margine ctxB+0xE0 = (ctxA[+6]−ctxA[+8])&0xFFFF. NB semantica ARC (dalla revisione): extw/extw_s = ZERO-extension dei 16 bit bassi (SEXW mai usato), ldw_s/stw_s = accessi 16-bit (nessuna sovrapposizione, nessuna .X): i valori dei campi non cambiano rispetto alla prima stesura, le descrizioni «sext16» e «store sovrapposti» erano errate. Successo → ritorno 0.
- **NB toolchain (correzione #2 dell'iterazione 8):** `add2` in questo objdump stampa l'immediato RAW e scala per 4 (prova nel chiamante: add2 r0,r1,0x3b / sub_s r0,r0,r1 / cmp 236: la sub cancella r1 e il cmp testa 0x3b×scala==236). La «verifica stride» di 0x29E680 è quindi un confronto di costante in compilazione, sempre vero: ramo errore da quel sito irraggiungibile; 0x1B00105 (pool 0x29E758, delay slot del b.d) è l'id DEL SITO MORTO, mai restituito in pratica (gli altri fallimenti verso 0x29E8D6 restituiscono i codici dei chiamati annidati: 0x1B00106 dall'intake, esiti di 0x25D3AC). Scala ×4 confermata da manuale ARCompact («ADD2 a ← b + (c << 2)») e simulatore GNU (`SLLSI(imm,2)`).
- **Contorno:** il getter 0x25C028 (subito dopo 0x25C020) legge [0x50F4D4+0x30]+[+0x32]−1 (pool 0x25C39C): la guardia 0x50F4D4 dell'iterazione 2 è essa stessa una struttura con campi +0x30/+0x32.

**Comandi/esiti.** `python3 Python_Trace_Scripts/s33_verify_lens_cmd_intake.py` → PASS exit 0 due volte (prima stesura, evidenza 20261021T231201Z; e dopo le correzioni della revisione, evidenza 20261021T231958Z, quella valida). Correzioni di collaudo della prima stesura: extw→extw_s sui siti 16-bit, regex offset per `[r14,0]` senza 0x, filtro parametri 6..14 separato da +0x10/+0x12, stessa regex nel controllo a5-mai-letta. Correzioni successive dalla revisione indipendente: bound con 2·p2+2·p3 (add1_s = b+(c<<1)) ora modellato e asserito, extw = zero-extension, stw_s = store 16-bit, 0x1B00105 = id del sito morto; rimossa la helper sext16 inutilizzata.

**Revisione indipendente (agente cmd-intake-audit, tools.agents.spawn, configurazione ereditata; atteso e integrato).** L'agente ha riverificato i byte raw del payload0 (hash confermato), ridedcolato le finestre GNU, e confrontato pattern binutils 2.45 (`arc-tbl.h`/`arc-opc.c`), manuale ARCompact locale (`outputs/gnu_arc700_aux/sources/ARCompact_5115-029.txt`) e simulatore GNU ARC700 (`work/gnu_arc700_dsp_lab/.../sem7.c`); non ha rieseguito il verificatore per non scrivere evidenze. Esito: claim resolver/intake-ctxB/mappa/magic/add2 = CONFERMATI (con sfumatura ldw_s zero-extend, .X mai usato); **bound CONTRADDETTO** (add1_s = c<<1 → 2·p2+2·p3, ora corretto ovunque); formule delle varianti CONFERMATE con tre correzioni di descrizione (extw = zero-extend, stw_s = 16-bit senza sovrapposizione, 0x1B00105 = id del sito morto). Nota di metodo acquisita per le prossime finestre: le word ARC 32-bit dai byte raw si ricostruiscono come (primo_halfword << 16) | secondo; campi registro via extract_rb (bit[26:24] = 3 bit bassi, bit[14:12] = 3 bit alti). Lo strumento «task con agente explore» richiesto non esiste in questo ambiente; usato spawn come nelle iterazioni precedenti.

**Limiti.** Statico, nessun hardware/esecuzione, NON_INSTALLARE; semantica fisica dei campi (tempi/posizioni/budget) = inferenza dall'aritmetica, non conferma MCU; doppioni p2/p3 in due campi ciascuno = fatto byte, trattamento MCU aperto; runtime di ctxA[+6]/[+8]/bit0xA sconosciuto (iterazione 3: nessuno scrittore statico del bit); 0x1B00106 come «budget superato» = inferenza; V1.1 vs V1.0; circa10% invariato.

**Prossimo passo (non ripetitivo).** (a) Seguire il consumatore dei campi 0xC4..0xDE dentro lo switch 0x1EE730 fino ai comandi wire del dizionario {00,10,30,50,60,70,80,D0,FF} (chiude la «semantica MCU dei byte» del checkpoint wire); (b) in alternativa censire i lettori/scrittori Main del banco 0x0FE400xx partendo da 0x301EC0 (identità periferica). Entrambe offline e byte-verificabili.

## Iterazione 8 — 22 ottobre 2026 — semantica record 22 byte, 0x301EC0 = strobe MMIO 0x0FE400xx, trasformazione ceil(h/8) (verificatore Orchestrator_Args PASS)

**Domanda affrontata.** Il punto aperto 9 dell'iterazione 7 ([Chiamanti del modulo orchestratore](S33_Obiettivo_Chiamanti_Modulo_Orchestrazione.md)): decodificare 0x301EC0 e il riempimento del record 22 byte (le 6 word a [fp-0x18..fp-0x04]) per collegare gli argomenti ai campi comandi dei contesti. In apertura: recupero della documentazione dell'iterazione 7 interrotta.

**Recupero iterazione 7.** Il verificatore `s33_verify_lens_module_callers.py` è stato RIESEGUITO in questa sessione: PASS (evidenza 20261021T224729Z; quella dell'iterazione 7 interrotta era 20261021T223912Z). Completate le scritture mancanti: percorsi_progetto, S33_Stato_progetto, questo checkpoint (voce Iterazione 7), sezione 7 del rapporto (agente module-callers-audit mai integrato, nessun output recuperabile). roadmap/AGENTS/mappa_ram erano già aggiornati dall'iterazione 7.

**Risultato (iterazione 8).** [Rapporto](S33_Obiettivo_Semantica_Record_Orchestratore.md),
[script](../Python_Trace_Scripts/s33_verify_lens_orchestrator_args.py),
[prove](../Risultati/Lens_MCU_Interface/Orchestrator_Args/latest.json) (4 finestre GNU allineate + corpo 0x301EC0 byte-exact + pool raw LE + modello ceil su 65.536 valori).
- **Il «record 22 byte» È il blocco argomenti `{a0..a4 word, a5[15:0]}`**: 0x301E1C lo azzera con memcpy da 0x354DE4 (22 byte zero dopo le stringhe BootNANDBase 0x354DC1/DD2); 0x29E8F0 salva r0..r5 a [sp+0x28..0x3C] e ricopia esattamente 22 byte a [sp+4].
- **0x301EC0 NON riempie il record**: corpo regolare 0x54 byte byte-exact = 4 scritture `sth.di` al banco **0x0FE400xx** (0x4321→0x0FE40004, 0x6641→0x0FE40008, 0xE972→0x0FE4000C, 0xFFFF→0x0FE40010; pool pcl; pop_s blink + j_s [blink]). È lo stesso banco dell'arresto GNU DSPv5 in TBIB (0x4321→0x0FE40004 a 0x010091F8): **primo scrittore Main-side noto del banco**, identità periferica aperta.
- **Rotta API stato = record tutto zero**: a0..a4=0, a5 con 16 bit di residuo stack ([fp-2],[fp-1] e [sp+0x1A],[sp+0x1B] non coperti dalle copie 22 byte su frame 24); unico input non zero **r6=arg1**, NON salvato/ricaricato da 0x29E8F0 (inoltro ABI-dipendente, aperto).
- **0x29E8F0**: ctxA=0x25CAEC(0)→[sp,0]; copia 22B; se bit0xA di ctxA[+2]: le 5 halfword del record a offset 6..14 (ldh [sp,46..54] → sth [sp,10..18], in-place) diventano **h←ceil(h/8)** (`bmsk.f 0,r0,0x2` idioma flags-only a destinazione fittizia — 72 `sub.f 0,` nel listato integrale — + `asr_s` senza flag + add condizionale); check 0x1593AC(0x1B00001,0) (pool 0x29EB84); dispatch 0x29E680(record[0..20]).
- **0x29E680**: arg a [sp+0x1C..0x30]; **intake candidato 0x25C038(ctxA, sp+0x1C)**; attenzione 0x25F28C; ctxB 0x25C020; stride 236 (id 0x1B00105, pool 0x29E758); 0x25D3AC; template 0x3F6698→0x50F210 (528B) e →0x50F310 (244B), ancore iterazione 5 confermate.
- **NB metodologica**: i pool pcl si leggono come word LITTLE-ENDIAN dai byte raw del payload (objdump stampa i chunk da 32 bit in ordine di halfword istruzione: pool 0x301EF4 = 0xE972, NON 0x72E9 — errore corretto durante il collaudo).

**Comandi/esiti.** `python3 Python_Trace_Scripts/s33_verify_lens_module_callers.py` → PASS (riesegno iterazione 7). `python3 Python_Trace_Scripts/s33_verify_lens_orchestrator_args.py` → PASS exit 0 (dopo 4 correzioni di collaudo: valore pool 0x301EF4, mnemonico bl per i validatori, formato esadecimale delle regex st_s/ld_s, halfword sth.di 0x0024; il corpo 0x301EC0 è ora verificato byte-exact). Agente `orch-args-audit` (tools.agents.spawn, configurazione ereditata): esito in fondo a questa voce. Lo strumento «task con agente explore» richiesto non esiste in questo ambiente; usato spawn come nelle iterazioni precedenti.

**Limiti.** Statico; ceil(h/8) modellato in Python su 65.536 valori ma non provato su CPU fisica; residuo stack e inoltro r6 indeterminati; 0x25C038 da byte-verificare; identità periferica 0x0FE400xx aperta (riferimento TBIB dal rapporto GNU DSPv5, non riverificato); V1.1 vs V1.0; NON_INSTALLARE; circa10% invariato.

**Prossimo passo (non ripetitivo).** Byte-verificare **0x25C038** (dove scrive le 6 word del blocco dentro ctxA e in quali campi 0xC4..0xDE) per chiudere argomenti→contesti→switch 0x1EE730; in alternativa censire lettori/scrittori Main del banco 0x0FE400xx partendo da 0x301EC0.

## Iterazione 7 — 21/22 ottobre 2026 — chiamanti del modulo orchestratore, correzione off-by-two (sessione interrotta, recupero completato dall'iterazione 8)

**Domanda affrontata.** Punto aperto dell'iterazione 4: prima di dichiarare il
vicolo cieco, cercare riferimenti calcolati (limm middle-endian, word LE) e
chiamate dirette verso gli orchestratori 0x29E682/0x29E9C6 e il bordo esterno
del sottosistema comandi obiettivo.

**Risultato.** [Rapporto](S33_Obiettivo_Chiamanti_Modulo_Orchestrazione.md),
[script](../Python_Trace_Scripts/s33_verify_lens_module_callers.py),
[prove](../Risultati/Lens_MCU_Interface/Module_Callers/latest.json).
- **CORREZIONE off-by-two**: gli ingressi reali degli orchestratori sono
  0x29E680/0x29E8F0/0x29E9C4 (`sub_s sp,sp,0x18` + `push_s blink`); gli
  indirizzi +2 censiti nelle iterazioni 3–4 erano il push_s dentro il prologo.
- **Primo chiamante esterno statico**: 0x301E92 `bl 0x29E8F0` dentro 0x301E1C
  (strato API stato: record 22 byte azzerato, 0x301EC0, validatori, 7 argomenti);
  chiamanti di 0x301E1C solo in payload4 CCD_Tune_DVT (0x7D470A/0x7D4734,
  dispatcher 0x80F9C8 con opcode 0x33 → case 0x80FAAA).
- Censimento bl su 16 payload verso [0x29E600,0x29EA00): 6 artefatti bln +
  3 intra-modulo + 1 esterno + 1 coincidenza dati payload9; zero limm/word LE
  in codice; uscita calcolata del modulo a 0x1ED11C (pool 0x29EB94).

**Comandi/esiti.** `python3 Python_Trace_Scripts/s33_verify_lens_module_callers.py`
→ PASS (evidenza 20261021T223912Z; rieseguito dall'iterazione 8: PASS, evidenza
20261021T224729Z). La sessione è stata interrotta dopo il PASS e l'aggiornamento
di roadmap/AGENTS/mappa_ram, PRIMA di aggiornare percorsi_progetto, Stato_progetto,
questo checkpoint e PRIMA di integrare l'agente di revisione `module-callers-audit`
(sezione 7 del rapporto lasciata in sospeso; nessun output agente recuperabile).
L'iterazione 8 ha completato percorsi/Stato/checkpoint e chiuso la sezione 7.

**Limiti.** Statico; chiamate con target calcolato non da pool/limm non
censibili; runtime della rotta payload4 aperto; semantica 7 argomenti/record
22 byte non decodificata; AE/iris 0x1236BC non agganciato; NON_INSTALLARE.

**Prossimo passo.** Decodificare 0x301EC0 e il riempimento del record 22 byte
(6 word a [fp-0x18..fp-0x04]) per collegare gli argomenti ai campi comandi
0xC4..0xDE dei contesti 0x50F52C/0x50F420; in alternativa salire ai chiamanti
del dispatcher 0x80F9C8 in payload4.

## Iterazione 4 — 21 ottobre 2026 — correzione "band entry" e getter MMIO del banco ausiliario (verificatore Aux_MMIO_Accessors PASS)

**Domanda affrontata.** Il prossimo passo del checkpoint Descriptor_Writers/iterazione 3:
risalire dai wrapper accessor 0x25E7xx–0x25EAxx ai loro chiamanti per agganciare
task/eventi e il blocco AE/iris 0x1236BC agli orchestratori 0x29E682/0x29E9C6.

**Risultato.** [Rapporto](S33_Obiettivo_Accessor_MMIO_Correzione_Band_Entry.md),
[script](../Python_Trace_Scripts/s33_verify_lens_aux_mmio_accessors.py),
[prove](../Risultati/Lens_MCU_Interface/Aux_MMIO_Accessors/latest.json) (12 finestre
getter + 5 finestre contesti chiamanti, allineate ai target dei `b_s`).
- **CORREZIONE dell'iterazione 3**: i 12 "wrapper accessor" 0x25E750..0x25EAB8 NON
  chiamano le band entry 0x29E85C..0x29EBC4. I `bln` nel listato allineato
  all'ingresso della funzione erano ARTEFATTI: la catena di decodifica a 2 byte
  attraversa il pool word della `ld_s` (indirizzo del registro MMIO). Flusso reale
  (finestra allineata al target del `b_s`, byte-verificato): `ldh.di r0,[r0]` +
  `and r0,r0,0xMASK` (limm middle-endian) + `pop_s/j_s.d [blink]` con `asr_s`
  shift nel delay slot. I 12 siti bln cadono tutti a g+0xE, dentro la ldh.di reale.
- I 12 accessor sono **getter bitfield del banco ausiliario 0x0FFCA084..0x0FFCA0BC**
  (passo 8; campi 0x6000>>13, 0x1FC0>>6 sui registri +4 mod 8, 0xFF00>>8 sugli
  altri). Censimento LE del banco in payload0: **47 registri 0x0FFCA004..0x0FFCA118**
  gestiti dalla famiglia 0x25E0xx–0x25ECxx (include il noto ausiliario 0x0FFCA008).
- **Negativo**: nessun chiamante reale delle band entry su 16 payload (i soli 12
  bln = artefatti; due rami interni 0x29E954/0x29E9A4 restano intra-modulo);
  gli orchestratori 0x29E682/0x29E8F2/0x29E9C6 restano SENZA chiamanti statici
  (il negativo dell'iterazione 3 resta valido, la rotta band entry no).
- Chiamanti: SOLO il getter 0x25E7A4 (dettaglio 7 bit di 0x0FFCA084) è chiamato,
  5 siti payload0 (fn 0x168DB0/0x169350/0x25F724/0x25F8CC/0x25F998), tutti
  percorsi di errore con **nuovi codici 0x1B00204/0x1B00205/0x1B00206/0x1B00207**:
  confronto 0x7F (0x168E64 sul risultato; 0x25FA38 su r0 vecchio del delay slot),
  risultato passato a 0x2600B4 (0x25FA32), scarto con errore 0x1B00212 (0x25F788),
  store r14→0x36B284 (0x25F90E), scarto (0x1694E2, guardia 0x1B00206 a 0x16949A).
  Nessun chiamante nel blocco AE/iris 0x1236BC..0x126000.
- Pool chiamanti 0x25FB18..0x25FB4C: **nuova famiglia 0x36B270..0x36B290** (genitore
  0x36B244, ctrl 0x36B254=genitore+0x10), cella **0x50F540** (= ctxA 0x50F52C+0x14),
  nuova cella **0x50FD80**, ID errore 0x1B00212/0x1B0000F/0x1B0000A/0x1B00010/0x1B00008.
- La sequenza middle-endian di 0x25E8A0 in payload6 (0x9B1619, dispari) è coincidenza
  in byte di codice (attraversa cmp/bhi), non un limm.

**Comandi/esiti.** `python3 Python_Trace_Scripts/s33_verify_lens_aux_mmio_accessors.py`
→ PASS exit 0 (12 getter, 47 registri censiti, 12 artefatti bln, 5 chiamanti esatti).
Il verificatore dell'iterazione 3 `s33_verify_lens_descriptor_writers.py` è stato
corretto NELL'INTERPRETAZIONE (docstring, commenti band-entry, descrizione JSON;
nessuna asserzione indebolita o rimossa) e rieseguito: PASS (cartella
20261021T221335Z). Fix durante il collaudo del nuovo script: regex `\b` dopo `]`
(invalida), shift in esadecimale nella stampa GNU, limm maschera middle-endian.
NB strumento: non esiste "task con agente explore"; usato `tools.agents.spawn`
(figlio `lens-aux-mmio-audit`, configurazione ereditata), atteso e integrato:
ha confermato tutti e 5 i punti senza controprova, con i contributi citati sopra
(guardia 0x1B00206 del sito 0x1694E2, rami intra-modulo delle band entry,
passaggio del risultato a 0x2600B4 come argomento, natura della coincidenza p6).

**Limiti.** Statico, nessun hardware/esecuzione, NON_INSTALLARE; V1.1 vs V1.0. Gli 11
getter senza chiamanti possono essere raggiunti da salti calcolati/tabelle invisibili
al censimento o essere codice morto. Semantica dei campi del banco = inferenza dai
siti d'uso; effetto cache di `ldh.di` non modellato. Layout/ownership delle celle
0x36B270..0x36B290/0x50F540/0x50FD80 non decodificati. La domanda "chi raggiunge gli
orchestratori" resta APERTA: la rotta band entry è chiusa, nessuna nuova rotta è
reclamata.

**Prossimo passo (non ripetitivo).** (a) Decodificare il layout della famiglia
genitore 0x36B244 (0x36B244..0x36B290 + bit-table 0x50F190) e le celle 0x50F540 /
0x50FD80 dai loro writer/lettori censiti: è lì che si decide iris/zoom/focus prima
del wire; (b) cercare salti calcolati/tabelle funzione verso 0x29E682/0x29E8F2/
0x29E9C6 (pattern jl [r] con caricamento da pool) prima di dichiarare il vicolo
cieco; (c) in alternativa decodifica campo-per-campo del template 0x3F6698 (528 B).

## Iterazione 3 — 21 ottobre 2026 — scrittori descrittori RAM, template statico e r57 (verificatore Descriptor_Writers PASS)

**Domanda affrontata.** Il prossimo passo del checkpoint Status_API/iterazione 2: chi
scrive a runtime i descrittori RAM 0x50E940 (record) e 0x36B254 (ctrl) della
transazione obiettivo 0x25F338, chi copia/inizializza l'area 0x50Fxxx e da dove viene
r57 della primitiva di movimento 0x29DDD4.

**Risultato.** [Rapporto](S33_Obiettivo_Scrittori_Descrittori_RAM.md),
[script](../Python_Trace_Scripts/s33_verify_lens_descriptor_writers.py),
[prove](../Risultati/Lens_MCU_Interface/Descriptor_Writers/latest.json) (cartella
20261021T220122Z, 10 finestre GNU allineate).
- Descrittori confermati RAM oltre la fine di payload0 (0x35BC00): nessun contenuto
  statico in 0x36B254/0x36B25C/0x36C3E8, 0x50E140/0x50E340/0x50E940/0x50E950,
  0x50F210/0x50F310; cella 0x54D8A8 nel gap RAM fra payload1 e payload2.
- Writer del ctrl byte-verificati: 0x29E1A4 (loop write-verify-reinit n.2:
  +0 conteggio, +1 stato=0, +2 word 0/ctxA[+0xE4], limiti ctxB[+4]/[+6], poi
  0x25F6A4 record + 0x25F28C + 0x25CBF0 + 0x29DDD4 + 0x260C6C, retry 0x1EDC10),
  0x29DF18 fratello, 0x29E458/0x29E574 (ctrl → 0x25C1F0/0x25C37C, ctxB[+0xC4]);
  switch 0x1EE730 reset {+0=0,+1=4,+2=0} SOLO se bit0xA di ctxA[+2] attivo;
  hub 0x1EE148 scrive marker 0x55/0xAA direttamente nel record (+6/+7/+0xB/+0xC)
  e riempie record+0x10.. di 0xFF. Layout ctrl: +0 conteggio/stato, +1 stato/tipo
  (0/4/8/0x11, non byte dati), +2 word.
- **Primo inizializzatore statico dell'area 0x50Fxxx**: gli orchestratori
  0x29E682/0x29E9C6 copiano via memcpy 0x128C20 il template di payload1
  **0x3F6698** (528 B, 282 non zero, sha256 46888e6e…4014d4) in RAM
  **0x50F210** (0x50F210+528 = ctxB 0x50F420, fine esatta) e 0x50F310 (244 B),
  poi dispatchano su bit0xA di ctxA[+2]. Contesti 0x50F420/0x50F52C restano
  runtime-only (checkpoint precedente invariato).
- **r57 chiuso**: non è argomento del chiamante; è la metà del prodotto muludw
  calcolata dentro 0x29DDD4 dopo sr 0,[aux_macmode] (P1 = muludw([ctxA+6],
  [ctrl+0]); r0 = [ctrl+2]+r57; P2 = muludw([ctxA+5], r0); i due byte di r57
  vanno in porta via 0x25E078). arg0 = ctrl stesso; flag post-mossa = bit8 di
  ctxA[+2], non bit0xA. Caveat muludw (formula condizionale) conservato.
- **Negativo su 16 payload**: nessun bl/b/jl e nessuna word-puntatore verso
  0x29E682/0x29E8F2/0x29E9C6: moduli multi-ingresso raggiunti dai wrapper
  accessor 0x25E7xx–0x25EAxx via band entry interne (0x29E85C…0x29EBC4;
  0x25E750 riverificato allineato). AE/iris 0x1236BC non chiama l'hub
  (0x1EE148 chiamato solo da 0x1EEA42 switch e 0x29E7A8 orchestratore).

**Comandi/esiti.** `python3 Python_Trace_Scripts/s33_verify_lens_descriptor_writers.py`
→ PASS exit 0 (due esecuzioni: prima 7 finestre, poi 10 dopo l'integrazione agente;
template sha256 verificato, censimenti chiamanti esatti, negativo 16 payload).
Correzioni durante il collaudo: sedute di fix mirate su regex (bl vs bl.d, mov_s
vs mov, `re.findall` al posto di `str.count`, offset ld.as estratto dal listato
invece di decodifica manuale); nessuna asserzione indebolita. NB: lo strumento
«task con agente explore» non esiste in questo ambiente; usato l'equivalente
`tools.agents.spawn` con figlio `desc-writers-audit`, atteso e integrato: ha
confermato writer e r57, allargato il censimento a ~20 siti statici writer/feeder
del ctrl (famiglia genitore 0x36B244, ctrl = +0x10, bit-table 0x50F190), trovato
l'unico **limm middle-endian** del record (0x29E846, byte `50 00 40 e9`,
riverificato e assertito) e il negativo **nessun writer statico del bit0xA di
ctxA[+2]** (solo 0x25D3AC bit7 su fallimento). Tre finestre nuove aggiunte al
verificatore per le sue scoperte chiave, tutte riverificate sui byte.

**Limiti.** Statico, nessun hardware/esecuzione, NON_INSTALLARE; V1.1 analizzata
vs V1.0. Chiamanti degli accessor 0x25E7xx e aggancio AE 0x1236BC→wire ancora
aperti; semantica del template 0x3F6698 non decodificata; muludw condizionale;
scansioni word LE non vedono i limm middle-endian (ricerca dedicata fatta solo
per 0x50E940); censimento writer dell'agente = candidato su finestre allineate.

**Prossimo passo (non ripetitivo).** Risalire dai wrapper accessor
0x25E7xx–0x25EAxx (funzioni con push_s blink, quindi con bl diretti o tabelle)
ai loro chiamanti per collegare task/eventi e il blocco AE/iris 0x1236BC al
modulo orchestratore; in parallelo decodificare il template 0x3F6698 campo per
campo e confrontarlo con ctxB[+0xC4..0xDE] per assegnare i record a
zoom/focus/iris. Se bloccati, passare a un altro punto offline (pulsanti o
display).

## Ultima sessione interrotta: Status_API incompleto (SUPERATO: vedi iterazione 2)

Leggere [osservazione e limiti](S33_Vibe_Silenzio_Watchdog_e_Errori_Reali.md).
`s33_verify_lens_status_api.py` NON passa: ultima asserzione osservata
`semaphore 0x12A71C missing`. Non considerare verificate le sue descrizioni
o correggere indiscriminatamente le attese. Snapshot e errori conservati;
nessuna asserzione rimossa o modificata da noi. Il runner e Vibe sono stati
fermati dopo un periodo senza output; non era in corso il comando Python.

Prossimo: scegliere un’altra domanda offline utile al percorso fotografico
(per esempio ingresso pulsanti o display), oppure un audit breve dei confini
delle finestre Status_API, con esito negativo ammesso. Non ripetere il censimento
dell’intero firmware o continuare ad aspettare subagenti senza checkpoint.
La classificazione wrapper precedente resta nel suo rapporto separato.
Circa10% invariato, nessun hardware.

## Iterazione 2 — 21 ottobre 2026 — contesti parametri comandi e strato API stato (verificatore Status_API completato)

**Domanda affrontata.** I punti 1–2 del checkpoint wire: dove vivono i parametri
dei comandi wire (incluso iris) e chi consuma il cluster porta obiettivo
0x25CB00–0x260D00. Il verificatore `s33_verify_lens_status_api.py`, già avviato
in precedenza e fermato su asserzione fallita, è stato completato in questa
sessione.

**Risultato.** [Rapporto](S33_Obiettivo_Contesti_Parametri_e_API_Stato.md),
[script](../Python_Trace_Scripts/s33_verify_lens_status_api.py),
[prove](../Risultati/Lens_MCU_Interface/Status_API/latest.json).
- Contesti RAM byte-verificati: 0x25CAEC→0x50F52C (flag bit0xA a +2, **byte cmd
  a +5**, count a +0x10), 0x25C020→0x50F420 (tabella halfword parametri a
  +0xD2..0xDE, stessa famiglia campi 0xC4..0xDE dello switch 0x1EE730),
  guardia 0x50F4D4 di 0x25BFB8. Nessun inizializzatore statico in payload0:
  i byte di comando runtime NON sono derivabili staticamente.
- Strato API stato: 0x30183C → [0x2FFFCC](1..5) → 0x16F41C; jump table 0x30000C
  su campi della struct payload0 0x3548D8; fuori range → 0x2900001.
- Semantica dizionario wire (finestre allineate + agente): 0x25F6A4 = **scrittura
  record parametro** (0x50 + sender + record 16B via 0x25F31C + 0x00; varianti
  0x25F4EC/0x25F5C8), 0x29DDD4 = **primitiva di movimento** (posizione da r57
  scritta direttamente su 0x0FF05000 via 0x25E078), 0x70 = query stato
  (0x260C6C legge porta, errore 0x1B00007), 0x80/0x10 = upload bulk,
  0x25F28C = attenzione/reset (72 chiamanti). Loop write-verify-reinit 0x1EEF6C
  con la coppia 0x50E940/0x36B254 (pool 0x1EF654/0x1EF260 verificati).
- Ancore iris aggiunte: blocco AE/iris Main 0x1236BC–0x125xxx con
  `Change Iris from MAX/To MIN` (payload1 0x3860EE/0x38612C, parole 0x124F64/
  0x124F6C); pannello `Iris status: Big/Small` (0x2C51A8/0x2C51AC, getter indici
  8/9/0xA); tabella overlay 0x323EE0 (Iris 0:Big 1:Small); `ucIrisIndex` dump.

**Comandi/esiti.** `python3 Python_Trace_Scripts/s33_verify_lens_status_api.py`
→ PASS exit 0 (12 finestre GNU allineate, ~25 letterali riverificati, 6 stringhe
iris + puntatori, censimento chiamanti). Correzioni durante il collaudo: valori
letterali reali (0x2609CC=20000, 0x2609D4=6000, 0x260C98=0x1B00007), finestre
estese (0x2FFFCC→0x300080, 0x25F6A4→0x25F71C, 0x2FF88C→0x2FF992), regex bl/bl.d
esatte; nessuna asserzione indebolita. Agente `lens-cmd-consumers` completato e
integrato; le sue affermazioni chiave (ingressi push_s blink, semantica 0x25F6A4/
0x29DDD4/0x260C6C, pool 0x1EF654/0x1EF260, blocco AE) sono state riverificate sui
byte. NB: lo strumento «task con agente explore» non esiste in questo ambiente;
usato l'equivalente `tools.agents.spawn` (figlio indipendente, configurazione
ereditata), atteso e integrato.

**Limiti.** Statico, nessun hardware/esecuzione, NON_INSTALLARE; contenuti dei
contesti/descrittori RAM e r57 runtime non determinabili; la mappa ingressi è
collegamento statico su finestre allineate (BFS solo bl/bl.d); l'iris non ha
ancora un wrapper ancorato fra i 33 chiamanti: 0x25F6A4 (record parametro) e
0x29DDD4 (mossa) sono i trasporti coerenti ma non provati per iris. muludw non
modellato. Circa10% invariato.

**Prossimo passo (non ripetitivo).** Cercare gli **scrittori dei descrittori
RAM** 0x50E940/0x36B254 (chi pone il flag bit0xA di [0x36B254+2] e riempie i byte
del descrittore, inclusa la provenienza di r57) e agganciare da lì il blocco
AE/iris 0x1236BC al record writer: è lì che si decide iris vs zoom/focus prima
del wire. Se bloccati, passare a un altro punto offline (es. display/pulsanti).

## Riparazione del 21 ottobre — non ripetere il ciclo di correzioni

Il runner è stato fermato dopo modifiche ripetute. Il verificatore
`s33_verify_lens_wrapper_classification.py` è riparato ed eseguito direttamente:
PASS, 33 chiamanti. Leggere [rapporto di riparazione](S33_Vibe_Blocco_Riparazione_Wrapper_Obiettivo.md)
e `Risultati/Lens_MCU_Interface/Wrapper_Classification/latest.json`.
11 regex erano corrotte da sed; lo switch 1EE730 richiede header, sette rami e
tratto comune separati dalle tabelle inline. Campi halfword verificati C4..DE.
La tabella per chiamante resta candidata (13 other), iris non identificato.
Non rifare queste sostituzioni o allargare liste attese per inseguire PASS.
Prossimo: cercare una prova nuova che colleghi uno dei wrapper al comando iris;
se bloccato, documentare il limite e scegliere un altro ramo offline.
Verificatori senza pipe a tail/head; dopo tre tentativi falliti sullo stesso
problema, salvare errore e diff e cambiare domanda. Nessun hardware; circa10%.

## Iterazione 1 — 21 ottobre 2026 — protocollo wire MCU obiettivo decodificato

**Domanda affrontata.** Il punto aperto 1 del checkpoint obiettivo/zoom
([S33_Obiettivo_Zoom_MCU_Interface_e_BCIP.md](S33_Obiettivo_Zoom_MCU_Interface_e_BCIP.md)):
decodificare il formato byte del protocollo porta MCU obiettivo (0x0FF05000),
chi manda quali byte, il ruolo del pack 3 byte e i chiamanti della transazione.

**Risultato.** [Rapporto](S33_Obiettivo_MCU_Formato_Wire_Decodificato.md),
[script](../Python_Trace_Scripts/s33_verify_lens_wire_protocol.py),
[prove](../Risultati/Lens_MCU_Interface/Wire_Protocol/latest.json).
- Correzione strutturale: 0x3341xx = thunk millicode GNU (push/pop r13–r16); il
  sender 0x25CB54 usa direttamente il descrittore {byte0, byte1, word2}; il pack
  0x25CBBC è il logger di posizione, non un header wire.
- Wire: gate bit4 di 0x0FEF03A8 + bit6 di 0x0FF04034 attorno alle transazioni,
  strobes bit8/9 di 0x0FF04020; pacchetto comando `[00] 00 lo/hi(desc[1]+r57)
  [desc[0]]` con flag dai contesti RAM 0x50F514/0x50F52C; dizionario byte di
  comando letterali {00,10,30,50,60,70,80,D0,FF} (29 siti byte-verificati);
  variante completa 0x29DDD4 (0x60 → lo/hi r57 → 0xD0); validatore risposta
  con marker 0x55/0xAA e tipo in [5]; attesa ready con timeout → 0x01B00003.
- Chiamanti reali di 0x25F338 = 33 (0x232B4A è falso positivo di pool, byte
  verificato); dominanti r1=0x50E940 e descrittore controllo r2=0x36B254;
  wrapper 0x25F3F4 inietta cmd in [r2+1]/[r2+2] e ripristina.
- MCUCTRL_Task risolto: stringa in payload1 (0x3764A7), record 0x372508 (id
  0x3200001, entry 0x15A80C, stack 0x800, priorità 6), contesto 0x391B38 con
  ring 8×0x24. NEGATIVO: nessun legame stabilito con la porta obiettivo (BFS
  inversa di 181 funzioni/564 antenati senza il sottoalbero MCUCTRL né LensCtrl
  0x14661C); il vecchio diagramma «UI→MCUCTRL_Task→cluster 0x25CB00» non è
  sostenuto; il task governa 0x0FED68xx/70xx.

**Comandi/esiti.** `python3 Python_Trace_Scripts/s33_verify_lens_wire_protocol.py`
→ PASS: 14 finestre GNU allineate, 16 letterali riverificati sui byte raw,
dizionario esatto, 33 chiamanti, timeout 0x01B00003. Agenti: `trx-callers`
(classificazione completa 33 siti, falso positivo individuato) e `mcuctrl-task`
(ingresso task + risultato negativo), entrambi attesi e integrati; claim
chiave dell'agente MCUCTRL riverificati sui byte in questa sessione.

**Fonti precise.** Main block0 base 0x0AD800: 0x25CB54 sender, 0x25F338
transazione, 0x29DDD4 variante, 0x25DEAC/0x25DEE8 gate, 0x25DF24/4C/74/9C
strobe, 0x25F2B8/0x25F31C fase dati, 0x25CBF0 validatore, 0x25D0D0 attesa;
payload1: 0x372508 record task, 0x3764A7 stringa. pcl: annotazioni ld_s non
scalate corrette, formula (PC&~3)+off*4 valida per ld.as (48.412 siti testati).

**Limiti.** Statico, nessun hardware/esecuzione, NON_INSTALLARE; valore runtime
di r57 e contenuto dei descrittori RAM (0x36B254, 0x50E940, 0x50E140) non
determinabili; semantica MCU dei byte = inferenza; muludw non modellato;
helper 0x2E5658 non decodificato; versioni V1.1/V1.0 separate. Circa10%
invariato.

**Prossimo passo (non ripetitivo).** Isolare il wrapper iris fra i 33 chiamanti
di 0x25F338 — candidato il gruppo 0x50E140/0x50E940 con ctrl 0x36B254 —
leggendo il byte `[ctrl+1]` scritto prima di ogni chiamata e confrontandolo col
dizionario {00,10,30,50,60,70,80,D0,FF}; in parallelo risalire dai chiamanti ai
task/eventi per identificare il consumatore del cluster porta obiettivo (il
legame con MCUCTRL_Task è escluso dalla BFS inversa).
