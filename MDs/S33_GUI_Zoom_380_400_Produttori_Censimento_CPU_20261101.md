# Produttori runtime degli eventi zoom 0x380/0x400, cancellatori dell'anello e handler di rilascio 0x65B5D4 (registro p3): censimento completo + libreria iniettori p4 provata in CPU su byte originali — 1 novembre 2026 (iterazione 49)

## Domanda

Punto aperto (a) dell'iterazione 48 ([S33_Vibe_Offline_Checkpoint.md](S33_Vibe_Offline_Checkpoint.md), it.48):
con writer (it.39/47), lettore (h100 it.37) e consumatore (it.48) del ring
chiusi in CPU, **chi alimenta a runtime gli eventi 0x380/0x400** (zoom
in/out della finestra AutoSceneLiveView, registro p3, handler 0x65B3A8)?
Census dei siti 0x17BF60/0x16F6B0/coda 0x169EB4 per questi due id e
decodifica del produttore più promettente.

## Verificatore

`Python_Trace_Scripts/s33_verify_zoom_event_producers_census.py` →
**PASS_ZOOM_EVENT_PRODUCERS_CENSUS 20261101T213509446205Z**; riesecuzione
identica **20261101T213559063117Z** (confronto ricorsivo: solo `utc`
differisce). Prove:
[Risultati/GUI_S33/zoom_event_producers_census_20261101T213509446205Z/](../Risultati/GUI_S33/zoom_event_producers_census_20261101T213509446205Z/)
e `..._20261101T213559063117Z/`, più `zoom_event_producers_latest.json`.
Versioni intermedie durante lo sviluppo: 212340Z, 212434Z (PASS parziale
pre-revisione), 212855Z/212904Z/212915Z/212934Z/213017Z/213030Z/213056Z/
213122Z/213238Z/213333Z/213411Z (fault di sviluppo, tutte con errori
conservati nelle rispettive `verified_evidence.json`).
Banco esplorativo preliminare (semantica bl/b_s del motore pinnato):
`tmp/explore_repeat380.py` + `tmp/explore_repeat380_out_{250000,50000,350000}/`.

Regressioni eseguite DOPO la prima PASS, senza pipe, exit code 0 verificato:
event router producers **20261101T212501827282Z**, consumatore ASLV
**20261101T212512111605Z** (16/16; NB: il checkpoint it.48 sconsigliava di
rieseguirlo come NUOVO lavoro, qui è solo regressione, esito conforme).

## Risultato 1 — census delle API di post/coda (bl, 6.1M righe di listato)

| API | Chiamanti bl | Ruolo |
|---|---|---|
| 0x169EB4 | 304 | post (desc, evento, arg) → anello 0x17BC7C |
| 0x169F40 | 28 | post variante |
| 0x169F00 | 33 | push-front |
| 0x16F6B0 | 7 | **fan-out macchina tasti** (eventi dinamici) |
| 0x17BF60 | 188 | **CANCELLATORE**, NON un produttore |

I tail-jump `b`/`b.d` (19) e le chiamate indirette `jl_s` alle API NON sono
nel census (limite dichiarato, come in it.45). 0x16F6B0: chiama fino a 10
callback da `0x446808+512+4i` (add2 ×4 it.39; `ld.as [r1,128]` scala 4),
poi — se `byte[0x3678F9]≠0` e `r4≠0` ed esito callback≠0 e
`0x16F6A4(ctx)≠0` — inserisce `(0, evento_r2_halfword, r3, 1)` nell'anello.
La tabella callback 0x446A08 è FUORI dai 16 payload verificati: APERTO.
Nei 7 chiamanti NESSUN 0x380/0x400 (0x581 const@0x26C5C2, pool 0x3B81
@0x20F74E, 4 dinamici): **il produttore fisico (tasti → 0x380/0x400) resta
APERTO**.

## Risultato 2 — produttori diretti via 0x169EB4 (def costante/pool)

- **0x380 ×8**: 0x654322, 0x65B700, 0x7CBC72, 0x802036, 0x80BE9A, 0x80BED4,
  0x80BEF4, 0x9E223A.
- **0x400 ×10**: 0x2101F2, 0x654B04, 0x654B9C, 0x7CBC8A, 0x80204E, 0x8020BA,
  0x80BC92, 0x80BCCC, 0x80BCEC, 0x9E2250.
- **0x381 ×1**: 0x80BEA6; **0x401 ×1**: 0x80BC9E (i rilasci degli iniettori).
- **SITO DUALE 0x65B700**: raggiunto da DUE rami — 0x65B6EA `mov r1,1024`
  (0x400) con `b_s 0x65B6FE`, e 0x65B6FA `mov r1,896` (0x380) — posta
  `(r13, 0x400|0x380, 0)` a seconda del ramo (v. Risultato 4).
- NESSUN hit 0x380/0x400/0x381/0x401 via 0x169F40/0x169F00.
- desc: iniettori = 0 (finestra corrente); 0x2101F2 = ritorno di 0x1453F4
  (resolver finestra corrente); 0x654322 = 0; gli altri = r13/r14/r16
  (nodo/contesto mirato, v. CPU per il valore effettivo).

## Risultato 3 — registro finestra p3 COMPLETO (0x783B08..0x783C40) e handler di RILASCIO

39 record `{evento, handler}` col terminatore `(0, 0x20E814)`, tutti
congelati nel verificatore. Oltre alle mappe note (0x380/0x400→0x65B3A8,
0x580/0x700/0x2180/0x2700→0x65C46C, 0x581/0x2701→0x65C6B4, 0x4401→0x659554,
0x4405→0x65959C, 0x4110/0x4111→0x65CC40/0x65CCC8…), la novità chiave:

**0x381/0x401 → 0x65B5D4** (record 0x783B60/0x783B70). L'entry reale è
`push_s blink` a 0x65B5D4 (byte `f1 c0 52 0b 4e 6c fc 1c c8 b6 0a 23 00 37`,
congelati): la riga del listato GNU a 0x65B5D2 (`b.d 0x5DCDD0`) è la
decodifica spuria della coda del pool 0x4111 (word 0x65B5D0, verificata) —
coerente con la lezione binutils sui blocchi disallineati. 0x65B5D4 NON ha
chiamanti bl e NON ha parole LE nei 16 payload: è raggiunto SOLO tramite il
registro p3 (i record sono le uniche LE di 0x65B5D4).

### Handler 0x65B5D4 (rilascio zoom) — decodifica statica, pool byte-verificate

Pool: 0x65B708=0x681F83 (cella byte azzera all'ingresso), 0x65B70C=0xBB8
(timer 3000), 0x65B710=0x681F5C (ctx), **0x65B714=0x17BF60**,
**0x65B718=0x16F920**. Flusso: gate C9BF8()==1/CAD30()==0x7E →
query 0x149474 → timer 0x14905C(node,2,0xBB8,…) → `[ctx+4]∈{4,5}` (gli
stati scritti dal consumatore it.48 a coda vuota) → **cancel (0,0x400,0x400)
e (0,0x380,0x380)** via `jl_s [r14=0x17BF60]` (due volte ciascuno in rami
diversi) → purga servizi (1493BC/1493C4/14941C/DE574/14A1CC) → timer →
zoom 0x14A1F8 ≤0x64 con CD558 → 0x65CDF4 → 0x65CE24 → `[ctx+4]:=r15` →
CF060(1) → cancel di nuovo → **query macchina tasti 0x16F920(8): se ≠0
posta (r13,0x400,0); altrimenti 0x16F920(7): se ≠0 posta (r13,0x380,0)** via
0x169EB4@0x65B700. Significato: al RILASCIO di un tasto zoom, purga gli
eventi zoom pendenti e RIPUBBLICA l'evento del tasto ancora premuto.
Percorsi alternativi (statici, revisione): con flag residuo →
`bl.d 0x145C3C` con delay slot `ld.as [pcl,-208]` → **0x65B39C=0x30D40
(attesa 200000)** prima del ri-controllo; l'uscita 0x65B704 è `b 0x65B1B8`
(rientro nel loop della macchina a stati, NON un return al dispatcher).

## Risultato 4 — cancellatori dell'anello 0x17BF60 (anti-produttori)

0x17BF60(desc, lo, hi) azzera l'evento dei record dell'anello 0x47A848 con
desc corrispondente (0: qualunque) ed evento in [lo,hi]. Census con
risolutore documentato (def costante/pool, copie da registro, catene asl,
delay slot di bl.d, proprio e altrui):

| Range | Siti |
|---|---|
| [0x1, 0x7FFF] | 1 (0x16A102) |
| [0x80, 0x307F] | 65 (0x144D9A…0x9DC3CE, elenco congelato) |
| [0x300, 0x500] | 2 (0x7DCFA8, 0x9D6EB2) |
| [0x380, 0x380] | 4 (0x654760, 0x801FFA, 0x802160, 0x9DEDD6) |
| [0x400, 0x400] | 4 (0x65476C, 0x802006, 0x80216C, 0x9DEDE2) |

Totale 76 + **12 chiamate indirette** `jl_s [pool=0x17BF60]` coprenti
0x380/0x400 (elenco congelato, include i 4 siti dentro 0x65B5D4).
**Non coprenti dimostrati** (controesempi congelati): 0x16F97E — il delay
slot `asl_s r1,r1,0xa` porta lo a 0x15<<10=0x5400 → range [0x5400,0x57FF]
(correzione accettata dalla revisione; il mio primo census lo includeva per
errore); 0x65A898 — `mov r1,0xC + bset_s r1,r1,0xe + mov r2,r1` → [0x400C,
0x400C]. La revisione stimava ~96 siti con regole proprie: i censimenti
coincidono su ogni sito che entrambi risolvono (0x16F972 mancato da me,
aggiunto; 0x16F97E/0x65B700/coppie-arg corretti dall'agente); la
differenza numerica è nei siti con argomenti non risolvibili localmente
(limite dichiarato, es. 0x65B342 r1 dinamico).

## Risultato 5 — libreria iniettori p4 e dispatcher (revisione integrata)

- Press+release con arg 0xFF/0: 0x80BC7C=(0x400,0x401), 0x80BD4C=(0x480,
  0x481), 0x80BDE8=(0x500,0x501), 0x80BE84=(0x380,0x381); **arg 0/0**
  (correzione revisione): 0x80BD18=(0x200,0x201), 0x80BC48=(0x780,0x781).
- Coppie estese: 0x700/0x701 (post@0x80BF4A), 0x580/0x581 (@0x80BFB2),
  0x600/0x601 (@0x80BFF4), 0x680/0x681 (@0x80C026); iniettore indiretto
  0x80C084 (0x580/0x581 via pool 0x80C0F8=0x169EB4, revisione, non
  congelato).
- Auto-ripetizione: 0x80BCB0=0x400, 0x80BD80=0x480, 0x80BE1C=0x500,
  0x80BEB8=0x380; periodo pool **0x186A0 (100000)** a 0x80BD08/0x80BDD8/
  0x80BE74/0x80BF10 + sleep del resto via 0x145C3C.
- Dispatcher 0x809F78(record, cmd_id): UNICO chiamante bl **0x2D77BE**
  (p0, interprete di comandi con id ASCII 'S'/'A'/'F'/'D'); catena
  `cmp_s r14,id`/`bne_s` byte-verificata per i casi **0x24..0x36 e 0x3A**
  con siti congelati (es. 0x24→0x80BC28@0x80A294 … 0x2B→0x80BEB8@0x80A308
  … 0x36→0x80BDE8@0x80A3A8, 0x3A→0x80BE84@0x80A3E4). NB: la revisione
  indicava 0x37 per 0x80BE84 — il caso reale è **0x3A** (verificato qui).

## Risultato 6 — 4 casi CPU su byte ORIGINALI (motore GNU ARC700 pinnato)

| Caso | Finestre originali | Asserzioni | Esito |
|---|---|---|---|
| press380 | 0x80BE84..0x80BEB6 + millicode 0x334100..0x3341E4 | 2 post: (0,0x380,0xFF), (0,0x381,0); 0 sleep | fault 0xDEADB101 |
| repeat380_d250 | 0x80BEB8..0x80BF0E + pool 0x80BF10 | 3 post (0,0x380,0xFF); sleep [100000,100000,50000] | fault 0xDEADB201 |
| repeat380_d50 | idem | 1 post; sleep [50000] | fault 0xDEADB301 |
| repeat380_d350 | idem | 4 post; sleep [100000,100000,100000,50000] | fault 0xDEADB401 |

Stub 0x169EB4/0x145C3C con log (desc,ev,arg)/(arg); le finestre sono
confrontate byte per byte coi payload in fase di link. PROVA in esecuzione:
gli iniettori p4 emettono davvero press (arg 0xFF) / release (arg 0) con
desc=0 e l'auto-ripetizione emette un evento ogni 100 ms con sleep del
resto; il `b` negativo-large verso il millicode (0x3341A4/0x33418C) è
eseguito correttamente dal motore pinnato (già it.48).

**Scoperta metodologica (prima prova CPU nel progetto)**: il `bl` SENZA
`.d` NON ha delay slot — in 0x80BEB8 il `b_s -32` a 0x80BEF8 è il loop-back
eseguito DOPO il ritorno di 0x169EB4. Stabilita con banco esplorativo
(DUR 250000 → npost=3/nsleep=3, 50000 → 1/1, 350000 → 4/4 via indirizzo di
fault) prima di congelare le asserzioni.

## Revisione indipendente (agente `producer-review-45`, tools.agents.spawn)

C1–C8 verificati ex-novo con censuses propri. CONFERMATI: census API, liste
produttori esatte, byte/pool iniettori, semantica fan-out 0x16F6B0 (gate e
ordine), flussi principali 0x65B5D4, desc. CORREZIONI ACCETTATE E INTEGRATE:
sito duale 0x65B700 (C2); arg press 0x200/0x780 = 0 e libreria oltre
0x80BF60 (C3); tabella callback 0x446808+512+4i, non +i*128 (C5);
percorsi alternativi 0x65B5D4 (attesa 200000, uscita b 0x65B1B8) e
raggiungibilità solo via registro (C6); cancellatori ~96 con regole
proprie, 0x16F97E non coprente per `asl` nel delay slot, 0x16F972 mancato,
12 pool di chiamate indirette (C7). CORREZIONE AL RAPPORTO DELL'AGENTE:
il caso dispatcher che chiama 0x80BE84 è 0x3A (0x80A3E4), non 0x37
(verificato qui). Esito dell'agente registrato in PMB (outbox 403).

## Controesempi, guardie e lezioni di banco

- 0x16F97E [0x5400,0x57FF]: delay slot `asl_s r1,r1,0xa` (bl.d) — un
  census che ignora i delay slot includerebbe un cancellatore inesistente.
- 0x65A898 [0x400C,0x400C]: `bset_s r1,r1,0xe` — idem per le catene bset.
- Il registro p3 ha handler SOLO per 0x381/0x401 a 0x65B5D4: un census che
  cercasse "handler del rilascio" con LE di 0x65B5D6 non troverebbe nulla
  (allineamento listato, lezione binutils it.45).
- `re.match` sulle righe del listato fallisce (colonna file-offset
  iniziale): usare `re.search`; `mov_s?` NON matcha `mov` (underscore
  letterale): usare `(?:mov|mov_s)`.
- Il Runner crea la directory prove e rifiuta directory esistenti
  (lezione it.47 ribadita).

## Limiti

- Statica + 4 casi CPU con stub: nessun hardware, boot, rendering, scatto,
  persistenza; NON_INSTALLARE; circa 10% invariato.
- Il produttore FISICO (bit tasto → evento 0x380/0x400) NON è identificato:
  0x16F6B0 riceve eventi dinamici dalla regione macchina tasti
  0x16F72C..0x16F920 (APERTO, prossimo passo).
- 0x65B5D4 è decodifica statica (pool verificate): il corpo NON è in CPU
  qui; i servizi (149028/14905C/149474/C9BF8/CAD30/CF060/1493BC…) e il
  contenuto runtime di [ctx+4] restano fixture/interpretazione.
- Il percorso anello → WindowManager → registro p3 non è eseguito in questo
  banco (statico, catena it.45); il scheduling runtime e la concorrenza
  restano APERTI; V1.1 vs V1.0.
- La tabella callback della macchina tasti (0x446A08) è fuori dai payload
  verificati: contenuto ignoto.

## Prossimo passo (non ripetitivo)

(a) **Decodifica della macchina tasti**: la funzione 0x16F920 (query
stato tasto per classe evento: id 7→0x380-class, 8→0x400-class, 521
chiamanti) e la regione 0x16F72C..0x16F920 che alimenta 0x16F6B0, per la
mappa bit fisico → evento: è il pezzo mancante del produttore runtime.
(b) Alternativa: CPU dell'handler 0x65B5D4 con stub dei servizi per
chiudere purge+repost in esecuzione. (c) Alternativa: decodifica di
0x65B71C (forward zoom del consumatore, punto it.48(b)).
