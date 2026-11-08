# Reattori del registro notifiche globale p1: slot 0x700 e 0x2180, ingresso 0x4006 — decodifica e CPU (iterazione 23, 1° novembre 2026)

## Domanda

Punto aperto (a) del checkpoint it.21/it.47
([S33_GUI_Router_0x169F60_p5_Default_Catena_Esclusioni_CPU_20261101.md](S33_GUI_Router_0x169F60_p5_Default_Catena_Esclusioni_CPU_20261101.md)):
la catena di consegna snapshot→coda→dispatcher→finestra→callback→router→registro
terminava in stub; il passo richiesto era «decodificare e provare in CPU il
reattore 0x20F414 (evento 0x4006 corretto) e i reattori slot
(0x700→0x20EAF4, 0x2180→0x20E940, 0x580/0x2700)».

**Domanda tecnica precisa.** Che cosa fanno i reattori del registro notifiche
globale p1 (base 0x3E8BB4, [it.21](S33_GUI_Router_0x169F60_p5_Default_Catena_Esclusioni_CPU_20261101.md))
per gli eventi 0x0700 (slot pulsante 1 candidato), 0x2180 (slot 2 candidato)
e 0x4006: quali celle leggono, quali gate applicano, quali notifiche/ventane
richiedono, e come si collega tutto alla guardia CaptureMenu e alla coda
eventi già studiate?

## Metodo

- Analisi statica con GNU objdump ARC700 su finestre carve dai payload
  verificati (`s33_trace_state_dispatch.verified_payloads`, hash SHA-256);
  LE scan a ogni allineamento (16 payload) con `le_scan`; census dei
  chiamanti bl dal listato GNU `Risultati/Disassemblati/Firmware1.1.asm`.
- Verificatore nuovo
  [s33_verify_notify_reactors_cpu.py](../Python_Trace_Scripts/s33_verify_notify_reactors_cpu.py):
  **16 casi CPU** su byte ORIGINALI del firmware, simulatore GNU ARC700
  (arc-elf32-run, hash invariato). Getter/setter/millicode/aiuti costanti
  ORIGINALI (finestre byte-identiche, verificate ELF↔payload a ogni build);
  stub SOLO ai call-site profondi, con trampolino `push_s blink / mov r7,sid /
  mov r12,logger / jl_s [r12] / pop_s blink / j_s [blink]` verso un logger
  condiviso (contatore 0x367000, voci {id,r0,r1,r2} a 0x367100+16k, tabella
  ritorni per-sid a 0x367400). Sondaggio di asserzioni a indirizzi assoluti;
  fall = 0xDEADB001..0xDEADB010 al successo, marker 0xDEAD0000+case*0x40+i
  per singolo assert fallito.

**Esiti.** `PASS_NOTIFY_REACTORS 20261101T160819606803Z` (16/16) +
riesecuzione **160829082666Z** identica salvo `utc`; evidenza finale
**161952929543Z** (post-audit: inventario `windows` completato con la
finestra pool `.pool6` 0x20F790, SHA
3cf860b49b7de1895318fe996b2b22a77e799e8675e4a2432e18ac5d75c917b6; le
altre finestre e i cpu_cases sono byte-identici alla prima run,
confronto programmatico). Prove:
[Risultati/GUI_S33/notify_reactors_cpu_20261101T161952929543Z/](../Risultati/GUI_S33/notify_reactors_cpu_20261101T161952929543Z/)
(finale), [prima run](../Risultati/GUI_S33/notify_reactors_cpu_20261101T160819606803Z/),
[riesecuzione](../Risultati/GUI_S33/notify_reactors_cpu_20261101T160829082666Z/).

## Risultato 1 — statica: i tre reattori sono callback puri del registro

- **Registro p1 completo** (67 record, R66 terminatore {0,0}): R02
  {0x0080, **0x20E940**}, R11 {0x0700, **0x20EAF4**}, R19 {0x2180,
  **0x20E940**} — lo STESSO handler di 0x0080, R58 {0x4006, **0x20F414**}.
  **0x0580 e 0x2700 NON sono nel registro globale**: gli altri due slot
  logici pulsante non hanno reattore p1 (coerente con la lista di
  esclusione 0x99ACAC della finestra p5, che li contiene, it.21/it.45).
- **Zero chiamanti bl** per i tre reattori nel listato GNU; LE scan a ogni
  allineamento: le uniche parole a 4-allineati con i loro indirizzi in
  TUTTI i 16 payload sono i campi handler del registro (0x20E940→0x3E8BC8 e
  0x3E8C50; 0x20EAF4→0x3E8C10; 0x20F414→0x3E8D88). Callback puri: si
  raggiungono SOLO via router 0x169F60.

## Risultato 2 — reattore 0x20EAF4 (evento 0x0700): apertura condizionale CaptureMenu

Decodifica completa (0x20EAF4..0x20EB32, epilogo condiviso 0x20E836→pop
0x334194, prologo bl 0x33412C = push r15,r14,r13):

```
stato := byte[0x365753]            (getter ORIGINALE 0xCAD5C, pool 0xCAD58)
se stato == 2:  0x1453E4(sexw(word[0x365776]), 0)   (getter ORIGINALE 0xCD9C8)
se stato == 1:  0x1453E4(2, 0)                      ← ID 2 = CaptureMenu
altrimenti:     nessuna notifica
```

**Casi CPU 1-4** (byte originali): stato 1 → notifica (2,0) unica; stato 2
con word 0x1234 → (0x1234,0); stato 2 con word 0x8002 → **(0xFFFF8002,0)**
(la `sexw` ORIGINALE segna-estende l'indice di finestra: negative control
verificato); stato 0 → contatore chiamate 0. **Precisazione della banca
sintetica storica «0x700 → ID 2, arg 4»**: il reattore reale richiede ID 2
con arg 0 e SOLO se byte[0x365753]==1; con stato 2 la destinazione è
l'indice word[0x365776], non ID 2. Cell 0x365753 = struct CaptureMenu
0x365750+3 (stessa struct della guardia +1 e del flag +0x5C).

## Risultato 3 — reattore 0x20E940 (eventi 0x0080 E 0x2180): gate, modo-2, cancel-code e richiesta finestra 0x87

Decodifica completa (0x20E940..0x20EA5C, epilogo condiviso 0x20E932→pop
0x334184, prologo bl 0x334124 = push r17,r16,r15,r14,r13):

1. **Gate d'uscita**: byte[0x365756]==2 (getter 0xCB4A8, pool 0xCB4A4) →
   esci; byte[0x365753]==3 → esci.
2. **Gate coda**: `0x17BE18(0, 0x3101, 0x3101)` (ORIGINALE non eseguita,
   stub) — 0x17BE18 è una QUERY A INTERVALLO sulla coda ad anello (base
   0x47A848, stride 12, indici read/write 0x367BBC, 128 voci, anello
   bmsk 0x7F — stessa coda di it.45): match se il campo nodo
   corrisponde (o a==0) e l'evento è nell'intervallo [r13,r15]; qui
   degenere su [0x3101,0x3101] = «è già in coda una notifica 0x3101
   (registro R26)» → **la pressione viene scartata**. È il meccanismo di
   scarto delle pressioni obsolete che la coda AkeruOS deve replicare.
3. **Gate configurazione (doppio)**: cfg[0x61] (lettura tabella
   ORIGINALE 0x16F920: byte a 0x446808+id×4, pool 0x16FA34) confrontato
   con l'aiuto costante ORIGINALE 0x16E41C (ritorna SEMPRE (42,0) e
   costruisce {42,0} sullo stack, qualunque sia l'argomento 0xB/0xC): il
   confronto è ripetuto DUE volte (0x16E41C(0xB) a 0x20E97E e
   0x16E41C(0xC) a 0x20E994) — se cfg[0x61]==42 → esci al primo. La
   tabella 0x446808 è RAM runtime (gap 0x428600..0x5FE800, NON in
   nessun payload verificato): valore reale ignoto, nel banco fixture.
   Il CPU-case `r2180_gate_cfg61` con cfg[0x61]=42 esce senza notifiche
   e VERIFICA la scalatura ×4 (add2) della lettura: con scalatura
   errata leggerebbe 0 e non uscirebbe.
4. **Gate id precoce**: resolver ORIGINALE 0x1453FC ([[0x14579C]]→
   [0x366EA4]≠0 → flag-check 0x14504C(ptr,4) → sexw) chiamato DUE volte
   prima del blocco modo: id==1 → esci (0x20E9AA), id==0x7E → esci
   (0x20E9B0).
5. **Blocco modo-2** (solo se byte[0x365753]==2): chiama 0x817BD8, gate
   0x177484, 0x14941C/0x17743C, 0xBBC04(4), 0xD0080, poi selettori con
   modo 0xCAD30 (ORIGINALE, byte 0xC8E80C) e id finestra corrente:
   5 / 158 / modo 0x37 / 0x5E / 0x4D selezionano il sotto-percorso
   0x20ea18 → **0xCBDF8 + 0x177030** (transizione, la stessa coppia
   dell'uscita modo di scatto it.41/it.42).
6. **Coda e richiesta**: in ogni caso che supera i gate
   (0x20ea20): **CANCEL** di 0x81, 0x80, 0x101, 0x100 con l'argomento del
   reattore via 0x17C074(0,id,arg) — 0x17C074 è la cancellazione dalla
   coda ad anello (scansione, match {arg0,evento,arg}, evento azzerato a
   +4 con `stw 0,[r3,4]` a 0x17C0BA, decodifica statica; stride 12, base
   0x47A848, indici 0x367BBC) — e infine **0x1453E4(0x87, 0)**:
   richiesta della finestra ID 0x87 (135). L'ID 0x87 è lo stesso
   richiesto dai percorsi impostazioni (it.42/it.43) e gatesato dal
   reattore 0x4006 (v. risultato 4).

**Casi CPU 5-11** (byte originali): gate 0x365756 (contatore 0), gate
0x365753, gate coda (query loggata (0,0x3101,0x3101), nessuna notifica),
gate cfg61, pass-through (4 cancel esatti + (0x87,0)), modo-2 con id=5
(18 chiamate loggate in ordine esatto, incluse 3×resolver), modo-2 con
id=0x5E e 0xCE6E8→0 (0xCBDF8+0x177030 + cancel + richiesta, 20 chiamate).

## Risultato 4 — reattore 0x20F414 (evento 0x4006): ingresso, azzeramento guardia, dispatch argomento

Decodifica del blocco di ingresso (0x20F414..0x20F524; il corpo completo
arriva a 0x20F8CC e il ramo 0x63 non è CPU-provato qui):

1. byte[0x36575B] (getter ORIGINALE 0xC9BF8, pool 0xC9BF4 — struct
   CaptureMenu+0xB) == 0 → **uscita immediata** 0x20F878 = 0xD008C(0) +
   epilogo 0x20F8C0 → pop 0x33417C (prologo bl 0x334120 = push r18..r13).
2. **Guardia**: getter ORIGINALE 0xCA310 ([0x365751]); se guardia ≠ 7 il
   setter ORIGINALE 0xCA2F4 scrive **0**: la notifica 0x4006 ripulisce una
   guardia stantia (it.39-40) prima di ogni altra cosa.
3. **Dispatch su extb(argomento)**:
   - **0x65** → `0x1443C0(node, 0, cfg[0x65] | 0xC0000000)` (0x1443C0 è il
     reattore del registro per 0x3281: NOTIFICA verso finestre) + 0xD008C(0)
     + **byte[0x36972D] := 0x210BC8()** + gate modo 0xCAD30==0x2C, POI
     gate **0xD0924()==0** (0x20F47A, prima dei check id; NON coperto dai
     casi CPU) con id {135 (0x87!), 6, 167} → 0xD08C8 + 0x201830(x,1).
   - **0x63** (solo statico, NON CPU-provato): [fp,-4]:=0,
     **[0x369735]:=1** (pool 0x20F794=0x36972C+9), 0x137774, cfg[0x63] con
     0x16F920, `0x17BE80(0, 0x3181, 0)` (post alla coda), 0x12B8E8/0x12B888
     su [0x36972C+0x12/0x15] → uscita. I pool a 0x20F798..0x20F7A4
     contengono gli eventi 0x3181/0x3081/0x3B81 dei ponti it.43-44.
   - {1, 0xC, 0x62, 0x66, 3} → gate 0x177484 (beyond: NON provato qui).
   - altro → uscita.

**Casi CPU 12-16** (byte originali): inattivo (guardia intatta 0xA5, solo
0xD008C); guardia 5 → setter ORIGINALE scrive 0, vicini 0xA5 intatti;
guardia 7 → NESSUNA scrittura; arg 0x65 con cfg[0x65]=0x5A e modo 0x10 →
0x1443C0 riceve (node,0,0xC000005A), byte[0x36972D]==0x77 con vicini
intatti, uscita al gate modo; arg 1 → gate 0x177484→esci.

## Collegamenti con i dossier precedenti

- La catena it.45/21 ora è chiusa fino al reattore: produttore→0x169EB4→
  coda→ciclo→0x169E1C→resolver→router 0x169F60→registro p1→**reattori
  (questa iterazione)**. Il reattore 0x4006 è anche il PRODUTTORE di
  notifiche verso 0x1443C0 (reattore 0x3281) e di transizioni 0xCBDF8:
  il registro notifiche è un MOLTIPLICATORE di eventi, non solo un
  consumatore.
- 0x1453E4(idx,arg) = wrapper di notifica finestra (it.18/47, 580
  chiamanti): qui i reattori lo usano con idx ∈ {sexw(word 0x365776), 2,
  0x87}.
- Le celle 0x365753/0x365756/0x36575B appartengono alla struct CaptureMenu
  0x365750 (guardia +1, flag +0x5C, it.39-40): i reattori slot leggono
  lo stato del menu CaptureMenu per decidere.
- L'evento 0x2180 e l'ID 0x87 collegano lo slot 2 candidato al filone
  impostazioni (it.30/31 ottobre) e al gate 0x7F6824 (it.21: 0x2180 è nel
  gate [0x80,0x307F] e nella lista di esclusione 0x99ACAC della finestra
  p5): coerente con un instradamento DUPLICATO finestra/registro.

## Controesempi e aggiunte dell'audit indipendente (agente `reactor-audit-23`)

C1-C8 CONFERMATI byte-esatti (C5 PARZIALE: le due omissioni sopra sono ora
documentate; asserzioni del verificatore invariate). Aggiunte accettate e
riverificate nel metodo dell'audit (ridisassembly ex-novo, census propri,
evidenze congelate solo rilette):

- **Registro finestra p3 0x783B08..0x783C40** (payload3, terminatore
  default (0, 0x20E814) a 0x783C40): **0x0580/0x0700/0x2180/0x2700 →
  0x65C46C** e 0x0581/0x2701 → 0x65C6B4. I quattro slot logici pulsante
  hanno DUNQUE handler in una tabella di finestra p3 (AutoScene-family,
  payload 3 = dove vive CaptureImage/0x65959C): la mancanza dal registro
  globale p1 NON significa «senza handler». La tabella p5 0x99AB8C
  conferma invece 0x2180→0x7F7F8C e 0x0700→0x7F833C (nessun 0x580/0x2700);
  il registro gemello 0x3EB554 (it.21) non ha slot pulsante.
- **Compagni delle celle** (altri accessi oltre ai pool citati):
  0x365753 — setter 0xCAD38 (stb sullo stesso pool 0xCAD58) e secondo
  getter 0xCD8CC via pool 0xCD8F0; 0x36575B — setter 0xC9BDC (pool
  0xC9BF4, è anche il callee del ramo 0x63); 0x365776 — word setter
  0xCD9AC (pool 0xCD9C4); 0x365756 — candidato writer 0xCA5DE
  (`stb [r13+6]:=0xDE398()` a 0xCA60A, base da chiamante, pool
  0xCA5D4=0x365750); 0x36972D — NESSUN altro accesso (pool 0x20F790
  unico; i pool su 0x36972C usano altri offset).
- Nessun bl/jl/riferimento ai tre reattori oltre al registro (listato,
  LE a ogni allineamento nei 16 payload e firmware.bin intero: zero).
- Finestre del verificatore: nessuna sovrapposizione fra le 21 finestre
  originali; stub mai dentro finestre originali; gap minimo 36 byte nel
  trio 0x17743C/0x177460/0x177484; fixture/probe/stack disgiunti.
- Inventario `.pool6` completato nell'evidenza finale 161952929543Z
  (SHA sopra).

## Controlli negativi e lezioni di banco

- sexw negativo (word 0x8002 → indice 0xFFFF8002) — prova che l'indice di
  finestra può segno-estendersi.
- Gate cfg61 con fixture 42: verifica la scalatura ×4; il pass-through
  con 0x29 NON la distinguerebbe da sola.
- Guardia 7 → setter MAI chiamato (controllo per-no-write); guardia 5 →
  vicini 0xA5 intatti.
- LEZIONI DI BANCO (nuove, per il methodo): (1) il taglio di una finestra
  PRIMA dell'ultima istruzione (j_s [blink] / b_s) manda l'esecuzione in
  memoria zero del sim → loop `b 0x0`/`b se stesso`: verificare SEMPRE che
  la finestra includa l'istruzione di ritorno (accaduto su W_RES hi
  0x145412→0x145414 e W_EXIT6 0x20F87E→0x20F880); (2) i POOL letti con
  pcl devono stare DENTRO la finestra (0x20EA58 escluso → jl_s [r14=0] →
  loop su 0x0; 0x20F790 escluso → store a [0]); (3) uno stub che usa
  `jl_s` SOVRASCRIVE blink: senza push_s/pop_s il logger rientra dentro lo
  stub e loopa (12M istruzioni, fault progressivo sopra lo stack); (4)
  stub ≥ 20 byte non coesistono a 12/36 byte di distanza: trampolino
  20-byte con logger condiviso e tabella ritorni in fixture.
- Il b 32-bit negativo piccolo (−758, 0x20EB2E→0x20E836) e il b_s −282
  (0x20EA4E→0x20E932) sono eseguiti CORRETTAMENTE dal sim: la divergenza
  it.44 riguarda solo i displacement negativi GRANDI.

## Limiti

- Statica + 16 casi CPU con fixture: nessun hardware, boot, rendering,
  scatto, persistenza. NON_INSTALLARE; circa 10% invariato.
- 0x17BE18/0x17C074/0x1453E4/0x177484/0x1443C0/0xD008C/0x210BC8 e il
  blocco modo-2 (0x817BD8, 0x177460, 0x14941C, 0x17743C, 0xBBC04,
  0xD0080, 0xCE6E8, 0xCBDF8, 0x177030) sono STUB: le loro semantiche sono
  decodifica statica (0x17C074 cancel-coda) o ipotesi di lavoro.
- Il ramo arg 0x63 e il seguito del gate 0x177484 in 0x20F414 NON sono
  CPU-provati; il corpo oltre 0x20F524 non è decodificato.
- La tabella cfg 0x446808 è RAM runtime: i valori cfg[0x61]/cfg[0x65]
  REALI restano ignoti (fixture nel banco).
- 0x580/0x2700: si prova che NON sono nel registro p1; i loro handler
  candidati sono ora noti nel registro finestra p3 0x783B08 (→0x65C46C,
  con 0x581/0x2701→0x65C6B4) ma NON sono decodificati né provati qui
  (APERTO).
- Producers/schedulazione runtime dei tre eventi non provati; V1.1 vs
  V1.0.

## Prossimo passo (non ripetitivo)

(a) **Decodifica e CPU dell'handler p3 0x65C46C** (registro finestra
0x783B08: riceve TUTTI e quattro gli slot logici pulsante
0x580/0x700/0x2180/0x2700, più 0x65C6B4 per 0x581/0x2701): è il
collettore che manca per distinguere i quattro pulsanti fisici e il
primo candidato gestore «pulsante 3» (0x2700). (b) Alternativa: CPU del
callback finestra 0x7F6824 con lista esclusione 0x99ACAC e tabella
0x99AB8C (punto (b) di it.21, ancora aperto): tre percorsi (in-range
gestito direttamente, out-of-range escluso, out-of-range inoltrato).
(c) Alternativa: decodifica del ramo 0x63 di 0x20F414 (scritture
[0x369735], 0x137774, 0x17BE80(0,0x3181,0), 0x12B8E8/0x12B888) per
collegare il reattore 0x4006 ai ponti guardia it.43-44. Non rieseguire
il verificatore di questo punto: è CHIUSO.
