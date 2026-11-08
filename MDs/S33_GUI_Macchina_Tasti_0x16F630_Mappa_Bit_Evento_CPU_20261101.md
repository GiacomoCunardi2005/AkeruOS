# Macchina tasti p0 0x16F630..0x16FA00: mappa bit fisico -> evento, installer, scanner, generatore, fan-out e repeat — 1 novembre 2026 (iterazione 50, recuperata e chiusa in it.51)

## Domanda

Punto aperto (a) dell'iterazione 49 ([S33_Vibe_Offline_Checkpoint.md](S33_Vibe_Offline_Checkpoint.md), it.49): decodifica della
macchina tasti che il fan-out 0x16F6B0 (it.49) lasciava aperta come
«produttore FISICO APERTO». Che cosa trasforma l'ingresso fisico in eventi
0x380/0x400 (zoom) e in generale negli id evento della famiglia
classe<<7 (0x180..0x3B01)? Esiste una mappa bit -> evento leggibile
nei byte del dump? La it.50 aveva prodotto verificatore e evidenze PASS
ma la sessione è stata interrotta durante l'attesa dell'agente di
revisione; la it.51 ha rieseguito il verificatore (PASS identica),
completato la revisione indipendente e steso questo rapporto.

## Verificatore

`Python_Trace_Scripts/s33_verify_key_machine_static_map_cpu.py` →
**PASS_KEY_MACHINE_STATIC_MAP_CPU 20261101T220850417476Z** (9/9 casi, questa
sessione). Coppia della it.50 (sessione interrotta, evidenze complete):
**20261101T215644087341Z** e **20261101T215656312452Z**. Confronto
ricorsivo dei tre `verified_evidence.json`: identici tranne `utc`.
Prove:
[Risultati/GUI_S33/key_machine_static_map_cpu_20261101T220850417476Z/](../Risultati/GUI_S33/key_machine_static_map_cpu_20261101T220850417476Z/)
(coppia it.50 nelle directory `..._215644087341Z/` e `..._215656312452Z/`).
Versioni di sviluppo 214652Z..215532Z (fault conservati nelle rispettive
`verified_evidence.json`). SHA tabella descrittori 0x392F04:
`b70d04c2fddac5f1e10101d96e9a8d03c30a861d22bc9621cca448d92c675c1f`.

Regressioni eseguite in it.51 dopo la PASS, senza pipe, exit code 0
verificato: event router producers **20261101T220928377441Z**,
snapshot capture record init **20261101T220935969096Z** (4/4).

## Componenti decodificate

| Componente | Indirizzo | Ruolo |
|---|---|---|
| Installer | 0x16F66C(base,count) | unico chiamante bl 0x16E306 con r0 = pool 0x16E388 = **0x392F04** (tabella descrittori statica nel dump, 16 record stride 20) e r1 = 0x10; per ogni descrittore scrive `byte[0x446808+4*classe+1] = indice` e salva base/count nel ctx **0x3678E4** {+0 abilitato, +4 puntatore array, +8 count} |
| Generatore | 0x16F72C(idx,classe,stato,flag) | stato 1 -> evento `classe<<7`; stato 0 -> `(classe<<7)|1`; al trigger preme `0x17C150(array {classe<<7, (classe<<7)|1}, 2, 1)` |
| Scanner | 0x16F86C(lo,hi,genera) | XOR con lo stato ctx 0x3678F0; per ogni descrittore con bit cambiato calcola il bit `(maschera & stato) >> numero` via 0x335C4C (shift-right 64-bit) e chiama il generatore |
| Sync | 0x16F8EC(lo,hi) | porta il ctx al complemento (TRANSITORIO: lo scanner sovrascrive con l'input netto), setta il byte scanner-armato ctx+0xA (0x3678EE), poi scanner con genera=0: aggiorna SOLO gli stati, NESSUN evento (usato all'init) |
| Query | 0x16F920(classe) | `byte[0x446808+4*classe]` — **521 chiamanti bl** (census congelata) |
| Gate ring | 0x16F950 / 0x16F964 | DUE funzioni separate (correzione it.50 in corsa: 0x16F950 NON cade through): 0x16F950 setta bit0 dei flags e ritorna; 0x16F964 scrive il byte gate 0x3678F9 |
| Fan-out | 0x16F6B0 | fino a 10 callback a 0x446A08+4i con (classe, stato, &evento), SHORT-CIRCUIT al primo esito 0; se `byte[0x3678F9] != 0` e flag-arg != 0 ed esito callback != 0 e 0x16F6A4(classe) bit0 != 0 -> inserisce `(0, evento, r3arg, 1)` nell'anello 0x17BC7C (il «produttore fisico» cercato in it.49). Callback registrate: 0x16E588 (init 0x16E2F4 via 0x16F988) e 0x323A00 (0x323856, revisione) |
| Iniezione | 0x16EC38(lo,hi) e 0x16E3A2(classe,bit) | 0x16EC38 con gate 0x16E6E0; 0x16E3A2 preserva gli altri tasti via 0x16F914 AND-ctx e shift-left 64-bit 0x334E9C; NESSUN chiamante bl -> registrazione indiretta (pool 0x16E390 = 0x16EC38 -> 0x140634; pool 0x16E38C = 0x16E588 -> callback slot via 0x16F988 all'init 0x16E2F4) |
| Init | 0x16E2F4 | legge 0x14066C (= ~0x22C434(), active-low: 1 = premuto) e sincronizza; unico chiamante bl dell'init = 0xC5D9E |

Census bl congelate (verificate dal verificatore): 0x16F66C = 1 (0x16E306),
0x16F8EC = 1 (0x16E336), 0x16F86C = 3 (0x16E3FA, 0x16EC74, 0x16F90A),
0x16F72C = 19 (0x144A82 + 17 siti nella famiglia 0x16E8A6..0x16F176 +
0x16F8D4 scanner; correzione it.54 su revisione cb588-review-52: il
censimento it.51 dichiarava «18 siti nella famiglia», il conteggio
totale 19 era corretto),
0x16F950 = 7 (0x2B37CC, 0x2CA34C, 0x2CABCC, 0x2CAC64, 0x2CBB28, 0x6531DE,
0x6531E6), 0x16F988 = 2 (0x16E30A, 0x323856), 0x16F638 = 1 (0x15AF58),
0x16E2F4 = 1 (0xC5D9E), 0x16F6A4 = 1 (0x16F710), 0x16E3A2 = 0, 0x16EC38 = 0.

## Risultato 1 — mappa bit -> evento (16 tasti, byte del dump a 0x392F04)

Descrittore stride 20: {+0 u32 mask_lo, +4 u32 mask_hi, +8 u8 bit,
+9 u8 classe, +0xA u32 flag (bit15 = repeat armato; per i tasti repeat
contiene press_ev<<16), +0xC u16 press_ev (periodo repeat)}.
Evento press = classe<<7, evento release = (classe<<7)|1.

| Bit | Classe | Evento press/release | Flag (dump) | Repeat (press_ev) |
|---|---|---|---|---|
| 20 | 7 | 0x380 / 0x381 (zoom) | 0 | — |
| 16 | 8 | 0x400 / 0x401 (zoom) | 0 | — |
| 21 | 9 | 0x480 / 0x481 | 0 | — |
| 15 | 10 | 0x500 / 0x501 | 0 | — |
| 31 | 98 | 0x3100 / 0x3101 | 0x01F40000 | 0x1F4 = 500 ms |
| 3 | 3 | 0x180 / 0x181 | 0 | — |
| **12** | **11** | **0x580 / 0x581 (slot AkeruOS)** | 0 | — |
| **7** | **14** | **0x700 / 0x701 (slot AkeruOS)** | 0 | — |
| **8** | **67** | **0x2180 / 0x2181 (slot AkeruOS)** | 0 | — |
| **13** | **78** | **0x2700 / 0x2701 (slot AkeruOS)** | 0 | — |
| 30 | 106 | 0x3500 / 0x3501 | 0 | no repeat |
| 35 | 102 | 0x3300 / 0x3301 | 0x012C0000 | 0x12C = 300 ms |
| 60 | 99 | 0x3180 / 0x3181 | 0x012C0000 | 0x12C = 300 ms |
| 61 | 101 | 0x3280 / 0x3281 | 0x012C0000 | 0x12C = 300 ms |
| 37 | 100 | 0x3200 / 0x3201 | 0x00C80000 | 0xC8 = 200 ms |
| 32 | 118 | 0x3B00 / 0x3B01 | 0x00C80000 | 0xC8 = 200 ms |

I quattro slot logici AkeruOS (it.23) hanno ciascuno un proprio bit
dell'ingresso fisico a 64 bit: **bit12 -> 0x580, bit7 -> 0x700,
bit8 -> 0x2180, bit13 -> 0x2700**. Gli eventi zoom 0x380/0x400 (it.48/49)
corrispondono ai **bit 20 e 16**: il «produttore fisico» lasciato aperto
in it.49 è questa macchina tasti, che il fan-out 0x16F6B0 alimenta
attraverso le callback 0x446A08+4i e l'anello 0x17BC7C.

Nota (revisione kmach-review-51): per le classi < 0x61 l'evento di
rilascio è `(classe<<7)|1` (provato in CPU per la classe 14); per le
classi repeat (>= 0x61 con press_ev != 0) l'evento |1 arriva SOLO dal
callback timer 0x16FA64, e per la **classe 106** (flag 0, press_ev 0)
ogni trigger posta ENTRAMBI 0x3500 e 0x3501: le colonne
press/release della tabella valgono quindi alla lettera solo per le
classi 3..78.

## Risultato 2 — il repeat (classi >= 0x61 con press_ev != 0)

Al primo trigger il generatore posta `classe<<7`, setta il bit15 del
flag del descrittore e arma `0x14905C(0x3678F8, idx, press_ev, 0, 0x16FA64)`;
con bit15 già settato posta `classe<<7` con flag 0 e chiama
`0x1491E8(0x3678F8, idx)` (riarmo/cancel). L'evento `(classe<<7)|1`
per queste classi arriva dal callback timer **0x16FA64** (revisione),
che posta e azzera bit15. Prova CPU: classe 98 (bit31, 500 ms) —
pressione arma il timer con (0x3678F8, 4, 0x1F4, 0, 0x16FA64) e setta
il halfword flag a 0x8000; il rilascio chiama 0x1491E8.

## Casi CPU (9, byte originali, motore pinnato GNU ARC700)

1. **install_sync** — installer + sync: ctx 0x3678E4 {1, 0x392F04, 0x10},
   indice descrittore scritto in `byte[0x446808+4*classe+1]`
   (classi 3,7,8,9,11,14,67,78,98), NESSUN evento/callback/timer
   (sync genera=0).
2. **press_700_query** — pressione bit7: callback (classe 14, stato 1,
   evento 0x700), array 0x17C150 = {0x700, 0x701}, `0x16F920(14) == 1`.
3. **release_701** — rilascio bit7: callback (14, 0, 0x701),
   `0x16F920(14) == 0`.
4. **zoom_pair_380_400** — pressione simultanea bit20|bit16: DUE
   callback (7, 1, 0x380) e (8, 1, 0x400) + i rispettivi array.
5. **repeat_98_arm_cancel** — vedi Risultato 2.
6. **no_change_negative** — scanner senza cambi: NESSUN evento, callback,
   timer o anello (controllo negativo).
7. **ring_gated_press** — gate attivo (0x16F950(14,1) + 0x16F964(1),
   byte 0x3678F9 = 1): la pressione produce ANCHE l'inserimento
   `(0, 0x700, 0, 1)` nell'anello 0x17BC7C.
8. **ec38_runtime_entry** — iniezione 0x16EC38(0x80, 0) con gate
   0x16E6E0: identica alla pressione fisica bit7 (callback + array).
9. **slot_map_all_four** — pressione simultanea bit12|bit7|bit8|bit13:
   QUATTRO callback (11, 1, 0x580), (14, 1, 0x700), (67, 1, 0x2180),
   (78, 1, 0x2700) + quattro array, una sola run per la mappa completa
   dei quattro slot AkeruOS.

Fault marker 0xDEADB001..0xDEADB009. Finestre ORIGINALI dal dump:
`.kmach` 0x16F630..0x16FA64, `.desc` 0x392F04..0x393044,
`.shift64` 0x335C4C..0x335C74, `.shiftl` 0x334E9C..0x334EC4,
`.ec38` 0x16EC38..0x16EC88, `.e3a2` 0x16E388..0x16E41C + millicode.

## Revisione indipendente

Agente `kmach-review-51` (it.51; revisione ex-novo C1..C10 su listato
GNU e byte del dump, controesempi e guardie): vedi sezione aggiornata in
fondo.

## Limiti e confini

- La mappa è **bit dell'ingresso a 64 bit -> evento**, NON ancora
  «pulsante fisico -> bit»: l'identità del pin/GPIO di ciascun bit della
  parola letta da 0x14066C (~0x22C434) è APERTA; la polarità active-low
  è decodifica statica.
- RAM runtime 0x446808..0x446A30 (record tasti + callback) e ctx 0x3678E4
  sono SINTETICI nei casi CPU (gap del dump 0x428600..0x5FE800); nel dump
  il ctx a riposo è zero (payload 1, verificato).
- Le callback reali (prima di tutte 0x16E588) sono stub con log: la loro
  decodifica è statica; 0x17C150/0x17BC7C/0x149028/0x14905C/0x1491E8/
  0x1593AC/0x1594A4/0x16E6E0/0xAD90C sono stub.
- Il wiring runtime (chi chiama 0x16EC38; registrazione 0x140634) è
  evidenza statica (pool 0x16E390).
- I 18 chiamanti del generatore 0x16F72C fuori dallo scanner
  (0x144A82 e 17 siti della famiglia 0x16E8A6..0x16F176;
  precisazione it.54) NON sono decodificati qui.
- V1.1; solo studio offline; NON_INSTALLARE. Nessun hardware, USB, SD.

## Prossimo passo

1. Decodifica della callback reale 0x16E588 (pool 0x16E38C, registrata
   via 0x16F988 all'init) e dei suoi 18 siti di chiamata al generatore:
   è il ponte macchina tasti -> anello -> dispatcher che manca alla
   catena snapshot -> coda -> dispatcher.
2. In alternativa: census dei lettori di 0x14066C/0x22C434 per risalire
   dal bit al sensore/GPIO (identità fisica dei pulsanti, passo verso la
   «mappa dei pulsanti fisici» richiesta dal progetto).

## Revisione indipendente (esito agente kmach-review-51)

Revisione ex-novo su listato GNU (righe 374516..374611 e 376300..376770),
byte del dump letti da
`S33-sections/TBM_blocks/block_01_type1_load_00360800.bin`
(0x392F04 = offset 0x32704), censimenti rg e scansione LE su tutti i 16
blocchi. Verificatore NON rieseguito dall'agente; accordo con le 9
evidenze congelate verificato per confronto diretto.

**C1..C10 tutti CONFERMATI** (installer/struttura descrittori/mappa 16
tasti/generatore/scanner/sync/query 521/fan-out/init e 0x16F950+0x16F964
separate), con queste correzioni integrate in questo rapporto:

1. **Repeat e classe 106 (correzione principale, C3/C4)**: la regola
   «stato 1 -> classe<<7, stato 0 -> (classe<<7)|1» vale SOLO per classi
   < 0x61 (provate in CPU). Per le repeat (98, 99, 100, 101, 102, 118)
   l'evento |1 arriva SOLO dal callback timer 0x16FA64 (posta
   (classe<<7)|1 e bclr bit15); il rilascio con bit15 armato riposta
   classe<<7 con flag 0 + 0x1491E8 (confermato dal caso CPU 5, cb
   (98,0,0x3100) in release). Per **classe 106** (press_ev=0, flag 0)
   OGNI trigger posta ENTRAMBI 0x3500 e 0x3501 (0x16F80E e
   0x16F820->0x16F7EA): la voce «press/release» della tabella per 106 è
   fuorviante, va letta come «impulso doppio».
2. **Secondo callback registrato**: 0x323856 registra **0x323A00** nella
   tabella 0x446A08 via 0x16F988 (pool 0x3239DC), oltre a 0x16E588
   dall'init. Il fan-out fa short-circuit: al primo callback che ritorna
   0 i successivi non sono invocati.
3. **Ctx completo**: {+0 abilitato, +4 base, +8 count, +0xA
   scanner-armato 0x3678EE (settato dal sync, richiesto dallo scanner
   0x16F878), +0xC/+0x10 stato 64-bit = 0x3678F0/0x3678F4}; 0x3678F8
   (timer node) e 0x3678F9 (gate ring) sono celle adiacenti SEPARATE.
4. **Sync**: il complemento in ctx è TRANSITORIO (lo scanner sovrascrive
   ctx con l'input netto); serve solo a forzare tutti i descrittori nel
   generatore con genera=0 per inizializzare i byte di stato.
5. **Gate ring 0x3678F9**: 0x16F964 ha 56 bl + 2 tail-b (ampiamente
   usato); valore nel dump a riposo = 0x01 (già abilitato). Il reset
   0x16F638 inizializza a 1 il halfword flag@2 dei record (bit0
   ring-enqueue ON di default). La 0x16F950 (bit0 alto) è condivisa con
   la GUI: 7 chiamanti esterni, tra cui 0x6531DE/0x6531E6 (handler zoom
   ASLV, it.48).
6. **Query**: census 521 = solo bl; esiste 1 tail-call `b.d` 0x31DD54
   -> 0x16F920 (non contato, coerente).
7. **Input**: 0x14066C = `bl 0x22C434; not_s r0,r0` verificato
   byte-esatto; 0x22C434 legge [0x5545F8+0x30] -> cella **0x554628**
   nel gap runtime non dumpabile: «1 = premuto» è provato a livello
   macchina, la convenzione elettrica del pin resta APERTA. Altri
   lettori di 0x14066C: 0x16B7CE e 0x174E72 lo passano a 0x156468 con
   argomenti log-like (debug), NON alimentano la macchina.
8. **Funzioni della regione non documentate prima**: 0x16F928 (query
   flag>>15 per classi >= 0x61), 0x16F96C (cancel [0x80,0x307F]+
   [0x5400,0x57FF], 0 chiamanti bl), 0x16F9F0 (unregister slot
   callback). 0x17C150: solo 2 bl, entrambi nel generatore; caso
   speciale classe==2 (post extra {0x100,0x101,0x81,0x80}×2, arg 3)
   irraggiungibile dai 16 tasti.
9. **Nessun altro writer statico** (scansione LE su 16 blocchi):
   riferimenti unici a 0x446808 (pool 0x16FA34/0x16FA3C + immediato
   0x16F644), 0x3678E4/E8/F8/F9, 0x446A08 (pool 0x16FA30), 0x392F04
   (pool 0x16E388), 0x16EC38 (pool 0x16E390 -> cella 0x366DE8 via
   0x140634), 0x16E588 (pool 0x16E38C), 0x16FA64. Tabella descrittori
   delimitata (16 record esatti, prima byte-list, poi stringhe ASCII):
   NESSUNA classe mancante.
10. Il generatore 0x16F72C è condiviso: 18 dei 19 bl sono fuori dalla
    macchina (libreria iniettori 0x16E8A6..0x16F176 + 0x144A82); la
    macchina lo usa solo da 0x16F8D4. Il fan-out 0x16F6B0 è chiamato
    anche fuori: 0x20F74E e 0x26C5C2 (coerente con it.23).

Limiti della revisione: statica su listato e byte dumpati; censimenti
limitati a bl/bl_s/bl.d (jl/jump-table non contati); gap RAM
0x428600..0x5FE800 non scandibile; nessuna esecuzione CPU da parte
dell'agente (appunti in PMB outbox 405).
