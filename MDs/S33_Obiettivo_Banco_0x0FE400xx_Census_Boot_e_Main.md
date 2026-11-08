# Banco 0x0FE400xx: census completo Main/TBIB e protocollo boot byte-exact

**Iterazione 19 — 22 ottobre 2026, R0/R1 (studio statico offline).**
Script: `Python_Trace_Scripts/s33_verify_lens_bank_0fe400xx.py` —
Evidenze: `Risultati/Lens_MCU_Interface/Bank_0FE400xx/latest.json` (**evidenza valida 20261022T004729Z**, post-correzioni della revisione indipendente; 20261022T004653Z identica; le cartelle 20261022T003756Z/003835Z sono le prime due esecuzioni complete PRE-audit, PASS ma con regex limm vacua — claim vero, prova incompleta in quelle corse) —
VERIFICATORE: `PASS_BANK_0FE400XX_CENSUS_STATIC`, più esecuzioni exit 0.

## 1. Domanda

Chiudere il punto (b) dell'iterazione 14 ([Sender porta](S33_Obiettivo_Sender_Porta_0x0FF05000_Gate_Strobe.md)): l'identità del banco 0x0FE400xx, lo stesso banco dello scrittore Main 0x301EC0 ([Semantica record](S33_Obiettivo_Semantica_Record_Orchestratore.md)) e dell'arresto GNU DSPv5 in TBIB (store 0x4321→0x0FE40004 a 0x010091F8). La sessione precedente (round 18, interrotta) aveva già isolato i pool TBIB; questa iterazione porta il census a verificatore con asserzioni congelate.

## 2. Metodo

- Census a livello di byte: ogni word a allineamento 2 byte nei 16 payload TBM verificati (sha del manifest) e nel corpo TBIB (base 0x01000000, checksum verificato), con lettura LE e lettura halfword-scambiate (convenzione limm, validata in iterazione 16).
- Classificazione contro i listati GNU objdump `-m arc:ARC700 -EL`: un riferimento REALE è un load pcl (`ld`/`ld_s`) il cui commento `;0xSITE` punta al sito; i commenti di branch NON contano; le istruzioni con la word del sito dentro il flusso decodificato o i dati sono coincidenze.
- Filtro anti-falso-positivo: un `ld_s` autentico non può codificare displacement pcl sopra 0x7C (campo 5 bit ×4); il «load» stampato a payload10 0x1025734 (`[pcl,0x154]`, dentro una regione dati) è scartato da questa regola. La classificazione copre tutte le forme di load pcl (`ld`, `ld_s`, `ld.as`, `ldb.di`, …); la revisione indipendente ha verificato che nessuna `ld.as`/`ldb.di` del TBIB punta a un valore del banco.
- Scansione anti-limm in tre forme (revisione): immediati canonici completi `0xfe4xxxx` (objdump non stampa lo zero iniziale), immediati decimali nel range [0x0FE40000,0x0FE50000), e `movhi` con operando 0xfe4. Un immediato breve isolato come `movl.cl r8,0xfe4` (payload10 0xFFA57E, word 0x0FE44919) NON è un riferimento al banco: carica la costante 16 bit 0xFE4.
- Finestre dedicate allineate (tecnica dell'iterazione 14): dove il pool dopo il `b_s` inghiotte la store nel decode lineare, si disassembla la fetta allineata sull'istruzione reale.
- Modelli Python: bit-modello degli strobe, modello del pacchetto compositore su 65.536 tuple di operandi.

## 3. Census (risultato principale)

**Zero limm/movhi immediati verso il banco in tutte le 17 righe di listato** (16 payload + TBIB): ogni accesso reale passa da pool pcl.

**Lato Main**: gli unici pool load-referenziati con valore banco sono i 4 del corpo 0x301EC0 (0x301EC8/0x301EDC nel decode lineare; 0x301EF0/0x301F04 nascosti dal pool dopo il `b_s`, provati con finestre allineate W3/W4). L'unico altro pool load-referenziato che sfiora il range è 0x26FF8C, il cui valore LE consegnato è 0x00270FE4, NON un indirizzo del banco: coincidenza dell'ordine delle halfword. **Payload 1..15: zero riferimenti reali; nessun reader Main del banco esiste** (negativo statico). Tutti gli altri siti (p0=24, p1=44, p2=12, p3=12, p4=14, p5=18, p6=8, p9=6, p10=30, p11=4, p12=8, p13=14; p7/p8/p14/p15=0) sono coincidenze congelate per riproducibilità byte-exact.

**Lato TBIB**: 74 siti totali, di cui **37 pool reali** (36 referenziati da load nel decode lineare + 0x1009214 provato con finestra allineata) verso **17 registri distinti**:

| offset | 00 | 04 | 08 | 0C | 10 | 18 | 1C | 20 | 24 | 28 | 2C | 30 | 34 | 40 | 44 | 48 | 4C |
|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|
| pool | 7 | 1 | 2 | 2 | 1 | 1 | 1 | 1 | 1 | 1 | 1 | 1 | 1 | 3 | 3 | 3 | 3 |

Il registro **+0x14 non è mai riferito** da nessun payload o TBIB. Tutti gli accessi al banco sono halfword `.di`.

## 4. Scrittore Main 0x301EC0 (finestre allineate + word raw dei pool)

Corpo completo (idioma identico al boot: coppia di `ld_s` + `b_s` sopra i pool + `sth.di`):

```
0x4321 -> 0x0FE40004,  0x6641 -> 0x0FE40008,
0xE972 -> 0x0FE4000C,  0xFFFF -> 0x0FE40010,  pop_s blink, j_s [blink]
```

Il Main ri-emette il comando magico 0x4321 del boot e tre parametri; la rotta è quella API stato/tuning (payload4 CCD_Tune_DVT opcode 0x33 → 0x301E1C → 0x301EC0 prima di 0x29E8F0, iterazione 8).

## 5. TBIB: routine 0x10091E4 (l'arresto GNU DSPv5 è il suo primo store)

Sequenza byte-exact (finestra allineata T1/T2 per le parti nascoste + tratto lineare):

| store | registro | valore |
|---|---|---|
| 0x10091F8 (arresto DSPv5) | 0x0FE40004 | 0x4321 |
| 0x100920C (allineata) | 0x0FE40008 | 0xFFFF |
| 0x1009218 / 0x1009224 | 0x0FE4000C / 0x0FE40010 | 0xFFFF / 0xFFFF |
| 0x1009234..0x1009258 | +0x18..+0x24 | 0 |
| 0x1009268 | 0x0FE40028 | 0x2 |
| 0x1009278 | 0x0FE4002C | 0x100 |
| 0x1009284 / 0x1009290 | 0x0FE40030 / 0x0FE40034 | 0 / 0 |

Poi `b.d 0x103E158` con `mov_s r0,r13` nel delay slot. **Il piano GNU «routine 0x10091E4 e protocollo FE40004 senza azzeramenti indiscriminati» (mappa RAM, checkpoint AUX/IRQ) è ora sbloccato offline**: l'emulatore può modellare le 11 scritture invece di fermarsi alla prima.

## 6. Compositori 0x100929C → +0x08 e 0x10092D8 → +0x0C

Entrambi scrivono l'halfword pacchizzato da 4 operandi:

```
((r0<<13)&0xE000) | ((r1<<8)&0x1F00) | ((r2<<4)&0xF0) | (r3&0xF)
```

Modello Python su 65.536 tuple esatto; i valori Main 0x6641 (campi 3,6,4,1) e 0xE972 (7,9,7,2) sono scritture pacchizzate dello stesso formato su +0x08/+0x0C. Tail call 0x103E158 con `mov_s r0,0`.

## 7. Strobe su +0x00 e poll su 0x0FFCA008

- Routine 0x1000CF2 e 0x1001472 (copie): `ldh.di r10,[r13]` con r13=0x0FE40000, poi **bset9, bset8, bclr9** (modello: 0→0x200→0x300→0x100: bit8 resta, bit9 impulsato) via `sth.di`; subito dopo caricano r14=**0x0FFCA008** (pool 0x1000D28/0x10014A8) e fanno **poll di bit0** a 0x1000D74–0x1000D7A: la stessa linea ausiliaria usata dalla famiglia porta obiettivo (0x25E0D4 set/clear bit0 di 0x0FFCA008).
- Variante 0x1000FF6: **bset9, bclr8** sul registro base.
- Il poll della sequenza A (0x1000F84) usa pure r14=0x0FFCA008, caricato però dal pool **0x1000D94** a 0x1000D8E (precisazione della revisione; pool aggiunto alle asserzioni). Unica lettura aggiuntiva verificata dalla revisione: le `ldh.di r0,[r0]` a 0x1000F54/0x10016E0 leggono 0x0FE80070/0x0FE80124 (famiglia clock 0x0FE8xxxx), NON il banco. In tutto il TBIB le uniche letture del banco sono i RMW `ldh.di` su +0x00.

## 8. Sequenze di init TBIB

- **Sequenza A** (0x1000EEC..0x1000FEA, copia a 0x100167C..): +0x40=0x2020 (`mov 0x20`+`bset 13`), +0x44=0xF80 (0x1F<<7), +0x48=0x300 (768), +0x4C=r16 (argomento della routine), base +0x00=0x0A poi 0x20A; RMW bit 12..15 su 0x0FE80070/74; poll 0x0FFCA008 bit0; poi +0x40=**0x216F**, +0x44=0x3F, +0x48=0x216F, +0x4C=0x3F; infine scrittura **1→0x0FFCA008** e tail 0x103E138.
- **Variante C** (0x1001710): 0x216F/0x3F ripetuti su +0x40/+0x44/+0x48/+0x4C, poi 1→[r14].
- Nota strumentale: i value pool si leggono come word LE dai byte raw (il pool a 0x1000FA8 è 0x0000216F; objdump stampa le halfword 0x216F/0x0000 — non invertire).

## 9. Identità della periferica (inferenza, NON fatto)

- **ESCLUSO DDR**: i registri DDR del BFN stanno a 0x0FE2xxxx ([BFN/DDR](S33_BFN_NAND_DDR_e_Configurazione_Persistente.md)), non 0x0FE4xxxx.
- Il banco è una periferica init da boot con: registro base a +0x00 con bit-strobe 8/9, comando magico 0x4321 a +0x04, parametri pacchizzati a 4 campi su +0x08/+0x0C, coda di config a +0x10..+0x34 e +0x40..+0x4C, handshake ready su bit0 di 0x0FFCA008 e RMW di clock 0x0FE80070/74 prima del poll.
- Il solo scrittore Main è sulla rotta tuning CCD (payload4), immediatamente prima del dispatch dell'orchestratore obiettivo 0x29E8F0: coerente con un blocco analogico/di potenza riarmato dal tuning prima di comandare l'obiettivo; **nessuna identificazione del blocco siliconico è possibile dai soli byte** (nessun datasheet pubblico del SD10P220). La revisione indipendente propone come inferenza un blocco di controllo sistema/clock-PLL/power-management (esclusi DDR e porta MCU obiettivo); resta aperta.

## 10. Limiti

- Statico: nessun runtime, emulazione o prova hardware; semantica dei bit = inferenza dal pattern.
- Il negativo «nessun reader Main» non esclude letture indirette calcolate, DMA o alias.
- Le finestre allineate provano i byte delle istruzioni reali nei punti nascosti al decode lineare; il resto del TBIB resta listato lineare (le regioni dati possono produrre falsi positivi, filtrati dal limite di displacement). Revisione: i 6 siti LE «instr» di payload0 (word di istruzioni 32-bit coincidenti) e gli analoghi non sono stati esclusi come pool nascosti con finestre allineate esaustive (solo i 3 casi noti); rischio residuo basso, non formalmente chiuso.
- Il tratto TBIB 0x1000D84..0x1000EEC (funzione init) è decodificato in modo inaffidabile nel listato lineare; la non-ridefinizione di r14 fra 0x1000D8E e 0x1000F84 è controllata solo su quel decode (revisione).
- Il valore runtime di r16 (scritto su +0x4C) e la semantica dei bit strobe/ready restano inferenza. V1.1 campione locale; macchina nei log V1.0. Circa 10% di avanzamento funzionale invariato: nessuna applicazione avviata, nessuna foto. NON_INSTALLARE.

## Revisione indipendente

Agente `bank-0fe400xx-audit` (tools.agents.spawn, configurazione ereditata; lo strumento «task con agente explore» non esiste in questo ambiente): census rifatto da zero in /tmp (nessuna scrittura nel progetto). Verdetto: tutti i punti 1–7 CONFERMATI. Correzioni accolte nello script: (a) la prima regex anti-limm era vacua (objdump stampa `0xfe40004` senza zero iniziale e a volte decimali) → sostituita con scansioni indirizzi-completi + decimali + movhi; (b) `LOAD_LINE` estesa da `ld|ld_s` a tutte le forme load pcl; (c) aggiunto il pool 0x1000D94 del poll della sequenza A e i poll reali 0x1000D74/0x1000F84; (d) rimosso un loop morto. Il claim «zero limm verso il banco» era VERO anche prima (l'agente lo ha verificato con scansione raw ME: tutti i 37 siti ME del TBIB sono straddle a LE+2 degli stessi pool); la correzione rende la prova effettiva.

## 11. Prossimo passo

**Aggiornamento 22 ottobre 2026, integrazione emulatore:** l'opzione GNU 1 sotto è superata: `s33_verify_gnu_boot_device_writes.py` e `s33_verify_gnu_boot_control_cluster.py` avevano già eseguito gli store TBIB e proseguito ai limiti successivi ([AUX/IRQ](S33_GNU_AUX_Interrupt_e_Fonti_Archiviate.md)). Il [nuovo profilo runtime P-code](S33_Emulatore_Runtime_GPIO_Timer_Service_Request.md) include ora il banco con store halfword espliciti e letture bloccate; verifica anche i quattro store Main originali. Queste prove non identificano la periferica e non completano il boot. La proposta originaria resta sotto per provenienza storica.

Due opzioni non ripetitive:
1. **GNU**: integrare la sequenza 0x10091E4 nel profilo DSP (scritture halfword al banco invece dell'arresto a 0x10091F8) e verificare fino a quale PC procede il TBIB con il banco modellato — sbloccato da questa iterazione.
2. **Statico**: censire i chiamanti TBIB delle routine del banco (0x10091E4 e sequenza A: chi le invoca nel flusso boot) per collegare l'init della periferica alla sequenza di avvio e restringere l'identità.
