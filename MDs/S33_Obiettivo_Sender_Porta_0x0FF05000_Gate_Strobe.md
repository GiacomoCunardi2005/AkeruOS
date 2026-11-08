# Sender porta obiettivo decodificato byte-exact: primitive 0x0FF05000, gate, strobe e sender 0x25CB3C/0x25CB54

**Data:** 22 ottobre 2026 (iterazione 14 del ciclo Vibe persistente) · **Tappe:** R0/R1 · **Esito:** PASS statico, chiude il punto (a) dell'iterazione 12, nessun hardware toccato · **Stima complessiva: circa 10 % invariata**

- Script riproducibile: [Python_Trace_Scripts/s33_verify_lens_port_sender.py](../Python_Trace_Scripts/s33_verify_lens_port_sender.py)
- Evidenze: [Risultati/Lens_MCU_Interface/Port_Sender/latest.json](../Risultati/Lens_MCU_Interface/Port_Sender/latest.json) (evidenza valida `20261022T000501Z`: 24 finestre GNU allineate salvate come `window_*.txt`, 18 pool + 9 word raw letti dai byte raw del payload0, 17 risoluzioni ld_s pcl verificate, modelli Python su tutti i 65.536 valori del registro strobe). Le cartelle `20261022T0003xx–0004xx` sono le esecuzioni di calibrazione fallite dello stesso script (nessun `verified_evidence.json`, non sono evidenze).
- Chiude il punto aperto (a) dell'iterazione 12 ([Split paths](S33_Obiettivo_Split_1EDED8_1EDFDC_Byte_Wire.md)): «byte-decodificare il sender 0x25CB3C/0x25DF24/0x25E064 fino alla sequenza di halfword sulla porta 0x0FF05000 e al gate/strobe», inclusi i residui 0x25DFxx/0x25DExx e il **qualificatore della store di porta**.
- Agente `port-sender-audit` (revisione indipendente, configurazione ereditata): esito in §9.

## 1. Domanda e metodo

Come i byte del dizionario wire {00,10,30,50,60,70,80,D0,FF} arrivano fisicamente alla porta 0x0FF05000 e quali registri governano gate e strobe. Metodo consolidato: finestre GNU ARC700 allineate a ogni ingresso (24 finestre, incluse finestre dedicate allineate sull'istruzione di accesso perché il pool pcl inghiotte la store nella finestra lineare), pool riletti come word LE dai byte raw, word raw delle istruzioni di accesso asserite direttamente, risoluzioni `ld_s [pcl,u6]` non scalate verificate per ogni sito, modelli Python delle trasformazioni RMW.

## 2. Le primitive della porta (qualificatore chiuso)

| Funzione | Corpo byte-exact | Note |
|---|---|---|
| `0x25E064(r0)` | `sth.di r0,[0x0FF05000]` | scrittura **halfword .di** dei 16 bit bassi di r0 |
| `0x25E078(r0)` | `sth.di r0,[0x0FF05000]` | copia identica (usata via registro dal sender descrittore) |
| `0x25E0A4(r0)` | `sth.di r0,[0x0FF05000]` | terza copia identica |
| `0x25E08C()` | `ldh.di r0,[0x0FF05000]` + `extb_s r0,r0` nel delay slot del ritorno | ritorna **solo il byte basso** zero-extended |
| `0x25E0B8()` | `ldh.di [0x0FF04024]` + `lsr 7` + `bmsk 0` nel delay slot | bit 7 di 0x0FF04024 |
| `0x25E0D0()` | tail `ld_s r0,[pcl,0x14]` nel delay slot del `j_s.d [blink]` | ritorna la costante 0x0FF05000 (getter dell'indirizzo porta) |
| `0x25E0D4(sel)` | RMW halfword .di su 0x0FFCA008 | `r0==1` → bclr bit 0, altrimenti bset bit 0 (banco ausiliario, contesto) |

I tre corpi di scrittura sono identici (pool 0x25E06C/0x25E080/0x25E0AC = 0x0FF05000 raw; word raw `sth.di r0,[r1]` = 0x00241900 asserita a 0x25E070/0x25E084/0x25E0B0; lettura `ldh.di r0,[r0]` = 0x09001000 a 0x25E098/0x25E0C4). **Il qualificatore lasciato aperto dall'iterazione 12 è chiuso: halfword `.di` su entrambi i lati**, e la lettura restituisce solo il byte basso: il wire è un payload a 8 bit sul byte basso della porta a 16 bit, coerente con i byte del dizionario iniettati come `mov r0,0xNN` nei delay slot dei `bl.d` verso 0x25CB3C.

## 3. Gate e strobe (RMW protetti)

- **Gate**: `0x25DEAC` pulisce **bit 4 di 0x0FEF03A8** e **bit 6 di 0x0FF04034**; `0x25DEE8` li setta. Entrambi: `ldh.di r10,[r1]` (raw 0x090A1100) → `bclr/bset r10,r10,r0` (numero di bit da `mov r0,4` / `mov r0,6`) → `sth.di r10,[r1]` (raw 0x02A41900), pool 0x25DEB8/0x25DED0 (clear) e 0x25DEF4/0x25DF0C (set). Ogni RMW è avvolto dalla coppia di sezione critica 0x1786E8/0x179354 (§6).
- **Strobe su 0x0FF04020** (pool 0x25DF30/0x25DF58/0x25DF80/0x25DFA8): `ldh.di r0,[r13]` (raw 0x19001500) → `and r0,r0,-769` (0xFCFF: pulisce i bit 8/9) → `bset_s 9` | nulla | `bset_s 8` | nulla → `extw_s` → `sth.di r0,[r13]` (raw 0x10241D00). Quindi: **0x25DF24 = bit9=1 bit8=0; 0x25DF4C = entrambi 0; 0x25DF74 = bit8=1 bit9=0; 0x25DF9C = entrambi 0**. Modello Python su tutti i 65.536 valori: un set-9 non lascia mai il bit 8 e viceversa (i due strobe sono mutuamente esclusivi per costruzione).

## 4. I sender e la chiusura della transazione

- **Sender singolo byte `0x25CB3C(r0)`**: `0x25DF24` (strobe bit9 set) → `0x25E064(byte)` (scrittura porta) → `0x25DF4C` (strobe clear). Il byte viaggia in r13 attraverso i due delay slot (`mov_s r13,r0` / `mov_s r0,r13`). È il destinatario dei 29 siti con immediata nel delay slot (dizionario dell'iterazione Wire).
- **Attenzione `0x25CB0C`**: strobe bit9 → scrittura porta **0xFF** (`mov_s r0,0xff` nel delay slot) → strobe clear → poll di `0x25E0B8` (bit 7 di 0x0FF04024) fino a **0xF4240 = 1.000.000** iterazioni mentre vale 0 → tail-call del close helper `0x25CAF4`.
- **Close helper `0x25CAF4`**: `0x25DF9C` + `0x25DF4C` (doppio strobe clear) → **gate SET** (`0x25DEE8`) → `0x2E5658(1)` (`mov_s r0,0x1` nel delay slot del `bl.d`). Il gate viene quindi ri-armato al termine dell'attenzione: il pattern è gate-clear all'apertura della transazione (0x25F338), gate-set alla chiusura.
- **Sender descrittore `0x25CB54(desc)`**: posizione `r16 = (desc[1] + r57) & 0xFFFF` con **r57 composto da due muludw**: `muludw(0, h(0x50F532), desc[0])` (0x50F532 = ctxA[+6]) poi `desc[+2] + r57`, `extw_s`, `muludw(0, byte(0x50F531), …)` (0x50F531 = **ctxA[+5], il byte cmd**) — sotto l'ipotesi MULUDW condizionale documentata. Poi strobe bit8 set (`0x25DF74`, `extw r16` nel delay slot) e il pacchetto scritto **un byte alla volta** via `jl_s.d [r14]` con r14 = 0x25E078 (pool 0x25CECC):
  1. `0x00` **extra solo se bit 0xA di h(0x50F52E)** è set (il `beq_s` a 0x25CB90 salta alla seconda copia);
  2. `0x00` sempre (0x25CB96);
  3. `lo8(r16)` (`extb r0,r16` nel delay slot);
  4. `hi8(r16)` (`asr r0,r16,8` + `extb_s`);
  5. `desc[0]` **solo se bit 8 di h(0x50F52E)** è set;
  infine strobe clear `0x25DF9C` e pop millicode 0x33418C.
  Nota di lettura: il vecchio «[00](se flag)» del rapporto Wire va letto byte-per-byte: bit 0xA set → **due** 0x00 consecutivi, clear → uno solo; la struttura complessiva del pacchetto confermata.
- **Pack3 `0x25CBBC(v, out)`**: `out[0]=v`, `out[1]=v>>8`, `out[2]=(v>>14)|3` — logger di posizione a 3 byte con tag 3, confermato non-header.

## 5. Pool e word raw asseriti

18 pool: 5× 0x0FF05000 (0x25E06C/0x25E080/0x25E094/0x25E0AC/0x25E0E4), 0x0FF04024 (0x25E0C0), 0x0FFCA008 (0x25E0E8), 4× gate (0x25DEB8/0x25DED0/0x25DEF4/0x25DF0C), 4× 0x0FF04020 (0x25DF30/0x25DF58/0x25DF80/0x25DFA8), 0x50F514 (0x25CEC8), 0x25E078 (0x25CECC), 0x369348 (0x178718). 9 word raw: `sth.di r0,[r1]` 0x00241900 ×3, `ldh.di r0,[r0]` 0x09001000 ×2, `ldh.di r10,[r1]` 0x090A1100, `sth.di r10,[r1]` 0x02A41900, `ldh.di r0,[r13]` 0x19001500, `sth.di r0,[r13]` 0x10241D00. 17 risoluzioni `ld_s [pcl,u6]` (non scalate, regola di progetto) verificate per ogni sito elencato nello script.

## 6. Coppia di sezione critica (contesto)

`0x1786E8`/`0x179354` avvolgono ogni RMW di gate e strobe (non le primitive porta, che sono singole halfword). Corpo: `r1 = [0x369348]` (pool 0x178718 nell'enter; l'exit usa un limm assoluto), contatore di annidamento a `[[r1+0x1c]+0x68]`; quando il contatore è 0 l'enter esegue `flag r0` con lo status salvato a `[r1,0x16]` (lettura halfword), poi incrementa e memorizza blink a `+208` **solo se `[r1,0x18] == 0`** (il `bne_s` a 0x17870C salta lo store quando `[r1,0x18] != 0` — polarità corretta dalla revisione indipendente, §9); l'exit decrementa (store nel delay slot di `jne.d [blink]`) e ripristina lo status via `flag` al ritorno a zero, con selettore `[r1+0x18]`: ==0 → `flag` da `[r1,0x1a]`, ≠0 → `ld.as r1,[r1,141]` scalato → `[r1+564]` e `flag` da `[+4]` (verificato: 0x179370 + 564 = 0x1795A4). Il **nominare** la coppia «sezione critica/interrupt lock» è inferenza dal comportamento; i byte (contatore, `flag`, salvataggio status) sono verificati.

## 7. Modelli Python

Strobe RMW su tutti i 65.536 valori: `set9 = (h & 0xFCFF)|0x200` non ha mai bit 8, `set8 = (h & 0xFCFF)|0x100` non ha mai bit 9, i clear lasciano `(h & 0xFCFF)`; gate RMW bit 4/bit 6 su valori campione; pacchetto del sender descrittore: `r57 = (cmd * ((ctxA6*d0 + d2) & 0xFFFF)) & 0xFFFF`, `pos = (d1 + r57) & 0xFFFF`, `packet = [00 se bitA] + [00, lo8, hi8] + [d0 se bit8]` con tre casi asseriti; attenzione: 0xF4240 = 1.000.000; pack3: `(v>>14)|3` con tag 3 sui 2 bit alti.

## 8. Collegamento con le iterazioni precedenti

I punti di iniezione dei byte dizionario dell'iterazione 12 (0x25CFC4/0x260C78 → 0x70; 0x2606DA → 0x80; 0x25F28C → 0x00/0xFF) raggiungevano 0x25CB3C: ora l'intera catena **0x25CB3C → strobe bit9 → sth.di halfword su 0x0FF05000 → strobe clear** è byte-exact, e il sender descrittore 0x25CB54 (usato da 0x25F338) ha la sequenza completa gate→pacchetto→strobe. La semantica MCU dei bit di gate/strobe (0x0FEF03A8 bit 4, 0x0FF04034 bit 6, 0x0FF04020 bit 8/9) resta inferenza dal pattern RMW.

## 9. Revisione indipendente (agente)

Esito dell'agente `port-sender-audit` (configurazione ereditata; tre turni: il primo interrotto dal limite turni su una scoperta laterale, il secondo di chiarimento con il coordinatore, il terzo di verdetto). Lo strumento «task con agente explore» richiesto non esiste in questo ambiente, come già annotato nelle iterazioni precedenti. L'agente ha riverificato i byte del blocco 0 sha-verificato con finestre proprie, assumendo dal manuale ISA ARCompact locale la semantica dei delay slot (D = sempre eseguito, ND = solo se non si salta), decisiva per i claim 3 e 10; non ha eseguito il verificatore né scritto file.

- **Claim 1–9: CONFERMATI.** Primitive porta (sth.di raw 0x00241900 su tre copie, pool 0x0FF05000, conferma che il pool inghiotte la store nella finestra lineare), lettura 0x25E08C (ldh.di raw 0x09001000 + extb_s → solo byte basso), 0x25E0B8/0x25E0D0/0x25E0D4, gate (pool 0x0FEF03A8/0x0FF04034, raw 0x090A1100/0x02A41900), strobe (raw 0x19001500/0x10241D00, and −769 + bset 9/8), sender byte 0x25CB3C, attenzione 0x25CB0C + close 0x25CAF4, sender descrittore 0x25CB54 (pacchetto con extra 0x00 condizionato a bit 0xA di h(0x50F52E), r57 sotto ipotesi MULUDW dichiarata), pack3 0x25CBBC.
- **Claim 10: CONFERMATO CON UNA CORREZIONE, ACCOLTA.** La polarità dello store del caller-PC era invertita nella prima stesura: i byte (`bne_s → 0x178714` che salta lo store) mostrano che il blink viene memorizzato a `[struct+0x1c]+208` **solo se `[r1,0x18] == 0`**, non quando ≠0. Corretti: rapporto §6, evidenza del verificatore, e il verificatore ora asserisce la sequenza (ldw/cmp/bne_s/st) inchiodando la polarità (evidenza valida `20261022T001031Z` post-correzione; le precedenti `20261022T000501Z/000730Z` sono pre-correzione). Nota minore accolta: l'exit 0x179354 usa un limm assoluto, il pool 0x178718 appartiene solo all'enter.
- **Scoperta laterale dell'agente, verificata dal coordinatore con sha256:** il campo `offset` di `S33-sections/TBM_blocks/manifest.json` NON punta al contenuto in firmware.bin (blocco 0 reale a file offset 0x482b8, slice sha-identica al file blocco; la slice a offset 512 non combacia). Nessun impatto sulla pipeline: `verified_payloads` legge i file blocco sha-verificati e usa `load_address_candidate` (0xAD800); il campo non è usato. Registrato come caveat del manifest in AGENTS.md e nel checkpoint, nessun file corretto.
- **Non verificato dall'agente (e perché):** semantica fisica dei registri MMIO, runtime di r57/flag ctxA, corpo di 0x2E5658 e dei thunk millicode 0x334128/0x33418C/0x3341A4 (destinazioni confermate, corpi non riesaminati), chiamanti reali dei sender; nessuna esecuzione, nessun hardware.

## 10. Limiti

- Statico: nessun MMIO, MCU obiettivo o fotocamera toccati; nessun firmware eseguito; NON_INSTALLARE.
- La composizione di r57 nel sender descrittore passa per due `muludw`: esatta solo sotto l'ipotesi MULUDW condizionale documentata (CPU non provata); lo stesso vale per i valori runtime (desc, ctxA[+5]/[+6], flag di 0x50F52E, contatore di sezione critica).
- `0x2E5658` (chiamato dal close helper con arg 1) è cross-riferito per call site, non byte-decodificato qui.
- Il significato fisico lato MCU di gate/strobe e del bit 7 di 0x0FF04024 è inferenza; il naming della coppia 0x1786E8/0x179354 è inferenza.
- I corpi di 0x25E10C/0x25E140 (bit 9 di 0x0FFCA008, bit 0 di 0x0FFCA00C, stesso idioma di 0x25E0D4) sono contesto non asserito dal verificatore.
- V1.1 analizzata vs macchina V1.0: nessun trasferimento automatico di indirizzi.

## 11. Prossimo passo (non ripetitivo)

(a) Byte-decodificare `0x2E5658` (post-helper della chiusura attenzione/transazione, unico anello mancante della coda 0x25CAF4) e il suo ruolo rispetto al gate appena riarmato; (b) in alternativa, il censimento dei lettori/scrittori Main del banco 0x0FE400xx partendo da 0x301EC0 (identità periferica, aperto dall'iterazione 8). Entrambe offline e byte-verificabili.
