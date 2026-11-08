# Consumatori runtime delle registrazioni iris: MCUCTRL_Task, evento 0x3200002 e invocatori di 0x1406D0/0x140704 — iterazione 34

**Correzione del 27 ottobre 2026:** `0x2B7190` acquisisce lo snapshot tramite `0x2D62D8`, non tramite `0x2D62B0`; il secondo è usato per il confronto nel monitor. Vedi [verifica dei registri](S33_GUI_Menu_Origine_Registro_20261027.md).

Data: 22 ottobre 2026. Ramo: Obiettivo/iris + Runtime/kernel (R0/R1/R3). Statico, V1.1, solo file locali.

- Script: `Python_Trace_Scripts/s33_verify_iris_registration_consumers.py`
- Evidenze: `Risultati/Runtime_Kernel/Event_3200002_Consumers/` (`latest.json` punta all'esecuzione valida)
- Prerequisiti: [Scrittori coppia di stato 64-bit](S33_Iride_Scrittori_Coppia_Stato_64bit.md) (iterazione 31), [TIMER1 callback differiti](S33_Timer1_Callback_Differiti_Dispatch_Kernel.md) (iterazione 29)

## 1. Domanda

Chiude il punto aperto dell'iterazione 31: **chi consuma a runtime le registrazioni** fatte dal setup iris 0x140568 — chi legge e invoca `[0x5545F8+0x18]` (il puntatore 0x1406D0 installato da 0x22C3BC) e `[0x392AC0+0x1C]` (il puntatore 0x140704 installato da 0x16ACDC(7,2,ptr)) — e quale task attende l'evento 0x3200002 il cui bit 10 viene alzato dalla registrazione stessa.

## 2. Risultato in sintesi

Il consumatore è **MCUCTRL_Task (entry 0x15A80C, record payload1 0x372508)**, che attende l'evento 0x3200002 con maschera 0x60F7F773 e ne dirama i bit. Il trigger runtime del commit della coppia di stato iris è finalmente ancorato:

```
setup 0x140568 ──0x22C3BC──▶ [0x5545F8+0x18] = 0x1406D0
evento 0x3200002 bit 8/9/10 ──▶ MCUCTRL_Task 0x15A80C ──▶ handler 0x242104
   bit 8: valore corrente (0x2D62B0) == coppia target [+0x2C/+0x2E] e modo [+0x20]==2
        ──▶ jl_s.d [0x5545F8+0x18] con r0 = [0x5545F8+0x30]
        ──▶ 0x1406D0(x) = [0x366DE8](~x, 0) ──▶ 0x16EC38 (normalizzatore + commit coppia)

setup 0x140568 ──0x16ACDC(7,2,·)──▶ [0x392AC0+0x1C] = 0x140704
cambio valore (0x169870) ──▶ 0x241E5C (registrato sotto id 0x3002)
   ──▶ jl_s.d [0x392AC0+0x1C] con r0 = v&7, r1 = v&0xF
   ──▶ 0x140704(bits) ──▶ celle id-1/id-2/id-4 [0x366DDC]/[0x366DE4]/[0x366DE0]
```

Inoltre la struct 0x392AC0 ha un **secondo slot di registrazione** (`+0x18`, scritto da 0x16AAB4) consumato dall'handler bit 0 del task (0x241EC4), e l'evento 0x3200002 ha sei produttori mappati.

## 3. MCUCTRL_Task: wait, lettura, auto-clear e dispatch

Task 0x15A80C (record payload1 0x372508: id 0x3200001, entry 0x15A80C, stack 0x800, priorità 6):

1. All'avvio azzera i bit attendibili dei due gruppi fratelli: `0x158CE0(0x3200002, 0x60F7F773)` e `0x158CE0(0x3200003, 0x60F7F773)` (pool 0x15AAE0/0x15AAE8/0x15AAE4).
2. Init dei sotto-oggetti a base 0x444CDC (+0x4C/+0x64/+0x8C via 0x138A98/0x16C640/0x24163C/0x241E50), post differito 0x145BF4(fn 0x15AAD4, 0, 1, 1000, contesto 0x391B38).
3. **Loop**: `0x158D04(0x3200002, 0x60F7F773, 0, 0)` (attesa), `0x158E28(0x3200002, &sp)` (lettura bit ricevuti), `0x158CE0(0x3200002, bit_letti)` (auto-clear) — il task consuma distruttivamente l'evento.
4. Dispatch sui bit ricevuti (finestra 0x15A80C..0x15A912):

| Bit | Maschera | Handler |
|---|---|---|
| 0 | 0x1 | 0x241EC4 (consumatore [+0x18] di 0x392AC0) |
| 4/5/6 | 0x70 | 0x241F88 (struct 0x392D70 → 0x262B48/0x262B44/0x262B10) |
| 8/9/10 | 0x700 | **0x242104 (consumatore [0x5545F8+0x18])** |
| 12..15 | 0xf000 | 0x2416F8 |
| 20..23 | 0xf00000 | 0x241E58 = **stub VUOTO** (2 byte `j_s [blink]`) |
| 29 | btst 0x1d | 0x241F0C + 0x241FC8 |
| 30 | btst 0x1e | clear → ritorno al wait (loop) |

Maschera 0x60F7F773 = bit {0,1,4,5,6,8,9,10,12..18,20..23,29,30}: ogni gruppo diramato è sottoinsieme della maschera; i bit 1/16/17/18 sono attesi ma senza test di dispatch nella finestra del loop (limite registrato).

## 4. Handler 0x242104 — consumatore di [0x5545F8+0x18] (= 0x1406D0)

Struct monitor **0x5545F8** (pool 0x242200; census LE: 4 pool in payload0):

- **bit 8 SET**: gestione flag `[0x36A6C8+0]` (con servizi 0x158FD0/0x145C2C), lettura valore corrente via `0x2D62B0`, confronto con la coppia halfword `[+0x2C]/[+0x2E]` (`lsr r2,r0,0x10` + `ldw_s`), richiesta modo `[+0x20]==2`, refresh dello snapshot via `0x2B7190` (che scrive `valore → +0x30`, `valore>>16 → +0x28`, `valore&0xFFFF → +0x2A`), incremento contatore `[+0x38]`, e se **`[+0x18] != 0` → `jl_s.d [r1]` con `r0 = [+0x30]`** (0x24214E..0x24215C). In caso di mismatch: contatore `[+0x34]++`.
- **bit 9 SET**: nuovo valore da `0x2D62B0` → memorizzato in `[+0x2E]/[+0x2C]`, lettura `[+0x14]`, `[+0x24]=0`, **armamento `[+0x20]=2`**.
- **bit 0xA SET**: sequenza di stop `0x2B7204` (con sezione critica e poll 0x2D6200) + `0x2B712C` + `0x242094` (che pone `[+0x20]=1`) e toggle del byte `[0x5545F8+0]` da 0 a 1.

L'unico chiamante statico di 0x242104 è il sito 0x15A8B6 dentro il task (census bl su tutto il listato). Il registro `[0x5545F8+0x18]` è esattamente la cella scritta da 0x22C3BC con 0x1406D0 (iterazione 31): **il trigger runtime del commit del complemento è chiuso** — avviene quando il valore monitorato dalla famiglia 0x2D62xx raggiunge la coppia target, con l'argomento `[+0x30]` passato a 0x1406D0(x) = [0x366DE8](~x,0).

## 5. Consumatore di [0x392AC0+0x1C] (= 0x140704): 0x241E5C

`0x241E5C` non ha chiamanti bl: vive come **puntatore nel pool 0x241F78** ed è registrato sotto id **0x3002** da `0x241E94` (via `0x242414(0x3002, 0x241E5C)`; 0x241E94 chiamato una sola volta, a 0x16AA72, dentro la funzione init 0x16A9F8 della famiglia 0x16Axxx). Corpo:

1. valore `v = 0x169870()` (chiamato anche da 0x16AD3A nella stessa famiglia);
2. `r14 = v & 0xF` (`bmsk r14,r0,0x3`), `r13 = v & 0x7` (`bmsk r13,r0,0x2`), `0x1698B0(r13)`;
3. **SET evento 0x3200002 bit 1** (`0x158CBC(0x3200002, 2)`);
4. legge `[0x392AC0+0x1C]` (pool 0x241F74) e se non nullo **`jl_s.d [r2]` con `r0 = v&7`, `r1 = v&0xF`**.

Il puntatore registrato lì dal setup iris è 0x140704 (iterazione 31): i tre bit bassi del valore dispatchano verso le celle id-1/id-2/id-4 `[0x366DDC]/[0x366DE4]/[0x366DE0]` (= 0x16EC88/0x16ECB4). Il dispatcher dell'id 0x3002 (servizio 0x242414, chiamanti {0x16D9B6, 0x1A083E, 0x23914E, 0x241E98}) resta da decodificare: è lo strato successivo.

## 6. Secondo slot di 0x392AC0: [+0x18] — 0x16AAB4 / 0x241EC4

- **0x16AAB4(ptr)** (nessun chiamante bl, ingresso calcolato): se `ptr!=0`, `[0x392AC0+0]!=0` e `[+0x18]==0` → scrive `ptr` in `[+0x18]`; se il byte gate `[+0x2A]` è non nullo → **SET evento bit 0** (`r1=1`). Con cella occupata il nuovo puntatore è ignorato (load morto in coda).
- **0x241EC4** (handler bit 0 del task): dopo il filtro 0x242034/0x242004 e `0x16ABC0`, legge `[0x392AC0+0x18]`; se non nullo → scrive il gate `[+0x2A]` (via 0x392ADC+0xE) e **`jl_s.d [r1]` con `r0 = [0x392AC0+0xC]`**; se nullo → gate=1. Semantica: notifica differita con valore associato. Precisazione (audit): lo store di `[+0xC]` dentro 0x16ABC0 è sul solo percorso `r0>0` e i due chiamanti statici noti passano `r0=0`; gli scrittori statici di `[+0xC]` sono l'init 0x241E94 (=0x20 via 0x16AC14) e 0x16C6AC.

## 7. Produttori dell'evento 0x3200002 (census pool + finestre)

| Bit | Produttore | Condizione |
|---|---|---|
| 0 | 0x16AAB4 | gate `[0x392AC0+0x2A]` durante la registrazione [+0x18] |
| 1 | 0x241E5C | prima di invocare [+0x1C] |
| 4 | 0x16C68C (`r1=0x10`) | byte `[0x392D70+0x19]==0` e `[0x392D70+0]!=0` — **chiamato dal setup iris 0x140568 a 0x1405D6** |
| 6 | 0x16C70C (`r1=0x40`) | stesse gate di 0x392D70 |
| 8 | 0x242040 (`r1=256`) | bit 0 di `0x2D6200` |
| 9 | 0x242040 (`r1=512`) | bit 1 di `0x2D6200` |
| 10 | 0x22C3BC (registrazione, iterazione 31) **e** 0x22C56C (`arg → [0x5545F8+8]`, `r1=1024`) | secondo produttore del bit 10 |

0x242040 è registrato come callback da `0x2420D0` via `0x16D898(1545, 0x242040)` (pool 0x242210); 0x2420D0 è chiamato una sola volta, da 0x22C3AE (famiglia di servizi 0x22C3xx, la stessa di 0x22C3BC).

## 8. Negativi

- **Zero branch di qualsiasi forma verso 0x1406D0 e 0x140704** in tutto il listato lineare: l'unico hit verso 0x140704 è V00D3F696 in REGION TBM_09 (payload9), classificato come **dati** con finestra allineata (frammenti di stringhe/tabelle, `.word`/`.long`, nessun flusso in ingresso).
- 0x241E5C, 0x242040, 0x16AAB4, 0x22C56C: nessun chiamante bl (solo puntatore; **0x16AAB4 è installato dall'init 0x16A9F8 tramite il pool 0x16ADC8 nella tabella famiglia a struct+0x10** → raggiungibile via dispatch calcolato). **0x242104 ha esattamente UN chiamante bl: il sito del task 0x15A8B6** (correzione dell'audit alla prima stesura di questo elenco, che lo includeva per errore tra i pointer-only).
- Nessuna word LE (16 payload, ogni offset) né limm middle-endian verso 0x5545F8/0x392AC0 al di fuori dei pool asseriti; l'hit LE non allineato di 0x1406D0 a 0x2B7475 è uno straddle di istruzioni (`ld_s r0,[pcl,0x1d4]` a 0x2B7474 + `ldh r0,[r4,6]` a 0x2B7476).

## 9. Revisione indipendente (agente `reg-consumers-audit-34`)

Agente spawnato con configurazione ereditata (lo strumento «task con agente explore» non esiste in questo ambiente, come documentato nelle iterazioni precedenti); ha riverificato i claim con finestre GNU proprie e letture raw sha-verificate, senza scrivere file nel progetto. Esito **claim-per-claim**:

- **Claim 1 (task/loop/dispatch) CONFERMATO** byte-exact, inclusi i delay slot del wait/lettura/auto-clear e il loop bit30.
- **Claim 2 (handler 0x242104) CONFERMATO**: ordine contatore [+0x38]++ prima del test null riconfermato; precisazione minore accolta: la memorizzazione bit9 è guardata dal confronto con la coppia snapshot [+0x28]/[+0x2A] (skip se uguale).
- **Claim 3 (0x241E5C) CONFERMATO**; precisazione di etichetta accolta: il chiamante 0x16AA72 sta nella funzione con ingresso 0x16A9F8 (non «0x16AA5x»).
- **Claim 4 (0x241EC4) CONFERMATO CON PRECISAZIONE ACCOLTA**: lo store `[+0xC]` di 0x16ABC0 è sul percorso r0>0 e i due chiamanti statici noti passano r0=0 → scrittori statici di [+0xC] = init 0x241E94 (0x20) e 0x16C6AC (§6 corretto).
- **Claim 5 (produttori) CONFERMATO**, con dettaglio aggiuntivo su 0x22C3BC: il SET bit10 scatta quando il flag interno r1 diventa 1 (0x22C408 forza r1=1 dentro la chiamata setup che passa r0/r1 esterni).
- **Claim 6 (negativi) CONFERMATO CON UNA CORREZIONE ACCOLTA**: la prima stesura elencava 0x242104 tra i «senza chiamanti bl», contraddetta dal claim 1 stesso — 0x242104 ha esattamente un chiamante (il task). §8 corretto. Straddle 0x2B7475 e census verificati indipendentemente.
- **Claim 7 (pool) CONFERMATO** (20+1 pool singolarmente riverificati).
- Punti di metodo richiesti: delay slot jl_s.d CONFERMATI; mask da pool 0x15AAE4 → 0x158D04 CONFERMATA; 0xf00000 → stub vuoto 0x241E58 CONFERMATO; V00D3F696 classificato dati (inferenza di classificazione: opcode non assegnati, nessuna struttura di funzione); census tutti combacianti.
- **Nota aggiuntiva accolta**: pool 0x16ADC8 = 0x16AAB4, installato da 0x16A9F8 nella tabella famiglia a struct+0x10 → 0x16AAB4 non è codice morto (asserito ora nel verificatore con finestra dedicata).

Verificatore corretto con le precisazioni (negativi, nota valore [+0xC], pool/finestra 0x16A9F8) e rieseguito: **PASS 20261022T024538Z post-audit** (023935Z = pre-audit della stessa sessione); conferma finale identica **20261022T024726Z** (`latest.json`). Nessuna asserzione indebolita.

## 10. Fonti precise

Payload0 (base 0x0AD800, blocchi sha-verificati): task 0x15A80C..0x15A912 con pool 0x15AAE0..0x15AB0C; handler 0x242104..0x2421FC con pool 0x242200..0x242220; producer 0x242040..0x2420D0; mode consumer 0x241E5C..0x241EC4 con pool 0x241F70..0x241F80; bit0 consumer 0x241EC4..0x241F10; 0x16AAB4..0x16AAF0 con pool 0x16ADC0..0x16AE04; 0x16C68C..0x16C728 con pool 0x16C7C0/0x16C7E4; 0x22C56C..0x22C58C con pool 0x22C584/0x22C588; 0x2B7190..0x2B71F0 con pool 0x2B7234; setup 0x140568..0x1405E8 con pool 0x1405E8/0x1405EC. Payload1: record 0x372508. Payload9: sito dati 0xD3F650..0xD3F6E0 (base 0xC8F800).

Regole ISA applicate: pool ld_s = (PC&~3)+offset_stampato; ld.as = (PC&~3)+campo×4; delay slot delle chiamate jl_s.d carica l'argomento; limm middle-endian (high16 LE poi low16 LE).

## 11. Limiti

- Statico, nessun hardware/runtime, NON_INSTALLARE, circa10% invariato.
- Il **dispatcher dell'id 0x3002** (chi chiama 0x241E5C a runtime) e la catena dei chiamanti della famiglia 0x2D62xx (provider del valore monitorato) restano da decodificare: sono lo strato successivo.
- Bit 1/16/17/18 della maschera di attesa senza test di dispatch nella finestra del loop; percorso di uscita del task (0x15A8EE..0x15A906, inclusa la costante codificata che GNU stampa `ror r1,0x1` e il servizio 0xB2C74) non decodificato.
- Layout delle struct ricostruiti dal lato lettura; i valori runtime (valore 0x2D62xx, gate, mode) non derivabili staticamente.
- Census dal listato lineare: un dato decodificato come branch può produrre falsi positivi/negativi; tutti i siti della catena sono riasseriti in finestre allineate.
- V1.1 campione locale vs macchina V1.0: indirizzi non portabili senza prova.

## 12. Prossimo passo

(a) Decodificare il **dispatcher dell'id 0x3002** (servizio 0x242414 e i suoi chiamanti {0x16D9B6, 0x1A083E, 0x23914E, 0x241E98}): chi invoca 0x241E5C chiude il trigger runtime di 0x140704. (b) In alternativa il gemello TIMER0 (handler 0x29F740) come tick dello scheduler Nikon (punto (b) dell'iterazione 29, ancora aperto). Entrambi offline e byte-verificabili.
