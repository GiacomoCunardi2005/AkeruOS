# Iris: lato completamento della mossa — handler differiti, evento 0x10, byte di stato e guardia di generazione

**Iterazione 23 — 22 ottobre 2026.** [Script](../Python_Trace_Scripts/s33_verify_lens_iris_completion.py), [prove](../Risultati/Lens_MCU_Interface/Iris_Completion/latest.json) (**evidenza valida 20261022T011924Z** post-audit; conferma finale identica 20261022T011933Z, ultima cartella; le corse 011103Z/011112Z sono pre-audit della stessa sessione).

**Correzione 27 ottobre 2026:** la maschera `and -25` a 32 bit è `0xFFFFFFE7`: azzera i bit 3 e 4 e conserva i bit 0 e 1. La descrizione «0/1/3/4» nel metadato storico prodotto dallo script è errata; le due istruzioni `bclr` su un altro registro nella fase di avvio sono distinte.

## 1. Domanda

Chiude il punto aperto (a) dell'iterazione 21 ([attuazione GPIO iris](S33_Iride_Attuazione_GPIO_0FF04024_e_Chiusura_Wrapper.md)):
**quando finisce la mossa dell'iride e chi azzera il byte di stato [0x36A464+6]?**
Serviva al «ritorno pronto» del percorso fotografico (inquadratura → tasto → acquisizione): il chiamante AE
imposta l'indice iris tramite 0x149530 → 0x18B85C → 0x235B0C, ma la fine della mossa era sconosciuta.

## 2. Risultato in sintesi

La mossa finisce quando gira il **callback differito** registrato dalla request: il corpo 0x2359B0
pulsа entrambi i GPIO iris, attende 500, li spegne e **azzera [0x36A464+6]**; poi il gestore rilascia
la risorsa e — solo nella variante «wait» — **segnala l'evento 0x10** che risveglia il chiamante.
Il setter 0x18B85C chiama SEMPRE la request con wait=1: **0x18B85C ritorna solo a mossa completata**
(modello runtime; l'attesa è su evento, il blocco effettivo è del planner, non eseguito staticamente).

Inoltre una **correzione** all'iterazione 21: il «contatore» incrementato dalla request è la halfword
**[0x36A464+0x1c] = cella 0x36A480** — la STESSA cella che la pre-guardia 0x235ABC confronta con la
handle h e che l'acquire 0x235A1C restituisce come h. Non è una doppia dereferenziazione
(«[[0x36A464]+0x1c]»): è una **guardia di generazione** — una handle stantia non attua più.

## 3. Catena byte-exact del completamento (payload0, base 0x0AD800)

```
request 0x235B0C (dentro sezione critica, DOPO l'attuazione Big/Small):
  contatore halfword [0x36A464+0x1c]++              (ldw_s/stw_s, pool 0x235BC8)
  evento CLEAR 0x158CE0(1|1<<25, 0x10)              PRIMA del post
  handler = wait!=0 ? 0x235AF8 : 0x235AE4           (pool 0x235BCC / 0x235BD0)
  post 0x145F28(0x36A494, handler, timeout 0x3A98, 0)
  [fine sezione critica]
  se wait && post-ok: attesa 0x158D04(1|1<<25, 0x10, 1, 0)

post 0x145F28 (servizio callback differiti, condiviso: 9 siti chiamanti):
  oggetto servizio 0x366EBC ([+8] init, [+0xc] scala tick /10000,
  [+0x10] seriale, [+8] contatore slot)
  ARC700 TIMER1 armato: limit1=0x1000000, count1, control1=2 poi 3
  tabella slot 0x4437F4: 10 slot, stride 20 byte
    slot+0 flags, +4 seriale, +8 scadenza (timeout via millicode), +16 HANDLER
  servizio di cancellazione 0x14605C: cerca slot per seriale, azzera flags,
  decrementa il contatore

callback differito (al momento della scadenza — consumatore runtime):
  0x235AE4:  0x2359B0()  →  0x23524C(2)  →  0x235DE8()  → ritorno
  0x235AF8:  0x235AE4()  →  0x158CBC(1|1<<25, 0x10)  → ritorno   [variante wait]

0x2359B0 (corpo di fine mossa):
  callback [0x36A464+0x3C] se non nullo (jl_s [r0])
  sezione critica → 0x0FF04024 |= 0x18 (ACCENDE entrambi i bit 3/4)
  attesa 500 (0x23C620)
  seconda sezione critica:
    0x0FF04024 &= -25 (SPEGNE bit 3/4, conserva bit 0/1)
    STATUS [0x36A464+6] = 0   ← chi azzera il byte di stato,
                                 DENTRO la stessa sezione critica (0x235A02)
  ritorno 0

0x23524C(2) → 0x235C60 → 0x234CD0   (rilascio risorsa tipo 2)
0x235DE8:  se 0x2C4F90([0x36A484])==0 → azzera il byte in-motion [0x36A488]

evento 0x10 = bit 0x10 del gruppo eventi id 0x2000001:
  tabella [0x372A48], stride 0x38, magic 0x45564E4C, bit31 a +8
  NB: 0x158CBC/0x158CE0 operano sul puntatore entry+0xC (add_s r0,r0,0xc):
    CLEAR 0x158CE0 → 0x23C8AC: bic_s del bit su [entry+0x24]
    SET   0x158CBC → 0x23C758: or_s del bit su [entry+0x24]
          + risveglio lista waiter con testa [entry+0x14]
  WAIT  0x158D04: registra il waiter (blink a [event+0x2c], senza shift)
```

## 4. Guardia di generazione (correzione all'iterazione 21)

- acquire 0x235A1C(2, &h): pone il bit di busy nella halfword [0x36A464+0x26],
  chiama il callback di tipo [0x36A464+0x34], restituisce **h = halfword [0x36A464+0x1c]**
  (= cella 0x36A480, `sth r0,[r16]` a 0x235A66).
- pre-guardia 0x235ABC(h): **h == [0x36A480]**? altrimenti la request ritorna 0 senza attuare.
- request: dopo l'attuazione **[0x36A480]++**.
- conseguenza: una handle acquisita prima di un'altra request completata diventa stantia.
  L'helper 0x18B954(idx, h) fa una **doppia** pre-guardia attorno al confronto fra idx richiesto
  e byte di stato [0x367FE8+2] (pool ld.as scalato 0x18B8F9 → 0x18B788 = 0x367FE8), poi rilascia.

La notazione «contatore halfword [[0x36A464]+0x1c]++» dell'iterazione 21 era una doppia
dereferenziazione che i byte non mostrano: entrambi i load prendono il VALORE del pool 0x235BC8
(0x36A464) e accedono a [+0x1c].

L'helper 0x18B954(idx, h) ha le due pre-guardie su **rami distinti** (non in sequenza):
pre-guardia in testa; poi idx vs byte di stato [0x367FE8+2]; il ramo idx==stato fa la seconda
pre-guardia e rilascia; il ramo idx≠stato inoltra la request con **wait=0**
(`mov_s r2,0` a 0x18B9AC, timeout 0x3A98) — non attende in modo sincrono.

Nota di contorno (scoperta dell'audit): il byte di stato [0x367FEA] (= [0x367FE8+2]) ha anche
un getter **0x18B8D4** e un mini-setter diretto **0x18B8E0** (pool 0x18B8DC), fuori dal
setter 0x18B85C: scritture dello stato possibili per altre rotte.

## 5. Percorsi di fallimento (completamento sincrono)

- setter 0x18B85C: `mov_s r2,0x1` (wait=1 sempre), timeout r3=0x3A98; se la request non ritorna 1
  → `bl 0x18B9D4` = corpo handler eseguito in sincrono (0x2359B0 + 0x23524C(2) + 0x235DE8);
  il byte di stato [0x367FE8+2] NON viene committato.
- 0x18B844: completamento + 0x235188(2) (variante sincrona alternativa, tail 0x18B6B0).
- 0x18B6B4 (epilogo tipo 1): 0x2357C8 + 0x23524C(1) + 0x235DE8.
- marker: 0x235A10 pone [0x36A47E]=1, chiamato dal claim wrapper 0x18B928 prima di 0x235A1C(2, idx).
- [0x36A488] ha anche un **gate di lettura** in 0x2353C2 (pool 0x2353FC): se in-motion, il logger
  dispatch cambia (0x2C4C2C vs 0x2C4CF0).

## 6. Pannello diagnostico 0x2C5100 (non legge [+6])

Il pannello NON consuma [0x36A464+6]: polla i byte shadow **0x446808 + 4·idx** tramite il getter
0x16F920 (pool 0x2C519C), con loop «until-zero» sugli indici 8/9/0xA, e quindi impone Big/Small con
0x18B85C(1)/(9). Chi scrive la tabella shadow resta APERTO.

## 7. Comandi ed esiti

- `python3 Python_Trace_Scripts/s33_verify_lens_iris_completion.py` →
  **PASS_IRIS_COMPLETION_STATIC**, exit 0. Corse: 20261022T011103Z e conferma 011112Z
  (pre-audit), **011924Z post-audit = evidenza valida**, conferma finale identica
  **011933Z** (ultima cartella, `latest.json` punta qui). Correzioni di collaudo della
  prima stesura (nessuna asserzione indebolita): `\b` dopo `]` rimosso (mai valido,
  lezione iterazione 21); `b_s` vs `b` nel tail di 0x18B844; finestra epilogo wait estesa
  a 0x158E20; `bset_s r0,r0,0x15` (bit 0x15, non 0x25) nell'errore del post service;
  filtro census esteso alle forme `bl_s`/`bl_s.d` (senza di esse i census di
  0x235ABC/0x235AE4/0x145F28 erano incompleti); census 0x36A488 esteso al secondo pool
  0x2353FC (gate di lettura, finestra dedicata); census 0x235ABC esteso a
  {0x18B968, 0x18B980, 0x235B28} con finestra dedicata 0x18B954.
- Integrazioni post-audit (seconda stesura): asserzione `add_s r0,r0,0xc` in 0x158CBC
  (coordinate evento entry+0xC), finestra `state_minisetter_18b8d4` (getter 0x18B8D4 +
  mini-setter 0x18B8E0 di [0x367FEA], pool 0x18B8DC), precisazioni nel JSON
  (store [+6] dentro la seconda sezione critica; coordinate evento; 0x18B954 con
  pre-guardie su rami distinti e wait=0 sul ramo idx≠stato).
- Verificatore: sha firmware e blocchi manifest verificati; 25 pool letti raw LE;
  31 finestre GNU allineate salvate in `gnu_windows.txt`; modelli Python su 65.536 valori
  (guardia di generazione, impulso GPIO clear/set, bit evento); census pool (7 celle)
  e census chiamanti (10 target, forme bl/bl.d/bl_s/bl_s.d) asseriti.

## 8. Revisione indipendente (agente iris-completion-audit, tools.agents.spawn, configurazione ereditata; atteso e integrato)

Ha riverificato byte-exact i punti 1–8 con finestre objdump proprie e letture raw dei pool
sha-verificati (nessun file scritto nel progetto, solo /tmp; verificatore non rieseguito).
Esito: **tutti i punti CONFERMATI**, con tre precisazioni ACCOLTE (già integrate nel
rapporto, nell'evidenza e nelle asserzioni):

- Punto 2: la store di azzeramento [+6] è DENTRO la seconda sezione critica (prima
  dell'uscita 0x179354 a 0x235A04) e la `and -25` (0xFFE7) spegne anche i bit 0/1 oltre a
  3/4; il callback del completamento è a +0x3C, distinto dal +0x40 delle attuazioni.
- Punto 5: 0x158CBC/0x158CE0 operano sul puntatore entry+0xC: il campo bit «[r0,0x18]» è a
  entry+0x24 e la testa della lista waiter «[r0,8]» a entry+0x14; la registrazione waiter
  [event+0x2c] è senza shift.
- Punto 8: in 0x18B954 le due pre-guardie stanno su rami distinti e il ramo idx≠stato
  inoltra la request con wait=0.

Controprove richieste, entrambe CONFERMATE: (a) census completo dei 19 pool di 0x36A464
con finestra dedicata per ciascun sito referenziante: **gli unici accessi [+6] della
famiglia sono tre scritture** — 0x235946 (Big, =1), 0x2359A6 (Small, =1), 0x235A02
(completion, =0) — nessun altro writer e **nessun lettore** di [+6] via pool; (b) i pool
di 0x36A480/0x36A488/0x36A47E sono esattamente quelli attesi (0x235AE0;
0x2353FC+0x235DE4; 0x235A18), nessuna sede extra.

Scoperte aggiuntive dell'audit accolte: mini-setter 0x18B8E0 e getter 0x18B8D4 del byte
di stato [0x367FEA]; conferma indipendente delle regole ld_s/ld.as scalate e della
posizione del byte 0x17 nelle istruzioni 32-bit (halfword LE a PC+1); secondo referente
della tabella evento 0x372A48 a 0x17B974. Lo strumento «task con agente explore»
richiesto dal runner non esiste in questo ambiente; usato spawn come nelle iterazioni
precedenti.

## 9. Limiti

- Statico: nessun MMIO, timer, interrupt, hardware né esecuzione firmware; NON_INSTALLARE.
- **Chi esegue i callback differiti** (il consumatore della tabella slot 0x4437F4, verosimilmente
  l'interrupt del TIMER1) non è identificato staticamente: la semantica «differito» poggia su
  layout slot + store dell'handler + armamento timer, non su un chiamante provato.
- Il significato fisico dell'impulso «accendi entrambi i bit, attesa 500, spegni» in 0x2359B0
  (frenatura? park? rilascio?) è inferenza, come la direzione di drive dei GPIO.
- Il blocco di 0x158D04 è un modello runtime: i byte della registrazione waiter sono verificati,
  lo scheduler no.
- Lo scrittore della tabella shadow 0x446808 del pannello resta aperto.
- Census su listato lineare: falsi positivi vicino ai pool possibili; tutti i siti della catena sono
  riverificati in finestre dedicate; il caveat RMW a maschera registro di 0x2349C0 (iterazione 21)
  resta valido.
- V1.1 campione locale vs macchina V1.0; indirizzi non portabili senza prova.

## 10. Prossimo passo (non ripetitivo)

(a) Identificare lo **scrittore della tabella shadow 0x446808** (chi copia lo stato iris nei byte
che il pannello 0x2C5100 polla): è il ponte fra completamento e UI; (b) in alternativa il
**consumatore della tabella slot 0x4437F4 / interrupt TIMER1** (chi esegue davvero i callback
differiti, ciclo 0x231420/0x23C904): chiuderebbe il «quando» runtime del completamento.
Entrambe offline e byte-verificabili.
