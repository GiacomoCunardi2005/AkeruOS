# AutoSceneLiveView: handler dei quattro slot pulsante decodificati e provati in CPU (iterazione 25, 2026-11-01)

Domanda affrontata (punto aperto it.23): il registro finestra p3 0x783B08
invia i quattro eventi slot (0x580/0x700/0x2180/0x2700) a un unico handler
0x65C46C. Che cosa distingue realmente i quattro slot? Da dove nascono le
richieste «ID 2 argomento 4» e «ID 2 argomento 5» osservate nei banchi
sintetici?

## Risultato principale

Il registro p3 è il registro notifiche della finestra **AutoSceneLiveView**
(descrittore 0x783AE8, nome "AutoSceneLiveView" a 0x783C4A, wrapper eventi
0x6593A0, contesto runtime 0x681F5C). I quattro slot NON sono equivalenti:
l'handler di pressione 0x65C46C pre-elabora (timer, chiusura sottofinestre,
modo 0x7E/0x2C) e poi catena invariato l'evento al mapper 0x65C5F8, che
smista in base all'ID evento:

| evento slot | percorso in 0x65C5F8 | notifica |
|---|---|---|
| 0x700 (slot 1) | 0x632798(1) | **0x1453E4(2, 4)** → CaptureMenu, arg 4 → risorsa 0x4800 |
| 0x2180 (slot 2) | 0x632798(2) | **0x1453E4(2, 5)** → CaptureMenu, arg 5 → risorsa 0x4801 |
| 0x2700 (slot 3) | 0x632798(3) | **0x1453E4(0xB7, 1)** → finestra 0xB7, arg 1 |
| 0x580 (slot 0) | blocco default | 0xD2500(0); se modo == 0x2C esce, altrimenti 0x632798(0)+0xCBDF8+0x177030+0xD0924(≠0→0xCB5E4)+0xCAD30+0xCFCAC+0x65E8C4(1)+**0xCA404(0x2C)** (transizione di modo)+0xCAFBC+**0x1453E4(0x87, 0)** |

Le due richieste del brief (arg 4/arg 5) nascono qui: la catena
AutoSceneLiveView → 0x65C5F8 → 0x1453E4. È la prima differenziazione
comportamentale provata fra i quattro pulsanti logici: lo slot 0 pilotа una
transizione al modo 0x2C e la finestra 0x87, lo slot 3 la finestra 0xB7,
gli slot 1/2 il CaptureMenu con argomenti distinti.

## Struttura statica verificata (byte del dump, LE)

- Registro p3 0x783B08: 39 record {u16 ev, pad, u32 handler} stride 8 +
  terminatore {0, 0x20E814} a 0x783C40. Slot: 0x580/0x700/0x2180/0x2700 →
  0x65C46C (0x783BAC/BB4/BB8/BC4); 0x581/0x2701 → 0x65C6B4
  (0x783BCC/BD4); 0x4401 → 0x659554.
- Descrittore 0x783AE8: {0x442, 0x330087, 0x783A1C, 0x6593A0, 0,
  0x783C4A}; wrapper 0x6593A0 filtra eventi [0x80..0x307F], calcola
  r14=(ev&0x3F80)>>7 e chiama 0x169F60(0x681F5C, 0x783B08, nodo, ev, arg)
  (pool 0x659550); pool aggiuntivi del wrapper: 0x659548=0x681F5C,
  0x65954C=0x30D40.
- Array sottofinestre 0x783A1C: **14** puntatori p3 con ID a +4 in ordine
  NON contiguo: 0x480C, 0x480E, 0x480D, 0x4801..0x4805, **0x4809**,
  0x4806, 0x4807, 0x4808, 0x480A, 0x480B; poi puntatori p1 (0x3ABA38,
  0x3ACA14...). Correzione sulla stima iniziale di 15 voci.
- Pool dell'handler di pressione (byte): 0x65C5DC=0x480C, 0x65C5E0=0x1388
  (5000), 0x65C5E4=0x783A1C, 0x65C5E8=0x4A12, 0x65C5EC=0x4A87,
  0x65C5F0=0x4A8A, 0x65C5F4=0x307F. NOTA: objdump scambia gli halfword nei
  `.word` mostrati; i valori sopra sono dai byte del blocco.
- Census: 0x65C46C/0x65C6B4/0x6593A0 hanno **0** chiamanti bl nei 16
  listing GNU e le loro uniche parole LE allineate sono i campi
  registro/descrittore (callback puri); 0x65C5F8 ha **0** parole LE ed
  **esattamente 2** chiamanti bl (0x65C5D4 nell'handler di pressione,
  bl_s 0x65C6F0 in quello di rilascio). 0x659554 appare anche a p6
  0xAF5F08 (secondo registro che riusa l'handler 0x4401, da studiare).

## Flusso di pressione 0x65C46C(nodo, ev, arg), r16=0

1. modo = getter ORIGINALE 0xCAD30 (byte 0xC8E80C).
2. Se modo == 0x7E: gate doppio 0xCD5AC (predicato `byte[0x3657DB] < 2`,
   prima chiamata ≠0 poi ==1), poi 0x145A60(nodo,0x480C,2)≠0; quindi
   switch evento: **0x700 → USCITA dalla funzione senza notifiche**;
   eventi diversi da 0x580/0x2180/0x2700 → uscita; gli slot validi →
   0xCD5AC()==1 → 0x65D534(nodo) (teardown: 0x143AFC, 0x149028(nodo,9),
   0x65DDA8, 0x65D008, 0xD2470, azzera [0x681F5C+0x30/+0x34]).
3. v = 0x14918C(nodo, 9) (predicato «timer id 9 attivo sul nodo»):
   **v == 0** → 0x14905C(nodo,9,5000,0x32,0) (crea timer) +
   0x65D1CC(nodo) + 0x65D850 + 0x145150(nodo) e USCITA senza catena
   [polarità confermata dalla revisione indipendente]; v ≠ 0 → blocco 4.
   (In modo 0x7E, 0xCD5AC()==0 immette anch'esso al blocco 4.)
4. Blocco 4 (0x65C516): se 0x12845C() ≠ 0 (predicato 0x15A690()≠0 ∧
   0x163CC8()==0): r13 = 0x14504C(nodo,6); 0x149028(nodo,0xE); r16=1;
   se r13>0 loop i=r13-1..0: id = halfword[[0x783A1C+4i]+4] (ldw_s.x con
   segno), 0x145B08(nodo,id,0); poi 0x145B08(nodo,0x4A12/0x4A87/0x4A8A,1)
   + 0x145150(nodo) + 0x15A5C8() (lock/attesa 0x158D04) + **0x17BF60(0,
   0x80, 0x307F)** (cancella dalla coda gli eventi con valore in
   [0x80,0x307F], anello 0x47A848/0x367BBC); se ev==0x580 anche
   0x145B08(nodo,0x4A87/0x4A8A,0) + 0x65D1CC + 0x65D850 + 0x145150.
5. Se modo == 0x2C ∧ r16 == 0 ∧ ev ∈ {0x580, 0x2700}: 0x26C508() (avvia
   timer pulsante, guard byte[0x36B43D], cfg[0x0B]/cfg[0x4E]) e USCITA.
6. Altrimenti catena 0x65C5F8(nodo, ev, arg).

Mapper 0x65C5F8: vedi tabella; il ramo default (0x580 e non-slot) legge
0xD2500(0) (byte[0xC8EB27]:=0), esce se modo==0x2C, altrimenti esegue il
blocco con 0xCA404(0x2C) e notifica 0x1453E4(0x87,0). Il ramo 0x2701
riusa la coppia (0xB7,1) solo se modo==0x2C, altrimenti 0x1453E4(0,0)
con r14/r15 azzerati (non raggiungibile dalle due entrate con modo fisso).

## Flusso di rilascio 0x65C6B4 (0x581/0x2701), r16=0

Se modo == 0x2C ∧ 0x26C4F8() ≠ 0 (predicato `byte[0x36B43D] != 0`) →
r16=1; poi 0x26C538() sempre (può RIPUBBLICARE 0x581/0x2701 in coda via
0x16F6B0 con gate cfg[0x0B]/cfg[0x4E]); r16==0 → USCITA senza catena;
altrimenti catena 0x65C5F8(nodo, ev, arg). Perciò il rilascio produce la
notifica (0xB7,1) per 0x2701 solo in modo 0x2C con guard attiva; 0x581 in
0x2C raggiunge il ramo default ed esce senza notifiche.

## Prove CPU (byte originali, simulatore GNU ARC700)

Verificatore nuovo
[Python_Trace_Scripts/s33_verify_aslv_slot_handlers_cpu.py](../Python_Trace_Scripts/s33_verify_aslv_slot_handlers_cpu.py),
**PASS_ASLV_SLOT_HANDLERS 20261101T163644112536Z** + riesecuzione identica
**20261101T163743659383Z** (16/16 casi, fault 0xDEADB001..0x10). Finestre
originali: 0x65C46C..0x65C5F8 (inclusi pool), 0x65C5F8..0x65C6B4,
0x65C6B4..0x65C6F8, epiloghi condivisi 0x65B1B8/0x659F8C, millicode push
0x334114..0x33413A (catene fall-through: bl 0x334124 spinge
r17,r16,r15,r14,r13) e pop 0x33417C..0x3341E4, getter modo ORIGINALE
0xCAAC4..0xCAD38. Tutte le altre funzioni sono stub che registrano
{id,r0,r1,r2}; modo, array e descrittori sono fixture. Casi:

1-3. press_700/press_2180/press_2700 → (2,4) / (2,5) / (0xB7,1) con
     0x632798(1/2/3) precedente; 0x14918C≠0 e 0x12845C==0 richiesti.
4. press_580 modo 0x2C → solo 0x26C508, NESSUNA catena (controllo negativo).
5. press_580 modo ≠0x2C → 0xD2500(0)+0x632798(0)+0xCBDF8+0x177030+0xD0924
   +0xCFCAC+0x65E8C4(1)+0xCA404(0x2C)+0xCAFBC+0x1453E4(0x87,0).
6. come 5 con 0xD0924()≠0 → extra 0xCB5E4 (controllo del gate).
7. press_580 con 0x14918C()==0 → blocco 0x14905C(nodo,9,5000,0x32,0)+
   0x65D1CC+0x65D850+0x145150 e USCITA senza catena (controllo negativo
   della polarità invertita).
8. press_2180 con 0x12845C()≠0 e 0x14504C(nodo,6)=2 → chiusura
   sottofinestre in ordine 0x480D poi 0x480C, 0x145B08(0x4A12/0x4A87/
   0x4A8A,1), 0x17BF60(0,0x80,0x307F), poi catena (2,5).
9. press_580 come 8 ma modo 0x2C: extra 0x145B08(0x4A87/0x4A8A,0)+
   0x65D1CC+0x65D850+0x145150, r16=1 salta 0x26C508, catena → 0xD2500(0)
   e USCITA senza notifiche.
10. press_700 modo 0x7E con gate passanti → USCITA senza notifiche dopo
    0xCD5AC×2+0x145A60 (controllo negativo del ramo 0x7E).
11. press_2180 modo 0x7E → 0xCD5AC×3+0x145A60+0x65D534(nodo)+catena (2,5).
12. press_2180 modo 0x7E con 0xCD5AC()==0 → salto diretto a 0x14918C+
    catena (2,5) (seconda via al blocco 4).
13-16. rilasci: 0x2701 in 0x2C con guard → (0xB7,1); senza guard → solo
    0x26C538, nessuna catena; 0x581 in 0x2C con guard → 0xD2500(0) e
    uscita senza notifiche; 0x2701 fuori 0x2C → solo 0x26C538.

Micro-test b di coda (evidenza
[Risultati/GUI_S33/aslv_tailb_blmicro_20261101T162741Z/](../Risultati/GUI_S33/aslv_tailb_blmicro_20261101T162741Z/)):
le b 32-bit 0x65C5D8 (disp -5152, allineata) e 0x65C6F2 (disp -10084, PC
2 mod 4) sono eseguite CORRETTAMENTE dal sim (trace: pc <- 0x65B1B8 /
0x659F8C); la divergenza it.44 (wrap mod 8192) NON si generalizza a tutti
i displacement negativi grandi. Nota banco: memoria non mappata <128 MiB
= zero-filled silenzioso (le evidenze di percorso si reggono su log e
marker di fault, non su fault di fetch).

Regressioni 5/5 PASS: snapshot init 163809460170Z, guard census
163812570997Z, raise pending 163826Z, wm notify registry 163842997883Z,
notify reactors 163845672909Z.

## Fonti, comandi, fixture e assunzioni

- Fonti: blocco 2 (0x5FE800), blocco 3 (0x669800), blocco 0 (0xAD800) del
  firmware V1.1 (SHA 1d34e990...); objdump GNU locale `work/build-arc/
  binutils/`; simulatore arc-elf32-run (immagine arc700-legacy:gcc10).
- Comandi eseguiti: `python3 Python_Trace_Scripts/s33_it25_blmicro.py`
  (micro-test, primo caso; secondo caso assemblato a mano, vedi README
  evidenza); `python3 Python_Trace_Scripts/
  s33_verify_aslv_slot_handlers_cpu.py` (2 esecuzioni PASS identiche);
  verificatori di regressione elencati sopra (tutti rc=0).
- Fixture: byte modo 0xC8E80C per caso (getter originale letto), array
  0x783A1C con due puntatori sintetici 0x500000/0x500010 (ID halfword
  0x480C/0x480D a +4, come nel dump reale), ritorni degli stub per caso.
- Assunzioni: nodo sintetico 0x1234; arg r2 propagato intatto alla
  catena (significato runtime ignoto); le funzioni stubbate non sono
  state eseguite e la loro semantica deriva dall'analisi statica
  (0x14918C/0x14905C = predicato/creazione timer id 9 con timeout 5000 e
  0x32; 0x17BF60 = cancellazione eventi in [lo,hi]; 0x26C4xx = timer
  pulsante; 0xCD5AC = byte[0x3657DB]<2).

## Limiti e non dimostrato

- Nessuna mappa fisica dei pulsanti: gli slot logici restano candidati;
  nessun contatto con hardware, USB, SD o fotocamera.
- Modo, array e contatori imposti dal banco; i produttori runtime della
  cella modo 0xC8E80C, del conteggio 0x14504C(nodo,6) e della guardia
  byte[0x36B43D] restano da studiare. Il loop del blocco chiusura legge
  fino a r13-1 voci: con r13>14 leggerebbe i puntatori p1 (limite
  statico, comportamento runtime non provato).
- 0x1453E4/0x632798 stubbati: la consegna reale della notifica
  (commutatore WindowManager, 0x169D78) e l'effetto di 0x632798 sono
  noti da iterazioni precedenti ma non rieseguiti qui.
- Il significato della finestra 0xB7 e della coppia (0x87,0), le unità
  dei timer (5000/0x32/200/2000), la natura degli id cfg[0x0B]/[0x4E] e
  il secondo registro p6 0xAF5F08 restano aperti.
- Un test simulato non dimostra scatto, rendering, persistenza o
  comportamento fisico. NON_INSTALLARE invariato; progresso funzionale
  invariato (~10%).

## Agenti

- `helper-explore-25` (explore, statico): helper della catena decodificati
  — 0x632798 (selezione elemento idx con guardia di rientranza, notifica
  0x4409, lock 0x186A0), famiglia 0x26C4xx (timer pulsante con guard
  byte[0x36B43D], ripubblicazione 0x581/0x2701), 0x14918C/0x149028/
  0x14905C (tabella timer 0x443ADC stride 0x1C), 0x17BF60 (cancellazione
  in [lo,hi]), setter semplici 0xD2500/0xCFCAC/0x65E8C4/0xCAFBC,
  0xCD5AC (byte[0x3657DB]<2), 0x12845C (0x15A690()∧¬0x163CC8()),
  0x145A60, 0x15A5C8 (0x158D04 lock/attesa), millicode push catene
  fall-through. Registrato in PMB (outbox 387).
- `slot-review-25` (revisione indipendente, statica): C1-C9 rivisti sui
  byte; 0 controesempi invalidanti; 3 correzioni integrate in questo
  rapporto (array 14 voci con ordine non contiguo; polarità 0x14918C
  invertita rispetto alla bozza; seconda via al blocco 0x65C516 via
  modo 0x7E ∧ 0xCD5AC()==0) e conferme sui pool, sulla semantica pcl
  EA=(PC&~3)+imm, sui delay slot bl.d e sul census. Registrato in PMB
  (outbox 386).

## Prossimo passo

Decodificare e provare in CPU i consumatori della nuova catena:
- il ramo 0x63 di 0x20F414 (0x17BE80(0,0x3181,0), it.23) e la callback
  0x7F6824 con lista esclusione 0x99ACAC, per chiudere il ciclo
  coda → router → esclusioni → registro p1/p3/p5; oppure
- l'handler 0x4401 di apertura 0x659554 (che scrive 0xFF a
  [0x681F5C+8], azzera [0x47BBC8], copia la guardia 0x365751 in
  [0x681F5C+9] e la ripristina con 0xCA2F4, e registra 0x30D40 via
  0x145C3C nel delay slot), per collegare lifecycle e stato della
  finestra agli slot; oppure
- la finestra 0xB7 (target dello slot 3) nel registro che la installa.
