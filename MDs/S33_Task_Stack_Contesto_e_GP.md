# S33 — stack, contesto iniziale dei task e registro gp

Analisi del 18 ottobre 2026 sul campione Nikon S33 V1.1, con compilazione locale del solo oggetto AkeruOS. Nessuna esecuzione del firmware, creazione di task sul dispositivo o scrittura in RAM/flash. I log hardware esistenti sono V1.0. Continuazione dell'[avvio runtime](S33_Avvio_Runtime_e_Creazione_Task.md). **Avanzamento orientativo: circa 10%, invariato.**

## Risultato concreto

È ricostruita la costruzione del contesto iniziale in `0x29F3A8 → 0x2C9C30` e il suo consumo in un percorso dello scheduler. Il nuovo task riceve l'ingresso dal template, il parametro in `r0`, il `gp` corrente del creatore e un trampoline originale in `blink` per il ritorno.

Il ramo con template personalizzato **copia il record di 32 byte** nella propria allocazione prima di costruire lo stack. Questa copia non include automaticamente stringhe o altri dati puntati dal record.

È emersa anche una dipendenza concreta della build: il precedente `main.o` usava `gp` per accedere a `counter`. Il Makefile ora usa **`-mno-sdata`** e l'oggetto ricompilato usa rilocazioni assolute. Questo elimina quella specifica dipendenza dal registro globale, senza validare ancora collegamento, ABI completa o avvio sul dispositivo.

## 1. Dalla selezione del template all'allocazione

Il servizio `0x2C9AE0` passa a `0x29F3A8` il template, un contesto del chiamante, il parametro di creazione e il discriminante del ramo personalizzato.

`0x29F3A8` controlla il campo template+12 rispetto a un limite del kernel; il ramo di errore può impostare un codice e restituire zero. Il campo template+8 determina la richiesta di stack:

```text
U = align_up(max(stack_richiesto, 200), 64)
L = U + 64
richiesta totale = 0xEC + L + (personalizzato ? 32 : 0)
```

La richiesta passa da `0x2F6D6C` a `0x2F729C`; l'allocazione incorpora un descrittore di **`0xEC` byte**. Il codice configura ID e collegamenti del task. Comportamento del pool esaurito, tutti i casi di fallimento e rilascio non sono ancora ricostruiti; la formula non dimostra disponibilità di RAM.

Indicando con `D` il puntatore al descrittore restituito:

| Ramo | Template usato | Inizio segmento stack `B` |
|---|---|---|
| Ordinario | Il template originale rimane referenziato | `D + 0xEC` |
| Personalizzato | Copia di 32 byte a `D + 0xEC`; bit 31 dell'ID copiato impostato | `D + 0x10C` |

La copia avviene a `0x29F41A → 0xAD920`, con dimensione 32. Il segmento stack di lunghezza `L` viene riempito da `0x29F390` con il valore del letterale `0x29F514`; non va interpretato come memoria inizialmente zero.

Le formule riportano le operazioni osservate per dimensioni ordinarie prive di overflow a 32 bit. Non sono un validatore per dimensioni arbitrarie.

## 2. Limiti e frame del nuovo task

La routine `0x2C9C30` riceve descrittore, inizio segmento, lunghezza, template, valore di stato e parametro. Costruisce:

```text
T = align_down(B + L - 1, 64)
limite basso = align_up(B, 64)
F = T - 0xB8
```

Il frame iniziale da `F` a `T` viene azzerato tramite `0x269F1C`, poi popolato. I campi del descrittore risultano:

| Campo di `D` | Valore scritto |
|---|---|
| +`0x10` | `T`, limite superiore |
| +`0x14` | `F`, puntatore al contesto salvato |
| +`0x18` | Limite basso allineato |
| +`0x54` | Puntatore al template usato, originale o copia |
| +`0x6C` | Attributi/flag, con bit `0x40` aggiunto per il ripristino iniziale |

Il template influenza anche attributi, selezione della struttura di schedulazione e altri campi; la tabella non rappresenta l'intero descrittore del kernel.

### Campi del frame collegati al ripristino

| Offset da `F` | Valore preparato | Consumatore nel percorso verificato |
|---|---|---|
| +`0x00` | Parametro di creazione | Caricato in `r0` a `0xB2F2E` |
| +`0x2C` | `0x2C9B90` | Ripristinato in `blink` a `0xB2E5E..0xB2E68` |
| +`0x30` | Valore passato dalla struttura di schedulazione | Ripristino dello stato CPU, incluso `status32_l2` |
| +`0x34` | Ingresso da template+4 | Passa in `r30`, usato dal salto finale |
| +`0x84` | `gp` corrente del creatore | Ripristinato in `gp` a `0xB2E92` |
| +`0x88` | `F + 0xA4` | Ripristinato in `fp` nel delay slot a `0xB2E9A` |

Il parametro viene copiato anche a `T-4`. Il significato completo di quest'ulteriore slot rispetto alle convenzioni del compilatore rimane da attribuire.

## 3. Collegamento al codice dello scheduler

Nel percorso verificato, lo scheduler seleziona un descrittore e a **`0xB2E22`** carica `sp` dal campo +`0x14`. Ripristina registri e stato dal frame. Il bit `0x40` del campo task+`0x6C` controlla la parte estesa del ripristino e viene cancellato in quel percorso.

Il tratto finale a `0xB2F2A..0xB2F34`:

1. legge l'ingresso da `F+0x34` e lo conserva in `r30`;
2. legge il parametro da `F+0x00` in `r0`;
3. incrementa `sp` di **164 byte**, cioè `0xA4`;
4. esegue `j.f [r30]`.

Quindi lo stack all'ingresso del task è **`F+0xA4 = T-20`**, non il limite superiore `T`. Il valore di `fp` predisposto coincide con quello stack iniziale. Le formule mostrano allineamento a 4 byte del punto d'ingresso; non viene attribuita una convenzione diversa del compilatore senza ulteriori controlli.

Questo collegamento esclude il ramo alternativo selezionato dal bit `0x8` del task, che salta a `0xB3318`. Configurazione CPU completa, tutti gli ingressi da interrupt, FPU/estensioni e tutti i percorsi di switch non sono ancora ricostruiti.

Il trampoline `0x2C9B90` consulta il task corrente, può invocare una callback di pulizia e chiama `0x23CAF0(0)`. Il suo inserimento in `blink` chiarisce il percorso previsto al ritorno dell'ingresso del task. Il contratto completo di distruzione e rilascio richiede ancora l'analisi del servizio chiamato.

## 4. Problema gp nella build e modifica effettuata

Il precedente oggetto di `AkeruOS/main.c` conteneva:

```text
ld.as r2,[gp]   → R_ARC_SDA_LDST2 counter
st.as r2,[gp]   → R_ARC_SDA_LDST2 counter
```

Questi accessi richiedono un accordo fra `gp`, collocazione dei dati e linker. Il runtime ricostruito conserva il `gp` del creatore: non lo sostituisce automaticamente con una nuova base globale AkeruOS.

La toolchain locale è GCC ARC 15.2.0, build 10504; il suo aiuto target conferma che i riferimenti sdata sono abilitati per impostazione predefinita. La variante compilata con **`-mno-sdata`** produce per il codice minimo accessi assoluti con **`R_ARC_32_ME counter`** e nessun operando `gp`.

È stato aggiornato [il Makefile](../AkeruOS/Makefile) e completato `make -B` in AkeruOS. L'oggetto corrente contiene 20 byte di testo e 4 byte BSS. I due oggetti di confronto, disassemblaggi e hash sono conservati nelle evidenze.

Le rilocazioni assolute devono ancora essere risolte da un linker con indirizzi verificati. L'ELF resta rilocabile, con indirizzo d'ingresso zero: gli zeri mostrati negli operandi prima del collegamento non sono indirizzi da usare sulla macchina. Nessuna compatibilità completa dell'ABI deriva dal solo successo della compilazione.

## 5. Controlli eseguiti

Eseguire `python3 s33_trace_task_context.py`. Lo [script](../Python_Trace_Scripts/s33_trace_task_context.py):

- verifica hash e dimensioni dei **16 blocchi**, istruzioni selezionate e destinazioni delle chiamate;
- controlla roundtrip ELF identico del blocco 00 e conserva **10 finestre GNU ARC700**;
- applica le formule a **6.784 casi aritmetici**: le dimensioni stack dei 53 template originali, due rami e tutti i 64 residui di allineamento di un indirizzo sintetico;
- ricompila localmente il codice minimo con e senza `-mno-sdata`, confronta disassemblaggi/rilocazioni e verifica che l'oggetto corrente non usi riferimenti SDA/gp.

I casi aritmetici verificano che frame e scritture descritte rimangano nel segmento calcolato e che l'intervallo allineato abbia lunghezza `U`. Gli indirizzi sono sintetici: non è un emulatore e non dimostra RAM libera o comportamento dell'allocatore.

Evidenze: [JSON](../Ghidra_Results/ghidra_reports/task_initial_context/verified_evidence.json), [finestre GNU](../Ghidra_Results/ghidra_reports/task_initial_context/gnu_verified.txt), [oggetto predefinito](../Ghidra_Results/ghidra_reports/task_initial_context/main_default.o), [oggetto senza sdata](../Ghidra_Results/ghidra_reports/task_initial_context/main_no_sdata.o), [confronto predefinito](../Ghidra_Results/ghidra_reports/task_initial_context/main_default_disassembly.txt), [confronto senza sdata](../Ghidra_Results/ghidra_reports/task_initial_context/main_no_sdata_disassembly.txt). Esecuzione completata con codice 0.

## Prossimo passo

La [continuazione sul bootstrap](S33_Bootstrap_Kernel_e_Pool_Iniziale.md) identifica ora configurazione, contesto kernel, assegnazione della tabella e pool iniziale; il trasferimento TBIB → TBM rimane aperto.

Seguire l'inizializzazione del contesto kernel e del puntatore ai template per collegare questa costruzione al bootstrap TBM. Per il task AkeruOS mancano ancora collocazione del codice e dei dati, linker, servizio cooperante di attesa/risveglio, ABI delle chiamate originali e punto d'inserimento. Avvio TBIB → TBM, caricamento del pacchetto e recupero rimangono requisiti aperti.

## Continuazione del19 ottobre — ingresso TBM collegato

Il [rapporto sul passaggio TBIB→TBM](S33_Passaggio_TBIB_TBM_e_Ingresso_CPU.md) attribuisce il record16/tipo2 all’ingresso `0xBB540`, collega la cella di trasferimento e verifica stack, gp e chiamata a `0xAD890`, oltre all’area azzerata. Il precedente punto aperto sul collegamento statico è quindi ristretto: restano la sequenza completa di chiusura TBIB, la residenza, l’inserimento AkeruOS e il recupero, senza esecuzione hardware dimostrata.

## Continuazione — frame dinamico dell'attesa

Il [rapporto attesa e switch](S33_Attesa_Task_Switch_e_Risveglio.md) collega ora il frame dinamico di164byte salvato da `0xB2C74` alla ripresa dopo la chiamata evento, a `0x2C9AC6`. Verificati gp/fp, r13..25, registri loop, rimozione e reinserimento nelle liste in512cicli sintetici sotto precondizioni. Il frame iniziale di184byte descritto sopra rimane distinto. Non sono provate tutte le varianti di contesto, effetti hardware di status/FLAG, fairness o proprietà di un nuovo evento AkeruOS.
