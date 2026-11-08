# Dumper RAM — binding task personalizzato, attesa finita e clock

22 ottobre 2026, firmware V1.1. Analisi offline dei payload originali con GNU ARC700 in sola lettura. Nessuna creazione di task sulla fotocamera. Verificatore [s33_verify_ram_dump_task_binding.py](../Python_Trace_Scripts/s33_verify_ram_dump_task_binding.py), [evidenza](../Risultati/Runtime_Kernel/RAM_Dumper_Task_Binding/verified_evidence.json), [14 finestre GNU](../Risultati/Runtime_Kernel/RAM_Dumper_Task_Binding/gnu_verified.txt). Il controllo passa: 16 hash payload, roundtrip block0 identico e 31 istruzioni assertite. Questi sono controlli statici, non 31 test runtime.

Il requisito di attesa finita cooperante ora ha un ingresso concreto: **`0x19A774(milliseconds)`**. Per creare un task con template proprio esiste **`0x23C990(0,0,&template)`**. Il dumper può mantenere contesto e buffer nel proprio stack assegnato dal kernel; non serve scegliere un indirizzo RAM globale libero o allocare un secondo oggetto per il solo buffer.

## Task e memoria propria

ABI candidato C a 32 bit:

```c
struct task_template {
    uint32_t index;
    void (*entry)(uint32_t);
    uint32_t stack_bytes;
    uint32_t priority;
    const char *name;
    uint32_t attributes;
    uint32_t parameter;
    uint32_t timeslice;
};
uint32_t create_task(uint32_t processor, uint32_t template_index,
                     const struct task_template *custom); /* 0x23C990 */
```

Usare `create_task(0,0,&record)` seleziona il ramo personalizzato. Il wrapper passa r1 originale a r0 e r2 originale a r1 del creatore `0x2C9AE0`. Con r0=0 questo legge parametro a template+24 e discriminante1; `0x29F41A` copia **32 byte** nella propria allocazione. Pertanto il record può essere temporaneo sullo stack del launcher fino al ritorno della creazione; **nome, entry e oggetto eventualmente puntato da parameter richiedono lifetime separato**. Il nuovo task può iniziare prima del ritorno del launcher.

Il ritorno di `0x23C990` è **ID task nonzero oppure zero in caso d'errore**. Non è il codice stato del wrapper `0x158E78`, che ricerca solo template fissi e scrive l'ID via puntatore. Il ramo programmato chiama `0x29F4E4` e può fare scheduling. Il ramo alternativo `0x23C940` lascia stato3 e non serve al launcher.

Il template originale conserva gli otto campi sopra; per quello nuovo, usare attributi0 e timeslice0 come scelta minimale, priorità nel limite verificato del kernel e uno stack iniziale proposto **0x8000**. Il task costruisce localmente il contesto dumper (~4,2 KiB) e lo usa fino alla conclusione. Questa scelta elimina BSS e un'allocazione aggiuntiva; **32 KiB non sono ancora un limite di stack misurato** delle chiamate filesystem annidate. Il costruttore assegna il proprio descrittore, copia template e stack attraverso l'allocatore kernel; disponibilità e comportamento a esaurimento del pool non sono provati da questa verifica.

Il nuovo task entra con parametro in r0, gp ereditato e trampoline ritorno `0x2C9B90` in blink. Compilare senza SDA/gp (`-mno-sdata`) e senza BSS presunta azzerata. Il codice originale ritorna attraverso il servizio di distruzione `0x23CAF0(0)`: non chiamare un loop infinito al termine. Per il percorso dumper one-shot, ritorno dall'entry è il comportamento previsto dal frame originale; il rilascio integrale delle risorse kernel resta analisi preesistente parziale.

## Attesa finita senza evento prestato

**`void delay_ms(uint32_t ms)` a `0x19A774`**, r0 durata positiva, ritorno r0 non specificato. Il caso0 ritorna senza accodare, quindi un yield fra chunk deve passare almeno1.

1. `0x28171C(ms,&D[0x5C])` converte millisecondi in tick usando `[K+0x200]` tick/secondo e il fattore1000. Per frequenze che dividono1000 usa divisione, altrimenti moltiplicazione64bit/divisione1000; le durate inferiori al tick possono troncarsi. Non si misura qui una frequenza fisica.
2. `0x26983C` aggiunge il tempo corrente a K+0x34 al timeout del task.
3. `0x28179C` rimuove il nodo dalla lista corrente, lo inserisce ordinato nella lista temporizzata K+0x4C, aggiorna count halfword K+0x54, OR stato con0x100.
4. A `0x281800` salta **`0xB2D50`**, salvando il contesto e raggiungendo lo scheduler. Non è il bare CPU `sleep 0`.
5. Il tick `0x2F70C4`, chiamato da TIMER0 `0x29F740`, aggiorna K+0x34/38 e scorre la stessa lista. Alla scadenza cancella0x100, scrive stato2 e reinserisce il task nella lista pronta.

Precondizioni: chiamata da task, scheduler e tick funzionanti, assenza di lock esterni mantenuti attraverso il dump. Il ritorno avviene quando lo scheduler seleziona nuovamente il task, senza promessa di latenza esatta.

**`0x23C620` è da escludere per le pause del dumper**: converte la durata e termina chiamando `0x17B97C`; quel corpo è un loop `lp` di nop. Il vecchio simbolo “delay” non era prova di una pausa RTOS. Il wrapper originale `0x145C3C` usa invece il nuovo ingresso19A774 quando il proprio argomento è divisibile per1000: il delay slot della divisione imposta divisore1000 e il ramo passa il quoziente al servizio.

## Clock per timestamp

Non serve attribuire un significato arbitrario al contatore:

```c
struct ticks { uint32_t lo, hi, hardware; };
struct seconds_ms { uint32_t seconds, milliseconds; };
void get_ticks(struct ticks *out);                    /* 0x2FB6FC */
uint32_t ticks_to_time(const struct ticks *,
                       struct seconds_ms *);         /* 0x269888 */
```

`get_ticks` copia12byte da K+0x34 sotto contatore di protezione/scheduling. `ticks_to_time` legge tick/secondo da K+0x200 e il denominatore hardware K+0x204, usa esplicitamente fattori1000 e2000 e restituisce **1 sul percorso normale, 0 su saturazione**, impostando secondi `0xFFFFFFFF` e millisecondi999 in quest'ultimo caso. Per timestamp32bit: `seconds*1000u+milliseconds`, aritmetica modulo2^32. La copia semplice non legge il contatore hardware AUX: la precisione è quella dei tick kernel; non dichiararla microsecondi.

## Hook e residenza: candidato concreto, ancora condizionato

`0xC58E0` contiene `bl 0x159128`, byte originali **`4a08c049`**; viene dopo `0xC58DC→0xC5AF4` (Load Resource, payload9) e prima del caricamento C4. Un wrapper residente che conserva la chiamata159128, lancia il task e ritorna può sostituire questo sito senza bloccare il worker Load Later durante tutta l'acquisizione.

**Il coordinatore ignora il risultato del wrapper Resource**. L'aggancio non può saltare direttamente in payload9 dopo un caricamento fallito: serve un launcher residente in payload0 o una guardia in payload0 che confronti firma/versione del codice caricato prima del salto. Il fatto che la zona di destinazione sia zero nel file non dimostra residenza permanente o assenza di sovrascrittori. Per evitare doppie creazioni dopo callback ripetute occorre inoltre un flag di proprietà assegnato/inizializzato, oppure un protocollo one-shot provato dal punto d'aggancio. Questa verifica non autorizza il riuso di celle originali o nullsub in sezioni wire/lock.

Resta da chiudere: collocazione persistente del launcher e del codice; guardia sull'esito loader; massimo stack con filesystem; gestione creazione fallita; mappa RAM completa; creazione esclusiva SD; confezionamento e recupero. **NON_INSTALLARE**: gli ingressi sono una base per il binding offline e non prova di firmware già funzionante sulla fotocamera.

## Binding C preparato

Implementati [nikon_v11_runtime.c](../AkeruOS/nikon_v11_runtime.c) e [header](../AkeruOS/nikon_v11_runtime.h). Le quattro destinazioni Nikon sono simboli `extern` da risolvere nel linker, non cast di indirizzi nel codice runtime. Le API esposte separano errori di argomento, creazione e saturazione del clock; il clock lascia intatto l'output in errore. `wait_ms(0)` viene rifiutato. Il template personalizzato è locale, attributi/timeslice0, entry/nome forniti dal chiamante; nessun intervallo di priorità viene assunto. La guardia superiore dello stack deriva dall'overflow della formula originale, non da RAM presunta disponibile.

[Prova host](../Risultati/Runtime_Kernel/RAM_Dumper_Task_Binding/port_test/runtime_mock_test.c): **13 casi** con le quattro funzioni Nikon esplicitamente simulate, ASan/UBSan, PASS. Questi verificano inoltro degli argomenti e gestione locale degli errori, senza simulare il kernel. Compilazione ARC700 con `-O2 -mno-sdata -mlong-calls -ffreestanding -fno-builtin`: **240 byte text, zero data/BSS**, soltanto i quattro simboli Nikon irrisolti attesi, nessun accesso SDA/gp. [Disassemblaggio](../Risultati/Runtime_Kernel/RAM_Dumper_Task_Binding/port_test/arc_disassembly.txt). Nessuna modifica del Makefile o inserimento hook in questo binding.
