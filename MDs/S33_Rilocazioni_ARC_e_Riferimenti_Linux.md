# S33 — rilocazioni ARC, confronto GNU e riferimento Linux

Verifica locale del 19 ottobre 2026. Tappa **R3**, collegamento del codice AkeruOS. Nessuna esecuzione sulla fotocamera. Gli indirizzi di questo esperimento sono sintetici e non identificano RAM disponibile.

## Risultato verificato

La ricerca fornita dall'utente è confermata per il riferimento **Linux v6.12**. È stato inoltre riprodotto il confronto dei **20 byte di `.text`** del programma attuale con GNU ARC700 a due basi, ed esteso il confronto alle tre rilocazioni indicate, con addendi non nulli.

Il risultato è un verificatore offline delle rilocazioni selezionate, **non un loader ELF completo**. Non carica o esegue codice sul dispositivo e non modifica `AkeruOS/build/main.o` o il firmware Nikon.

## 1. Riferimento Linux e ordine dei byte

Fonte primaria: [Linux v6.12, arch/arc/kernel/module.c](https://github.com/torvalds/linux/blob/v6.12/arch/arc/kernel/module.c), funzioni `arc_write_me()` e `apply_relocate_add()`.

Il livello specifico ARC usa record `Elf32_Rela` e presume che i simboli indefiniti siano già risolti. Calcola `S+A`, dove S è il valore del simbolo e A l'addendo esplicito; P è l'indirizzo della parola da correggere.

| Tipo ELF | Numero | Valore scritto | Codifica nella configurazione LE studiata |
|---|---|---|---|
| `R_ARC_32_ME` | 27 | S+A | metà alta16 prima della metà bassa16, ciascuna LE |
| `R_ARC_32` | 4 | S+A | parola LE ordinaria |
| `R_ARC_32_PCREL` | 49 | S+A−P | parola LE ordinaria |

L'implementazione commenta l'ipotesi `-mlong-calls` per i moduli; il supporto di queste tre forme non implica supporto di ogni chiamata prodotta con altri flag. `module.c` dipende dal caricatore generico del kernel per le altre fasi: non è un loader autonomo da trasferire integralmente al runtime Nikon.

Conferma indipendente GNU: [analisi e patch Binutils del 6 gennaio 2016](https://ecos.sourceware.org/ml/binutils/2016-01/msg00018.html), più i sorgenti locali [elf32-arc.c](../work/binutils-2.45/bfd/elf32-arc.c) e [arc-reloc.def](../work/binutils-2.45/include/elf/arc-reloc.def). La convenzione middle-endian riguarda le parole di istruzione pertinenti: non trasformare indiscriminatamente anche i dati.

Esempio indipendente usato come controllo:

```text
valore 0x12345678
R_ARC_32_ME → 34 12 78 56
R_ARC_32    → 78 56 34 12
```

## 2. Confronto del programma AkeruOS

[Script riproducibile](../Python_Trace_Scripts/s33_check_arc_relocations.py):

```bash
python3 Python_Trace_Scripts/s33_check_arc_relocations.py
```

Richiede la toolchain `arc-snps-elf-*` già presente. Compila `AkeruOS/main.c` in una directory di evidenze separata, con gli stessi flag attuali del Makefile: ARC700, `-mno-sdata`, `-O2`, freestanding. Toolchain osservata: GCC15.2.0, GNU ld2.45.1, build10504.

Il lettore ELF controlla classe32, LE, macchina ARCompact93, flags `0x403` ARC700/ABI4 e i limiti dei record usati. Legge le due `R_ARC_32_ME` di `.rela.text`, agli offset `0x4` e `0xE`, entrambe riferite a `counter` con addendo0. Il secondo sito è allineato a2byte: non richiede allineamento a4 per la scrittura ME.

| Base `.text` richiesta a GNU ld | Simbolo `counter` risultante | Byte confrontati |
|---|---|---|
| `0x00100000` | `0x00102014` | tutti i20byte, identici |
| `0x00200000` | `0x00202014` | tutti i20byte, identici |

Le posizioni delle sezioni e i valori dei simboli definiti sono ricavati dall'ELF collegato di riferimento: il confronto verifica l'applicazione delle rilocazioni con quel layout, non un allocatore o una scelta indipendente del layout. La regione `.bss` fornisce qui l'indirizzo di `counter`; la sua inizializzazione a zero non è eseguita dal verificatore.

Sono stati confrontati anche i20byte dei due ELF temporanei segnalati dall'esperimento precedente: coincidono con quelli riprodotti. La riproduzione successiva non dipende dalla sopravvivenza dei file in `/tmp`.

## 3. Estensione verificata

Una piccola fixture assembler genera tre `R_ARC_32_ME` in `.text`, tre `R_ARC_32` e tre `R_ARC_32_PCREL` in `.data`, usando per ogni tipo gli addendi **0,−4,+4**. Le ME iniziano agli offset2,6,10. Le sezioni vengono collegate a due layout sintetici, con `.data` a base+`0x1000`.

Il simbolo esterno della fixture vale `0x12345678` nel primo layout e `0x1000` nel secondo: il confronto GNU copre quindi anche differenze PC-relative negative. Il modello risolve quel solo simbolo tramite la stessa definizione esplicita fornita al linker; non implementa una ricerca dei simboli Nikon.

Esito: **4 eseguibili confrontati, 22 parole rilocate**, di cui4 nel programma C e18 nella fixture. Sono confrontati i byte completi delle sezioni allocate PROGBITS non vuote, inclusi quelli non modificati dalle rilocazioni. Controlli diretti aggiuntivi verificano ordine dei byte, differenza negativa, riporto modulo32bit e rifiuto di un tipo non supportato. Non sono eseguite istruzioni ARC.

Evidenze: [JSON con hash, versioni, siti e byte](../Ghidra_Results/ghidra_reports/arc_relocations/verified_evidence.json), [readelf e objdump GNU](../Ghidra_Results/ghidra_reports/arc_relocations/gnu_verified.txt), [fixture assembler](../Ghidra_Results/ghidra_reports/arc_relocations/relocations.s). Il JSON conserva anche l'hash dello script e del sorgente C.

## 4. Ricerca di piattaforme affini

La fonte [Fujifilm Firmware Reverse Engineering](https://tiredboffin.github.io/) distingue le piattaforme ODM, comprese quelle Altek, dalle famiglie EXR inizialmente studiate da FujiHack. Questo sostiene una ricerca per CPU, contenitore, runtime e componenti condivisi, oltre al marchio commerciale.

**Inferenza operativa:** cercare possibili firmware ODM/Altek da confrontare con la S33. Non è ancora dimostrato che uno specifico modello Fujifilm condivida piattaforma, ABI o servizi con la S33. Una somiglianza del nome, del fornitore o del contenitore non autorizza a trasferire indirizzi o procedure di caricamento.

## 5. Limiti e prossimo passo

R3 avanza sul collegamento offline. Restano aperti: memoria assegnabile, allocazione e allineamento delle sezioni, inizializzazione BSS, risoluzione dei servizi Nikon, startup/ABI, cache, avvio come task cooperante e gestione degli errori del caricamento. Il lettore è intenzionalmente limitato ai normali ELF32 LE ARC700 generati qui: non è validato come parser di input arbitrari, ELF estesi, REL o tipi di rilocazione diversi.

Prima di progettare un loader completo, verificare quali rilocazioni produce un modulo minimo con una vera chiamata di servizio, e quali simboli/indirizzi siano necessari. Valutare il collegamento statico con GNU come alternativa: la possibilità di rilocare non impone un loader dinamico. Non aggiungere flag di chiamata o linker script al firmware corrente senza tale evidenza.

R4 (caricamento e recupero) e le prove funzionali restano aperti; stima qualitativa invariata. Nessun collegamento automatico fra indirizzi del campione Nikon V1.1 e dispositivo V1.0.

## Continuazione — allocazione e chiamata C verificate offline

Il [prototipo successivo](S33_Prototipo_ELF_Offline_e_Integrazione_Fonti.md) ora calcola autonomamente layout e simboli e li confronta con GNU:6casi/32rilocazioni, BSS e chiamata C con `-mlong-calls`. Senza il flag compare tipo17, rifiutato.31casi negativi verificati. Non risolve memoria reale, servizi Nikon, cache, avvio o recupero; il precedente confronto di22parole rimane un'evidenza distinta.
