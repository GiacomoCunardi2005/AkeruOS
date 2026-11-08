# S33 — prototipo ELF offline e integrazione delle fonti esterne

19 ottobre 2026. Continuazione delle [rilocazioni ARC verificate](S33_Rilocazioni_ARC_e_Riferimenti_Linux.md), sulla base della ricerca allegata dall'utente. Ambito: host, senza operazioni sulla fotocamera o produzione di pacchetti Nikon modificati.

## Risultati verificati

È disponibile un prototipo indipendente che carica **un oggetto ET_REL** in sezioni simulate, sceglie gli indirizzi in ordine di sezione con il rispettivo allineamento, inizializza NOBITS a zero e risolve simboli prima di applicare RELA. Diversamente dal precedente confronto, non ricava il layout dall'eseguibile GNU.

**6 confronti GNU passati**, su3oggetti a2basi sintetiche, con **32 rilocazioni complessive**. Le sezioni, gli indirizzi, i simboli e i byte corrispondono. **31 casi di rifiuto passati**, inclusa una chiamata C con una rilocazione non supportata. Il caricamento resta una simulazione: le istruzioni non vengono eseguite.

L'integrazione delle fonti ha inoltre portato a correggere due errori del parser del contenitore: posizione e descrittore P1RES errati, e lettura di metadati oltre una lunghezza dichiarata troppo piccola. **5 test unitari passati**, più controllo in lettura del file Nikon originale con hash noto. Nessuna riestrazione dei16blocchi.

## A. Prototipo e riproduzione

[Prototipo](../Python_Trace_Scripts/s33_arc_elf_offline.py), [verifica differenziale](../Python_Trace_Scripts/s33_check_arc_elf_offline.py).

```bash
python3 Python_Trace_Scripts/s33_check_arc_elf_offline.py
python3 Python_Trace_Scripts/s33_arc_elf_offline.py AkeruOS/build/main.o --base 0x100003
```

Il secondo comando emette soltanto JSON su stdout. La base è una scelta artificiale per controllare l'allineamento, non una regione identificata sulla Nikon. Il primo comando compila fixture e produce gli eseguibili di confronto in una directory di evidenze separata, senza alterare la build AkeruOS.

Copertura del prototipo:

- ELF32 LE, ET_REL, macchina93/ARCompact, flags esatti `0x403` ARC700/ABI4; controlli dei limiti per header, sezioni, nomi, simboli e RELA.
- Sezioni allocate PROGBITS/NOBITS con flags ordinari W/A/X; allineamento potenza di due e limite host di16MiB, distinto dalla RAM Nikon. Memoria e scritture sono locali a ciascuna sezione simulata.
- Un'unica SYMTAB: simboli locali, globali, di sezione, assoluti e indefiniti risolti tramite un dizionario esplicito dell'API. I nomi devono coincidere interamente; i valori interni derivano dalla nuova posizione della sezione, non dal suo offset nel file.
- `R_ARC_32_ME`, `R_ARC_32`, `R_ARC_32_PCREL`, riusando il codificatore del precedente esperimento. Rifiuto esplicito di altri tipi, simboli mancanti, scritture fuori sezione e rilocazioni sovrapposte. Gli errori restituiscono nessuna immagine parzialmente caricata al chiamante.

Sono intenzionalmente esclusi REL, ELF64/BE, altri flag ABI, più SYMTAB, simboli weak/common/TLS, compressione, merging delle sezioni, risoluzione fra oggetti separati e caricamento dinamico completo. I due oggetti C della fixture vengono uniti prima con GNU `ld -r`. Non viene sostituito il linker GNU nella build del prodotto.

### Confronti con GNU ARC

| Oggetto | Contenuto verificato | Rilocazioni per base |
|---|---|---|
| `main.o` | programma AkeruOS, `.text`20byte e BSS `counter` | 2 ME |
| `multiple.o` | dati e BSS, simboli locali/assoluti/esterni, addendi0/−4/+4, distanze PC-relative positive/negative | 12, tipi4/27/49 |
| `calls.o` | chiamata C `entry→helper`, salvataggio di blink generato dal compilatore, lettura di `state` da altra sezione | 2 ME |

Basi: `0x100003` e `0x200000`. La prima richiede allineamento: `.text` del programma comincia a `0x100004`. GNU riceve un linker script di prova con ordine delle sezioni dell'oggetto e direttive ALIGN; calcola autonomamente indirizzi e rilocazioni. Per NOBITS si confrontano indirizzo, dimensione e contenuto zero previsto dal formato; per PROGBITS si confrontano tutti i byte.

Nella fixture C **`-mlong-calls`** produce `R_ARC_32_ME helper` a `.text.entry+6`. Senza tale flag, la stessa chiamata produce **`R_ARC_S25W_PCREL`, tipo17**, che il prototipo rifiuta. Questa è una limitazione concreta per futuri moduli: non basta che l'attuale `main.o` usi soltanto ME. Il Makefile AkeruOS rimane invariato; non è ancora provata la compatibilità di chiamate a servizi Nikon.

I31rifiuti coprono input troncati, architettura/ABI errate, allineamento non valido, TLS, REL, riferimenti RELA errati, nomi/simboli/scritture fuori limite, sovrapposizione, simboli non risolti/common, limiti host/indirizzi, confronto esatto dei nomi e il tipo17 reale. È verificato anche il rifiuto della CLI con `python -O`: i controlli del prototipo non dipendono da `assert`. La CLI valida produce lo stesso JSON dell'API.

Evidenze: [JSON](../Ghidra_Results/ghidra_reports/arc_elf_offline/verified_evidence.json), [GNU](../Ghidra_Results/ghidra_reports/arc_elf_offline/gnu_verified.txt), [esempio CLI](../Ghidra_Results/ghidra_reports/arc_elf_offline/cli_main.json), [registro delle fonti e hash](../Ghidra_Results/ghidra_reports/arc_elf_offline/source_review.json). Il JSON conserva hash dei sorgenti di verifica, degli oggetti e degli eseguibili, differenze vuote nei confronti riusciti e gli errori attesi. Non costituisce una validazione esaustiva di ogni ELF maleformato o di tutti gli overflow aritmetici possibili.

## B. Fonti esterne: cosa riducono e cosa resta aperto

### Linux ARC e GNU

Il [riferimento Linux v6.12](https://github.com/torvalds/linux/blob/v6.12/arch/arc/kernel/module.c) conferma le tre forme già documentate; il livello ARC presume che il caricatore generico abbia allocato sezioni e risolto simboli. Riduce il lavoro necessario per capire il formato delle rilocazioni, senza fornire allocatore o servizi Nikon.

Il [commit GNU BFD fornito nell'allegato](https://gnu.googlesource.com/binutils-gdb/+/fa7f0c2d4e8e670a608337d71857408010551215/bfd/elf32-arc.c) è del **9 marzo2009**. Quel file non contiene `R_ARC_32_PCREL`: va conservato come riferimento storico, non come specifica completa della toolchain corrente. I confronti usano GNU ld2.45.1 e i [sorgenti locali Binutils2.45](../work/binutils-2.45/bfd/elf32-arc.c).

### Cache ARC700

Il [sorgente cache ARC700 al commit indicato](https://android.googlesource.com/kernel/common/+/2f14f4b51ed34fe2b704af8df178f5cd8c81f65e/arch/arc/mm/cache_arc700.c), in particolare `flush_icache_range()`, tratta esplicitamente coerenza I/D, indirizzi fisici/virtuali e alias. Questo conferma che scrivere byte di codice non basta a dimostrarne l'eseguibilità.

Nel [percorso Nikon di uscita TBIB](S33_Uscita_Kernel_TBIB_e_Ripristino_Contesto.md) sono invece provate richieste `dc_flsh/dc_ivdc` e gestione della base vettori: non sono una prova completa della manutenzione I-cache per nuovo codice. Geometria, completamento, indirizzi/alias e interazione DMA della S33 restano da ricostruire. Non viene importata o richiamata alcuna routine Linux.

### Frontier / FujiHack

Ispezionati i file locali al commit **`754acff9aa0322df19446cf7eca699b221c3330d`**: [loader.c](../Research/Repositories/fujihack/src/portable/loader.c), [sym.c](../Research/Repositories/fujihack/src/portable/sym.c), [app.c](../Research/Repositories/fujihack/src/portable/app.c), [ml.c](../Research/Repositories/fujihack/src/portable/ml.c), [debug.S](../Research/Repositories/fujihack/src/patch/debug.S).

Confermati filtro ARM, rilocazioni ARM/REL e assenza di un rifiuto generale nel default dello switch. In `sym.c` il confronto limitato alla lunghezza registrata accetta anche prefissi e la crescita non verifica tutti i limiti delle tabelle. Le due API di compatibilità task/allocazione di `ml.c` restituiscono−1. `debug.S` usa istruzioni ARM e punti d'intercettazione Fujifilm.

Si recupera il modello di separazione fra caricamento, simboli e API esportate. Non è un port ARC pronto; il prototipo è implementato separatamente, senza copiare quei file o patch hardware.

### Patcher e ricerca ODM

[FujiHack Patcher](https://github.com/fujihack/patcher), [patcher.js](https://github.com/fujihack/patcher/blob/master/patcher.js) e [test.js](https://github.com/fujihack/patcher/blob/master/test.js) documentano controlli prima delle patch e test automatici dei firmware supportati. Il test.js esaminato scarica firmware e applica patch: non è stato eseguito. Il modello di verifica è utile, ma non dimostra un roundtrip o una procedura di recupero Nikon.

La [distinzione fra famiglie EXR e ODM](https://tiredboffin.github.io/) resta una guida alla ricerca. Nessuna prova di compatibilità binaria S33/S8500 o di identità del chip viene aggiunta da questo lavoro. Le somiglianze vanno verificate su byte, identificativi, istruzioni, task e contenitori.

### Licenze osservate

Linux `module.c` dichiara `GPL-2.0-only`; GNU BFD esaminato dichiara GPLv3 o successiva; il repository Patcher espone GPL3. Il [LICENSE locale FujiHack](../Research/Repositories/fujihack/LICENSE) è GPL3, mentre i file Frontier elencati recano una nota «Apache License» senza versione: non viene assunto che questa ambiguità consenta un riuso senza ulteriori verifiche. Nessun sorgente esterno viene importato nell'implementazione. Il sorgente cache storico viene usato soltanto come riferimento tecnico.

## C. Correzione verificata del parser del contenitore

[Parser](../coolpix-s33-re/s33_extract.py) e [test](../coolpix-s33-re/tests/test_s33_extract.py). I chiamanti trovati sono la CLI e i test dello stesso progetto.

Nel file V1.1 originale:

```text
fine TBM = marker P1RES = 0x01114AB8
descrittore P1RES      = marker+0x40 = 0x01114AF8
inizio dati           = descrittore+12 = 0x01114B04
lunghezza dati        = 0x00B26616
```

Il vecchio parser cercava erroneamente il marker a fineTBM+0x20 e modellava un descrittore a16byte. La vecchia fixture riproduceva quell'errore, quindi i test sintetici non lo rilevavano. Corretto il marker, il descrittore a12byte e la fixture. Il campo dopo la lunghezza è una sola parola, attualmente0: la parola successiva,1000, appartiene già al payload e non è un quarto campo del descrittore. Non viene attribuita una nuova semantica a questi valori.

Inoltre il parser richiede almeno `0x14` byte P1RES, perché legge una parola a payload+`0x10`. Il test nuovo mostrava prima che una lunghezza1 veniva accettata sfruttando byte nel trailer; ora viene rifiutata.

Riproduzione test: `cd coolpix-s33-re && python3 -m unittest discover -s tests -v`. **5 test passati**, con sottocasi di troncamento e descrittori fuori file. [Verifica del file originale](../Ghidra_Results/ghidra_reports/arc_elf_offline/container_parse_check.json): hash Nikon noto, tre intervalli corretti, risorsa JPEG a `0x1114CD4`, trailer10byte. Nessun payload estratto o riscritto. `gap_before_P1RES` rimane nel JSON per compatibilità e vale dimensione0; `P1RES_unknown_u32_after_length` ora contiene la sola parola del descrittore.

Questa correzione non è un ricostruttore TBIB/TBM, non estende i checksum noti e non interpreta il tipo2 RHIR come sezione dati. Roundtrip di contenitore e precondizioni di future patch restano un lavoro distinto: non si riconta la verifica storica dei16blocchi come risultato nuovo.

## Impatto concreto su R3/R4 e continuazione

| Requisito | Evidenza disponibile | Ancora necessario |
|---|---|---|
| Collegamento del codice | sezioni/simboli/BSS/RELA verificati offline; chiamata C con ME | scegliere link statico o loader; definire API Nikon e tutti i tipi necessari |
| CPU e ABI | ingresso TBM e frame task già ricostruiti; `-mno-sdata` nel programma minimo | contratto completo di registri, stack, ritorno e attesa cooperante |
| Memoria e ownership | allocazione simulata deterministica | regione reale assegnabile, ultimo uso degli overlay, allocatore e rilascio/errori |
| Cache | riferimento ARC700 e scritture Nikon distinte | sequenza Nikon specifica e completamento I/D/DMA |
| Contenitore | parser corretto e limiti provati | ricostruzione senza modifiche verificata e controlli di patch, se necessari |
| Caricamento e recupero | nessuna nuova prova hardware | compatibilità V1.0, metodo di caricamento e recupero R4 dimostrati |

**Inferenza:** queste fonti riducono il lavoro su rilocazioni e verifiche host, ma non eliminano i principali vincoli d'integrazione. Nessuna tappa funzionale viene chiusa per il solo numero di test; percentuale invariata.

Prossimo punto utile: definire un singolo servizio Nikon necessario a un task che ritorna o attende cooperativamente, collegando ABI, simbolo e durata della regione che lo ospita. Usare il prototipo per verificare il relativo oggetto; tenere il tipo17 esplicitamente rifiutato finché non sia necessario e verificato implementarlo. Non usare il loop infinito attuale come callback.

Continuazione: il [servizio di attesa senza termine](S33_Attesa_Task_Switch_e_Risveglio.md) è ora collegato al cambio di contesto e alla ripresa dopo il segnale. Restano da definire evento proprio e lifetime, memoria, percorsi di errore e binding; le verifiche ELF qui riportate non dimostrano queste proprietà.
