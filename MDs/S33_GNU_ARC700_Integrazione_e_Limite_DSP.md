# GNU ARC700 integrato: baseline Nikon e limite DSP riprodotto

**Continuazione corrente,20 ottobre2026:** leggere prima [AUX/IRQ e fonti archiviate](S33_GNU_AUX_Interrupt_e_Fonti_Archiviate.md). Il motore GNU originale ha un difetto AUX fuori array confermato nel TBIB. `gnu-main` usa ora AUXv2 corretto; DSP separato v5 supera il vecchio limite AUX512 e arriva a scrittura4321→FE40004, restando provvisorio. I riferimenti a v3, attesaPDF e motore originale come default nelle sezioni storiche sotto sono superati.

20 ottobre 2026, R3/R4. Il simulatore del handoff è ora utilizzabile dal progetto con un runner locale e target Make. La baseline TBIB è riprodotta; il proseguimento con parametri MMIO sintetici raggiunge una codifica `muldw` che questo eseguibile GNU non decodifica. Non è un boot completo e non cambia il circa 10% funzionale del progetto.

## Uso e fonti

Dalla radice del progetto:

```bash
make -C AkeruOS gnu-verify
make -C AkeruOS gnu-tbib
make -C AkeruOS gnu-clock
```

`gnu-verify` ripete i 23 casi descritti sotto; `gnu-tbib` esegue la baseline con traccia; `gnu-clock` esegue un proseguimento a parametri zero fino al limite DSP atteso. Un esito PASS significa che l'arresto o il risultato corrispondono agli assert del caso, non che il firmware abbia completato l'avvio.

Il [runner](../Python_Trace_Scripts/s33_run_gnu_arc700.py) accetta anche:

```bash
python3 Python_Trace_Scripts/s33_run_gnu_arc700.py clock --selector 128 --word 16
python3 Python_Trace_Scripts/s33_run_gnu_arc700.py clock --ram 128-zero
python3 Python_Trace_Scripts/s33_run_gnu_arc700.py probes
```

Le esecuzioni usano Podman senza rete, limite contenitore 2 GiB, timeout interno 10 secondi e timeout host 30 secondi per comando. L'installazione GNU è montata in sola lettura; la sola directory di risultati è scrivibile. Nessun comando USB/PTP o accesso alla fotocamera. Ogni invocazione crea una directory nuova sotto `outputs/gnu_arc700/`; non sovrascrive baseline precedenti. Un timeout, un errore di avvio o un segnale diverso dall'atteso falliscono la verifica.

Dipendenze locali riusate, senza installazione o ricompilazione del simulatore:

- `/home/jack/opt/arc700-legacy/install/bin/arc-elf32-run`, SHA-256 `7d6ccd1bc2291f377201e8cd1027c6ecf94d30901f13251c1c6bf647aa8a43dc`.
- Immagine `localhost/arc700-legacy:gcc10`, ID `6f0f4aaf7745a0418008ff41116d860e0af98c998e75a4cdce4e9b7c230aeb9a`.
- Toolchain `/home/jack/opt/arc-toolchain/arc_gnu_prebuilt_elf32_le_linux_install/arc-multilib-elf32/bin/` per i soli piccoli probe GNU.
- ELF e test del handoff sotto `/home/jack/opt/arc700-legacy/tests/`; il runner ne registra gli hash e riusa `smoke.ld` per i soli ingressi sintetici di laboratorio.

Evidenze dell'esecuzione finale: [manifest PASS](../outputs/gnu_arc700/20261020T103823Z_f40cbb57/verified_evidence.json), [copia del runner eseguito](../outputs/gnu_arc700/20261020T103823Z_f40cbb57/runner_snapshot.py), [audit traccia](../outputs/gnu_arc700/20261020T103823Z_f40cbb57/trace_audit.json), [inventario sorgenti motore](../outputs/gnu_arc700/20261020T103823Z_f40cbb57/engine_source_inventory.json). Ogni comando ha file JSON e log associati; i probe conservano assembly, oggetto, ELF, disassemblato e traccia. La directory `20261020T103644Z_e168f0d5` conserva il primo FAIL del runner: l'assert cercava `Extract` nello stdout, mentre `--trace-file` lo scrive nella traccia. La correzione riguarda la raccolta delle evidenze, non il motore CPU. `20261020T103711Z_f9ebf486` è la prima suite completa PASS; il risultato finale aggiunge snapshot, hash dei sorgenti/tool e assert sulla reale esecuzione delle istruzioni di controllo.

## Identità e mappa caricata

Campione esclusivamente V1.1 CMP3: 29.602.084 byte, SHA-256 `1d34e990a8f99019ffa53ca5de785399df863e942739a667ceb314ec6ce62a39`. Il runner riusa `verified_payloads` e ricontrolla i 16 payload del manifest. Controlla anche header TBIB, checksum `0xF3F78173`, identità del corpo con il file estratto e byte dei segmenti ELF; verifica nuovamente gli hash degli input a fine esecuzione.

L'ELF del handoff viene copiato nella directory di prova dopo la verifica, senza rigenerarne o cambiarne il layout:

| Oggetto | Intervallo / valore | Significato |
|---|---|---|
| Corpo originale TBIB nel file | `[0x7C, 0x44C38)` | 281.532 byte verificati |
| Segmento TBIB | `[0x01000000, 0x01044BBC)` | Byte originali; ingresso ELF candidato `0x01000000` |
| Segmento stack ELF NOBITS | `[0x010D0000, 0x010E0000)` | 64 KiB sintetici del handoff |
| RAM predefinita GNU | Derivata da `init_stack` in `sim/arc/sim-if.c` | La creazione automatica include memoria da zero e inizializzazione degli argomenti; non è una mappa della Nikon |
| Variante diagnostica | `[0, 0x08000000)` azzerata | Profilo 128 MiB esplicito, separato dalla baseline |

Questo GNU non conserva la proprietà «lettura di RAM sconosciuta → stop» del precedente modello P-code. Né RAM zero, né stack ELF, né ingresso TBIB provano capacità fisica, memoria libera, reset hardware o memoria disponibile per AkeruOS. I payload MainCode e gli overlay 11–15 non sono caricati arbitrariamente: il percorso verificato si ferma ancora dentro TBIB.

La build C `AkeruOS/main.c`, i suoi flag e il suo oggetto restano separati da queste esecuzioni del TBIB originale. Nessun nuovo programma AkeruOS viene avviato dal runner.

## Controlli effettivamente eseguiti

Comando finale: `make -C AkeruOS gnu-verify`, concluso con codice zero. Totale 23 casi: 11 test preesistenti, una baseline, cinque proseguimenti TBIB e sei probe nuovi. Gli arresti intenzionali sono esplicitamente verificati.

- Smoke: exit 0, 167 istruzioni dichiarate dal profiler.
- Alias `ld.ab r13,[sp,r13]`: exit 0, 13 istruzioni dichiarate.
- Nove ELF della suite aritmetica/memoria/chiamate: 9/9 exit 0.
- Baseline TBIB con halfword `0x0FE800F8=0` e `0x0FE80064=0`: exit 11 soltanto insieme a fault di lettura da 2 byte su `0x0FE80108`, PC `0x01009B6A`, profiler **10.952**.
- Traccia baseline: 10.954 record istruzione, 3.900 eventi interni `-`, 1.111 PC distinti, 94 mnemonici. Riprodotta la differenza di due record dal profiler; la causa resta aperta. Nessuna metrica di compatibilità ISA del 99%.

Il numero «Total instructions» è riportato come contatore GNU, non assunto come conteggio certificato di istruzioni ritirate. Nei piccoli probe può differire sensibilmente dai record eseguiti della traccia; gli assert sull'esito e sulla decodifica non dipendono da un conteggio esatto di quei probe.

## Proseguimento Nikon e limite nuovo

Continua il [ramo dei parametri clock candidati](S33_Parametri_Clock_e_Proseguimento_Boot.md). Per ogni profilo sono dichiarate tre halfword simulate: selettore F8, registro 50/64 scelto, parametro 108/120 scelto posto a zero. Tutti gli altri MMIO restano non mappati. Non è implementata una periferica fisica: sono ingressi costanti di laboratorio.

| F8 sintetico | Registro scelto e valore | Parametro nuovo | RAM | Profiler GNU | Arresto |
|---:|---|---|---|---:|---|
| 0 | `0x0FE80064=0` | `0x0FE80108=0` | Default GNU | 10.963 | SIGILL, decode vuoto a `0x01009B8C` |
| 0 | `0x0FE80064=16` | `0x0FE80120=0` | Default GNU | 10.962 | Identico PC |
| 128 | `0x0FE80050=0` | `0x0FE80108=0` | Default GNU | 10.964 | Identico PC |
| 128 | `0x0FE80050=16` | `0x0FE80120=0` | Default GNU | 10.963 | Identico PC |
| 0 | `0x0FE80064=0` | `0x0FE80108=0` | 128 MiB zero | 10.963 | Identico PC |

Il caricamento di halfword nonzero usa piccoli file mmap scrivibili soltanto nella directory di prova. Il runner considera il padding `address % 8` richiesto da `sim-memopt.c`, mappa i file prima di impostare `memory-fill` e controlla che i file non siano cambiati. Nel sorgente GNU `memory-fill 0` può altrimenti azzerare il primo byte del file appena mappato: l'ordine delle opzioni è significativo.

La [traccia completa del primo profilo](../outputs/gnu_arc700/20261020T103823Z_f40cbb57/clock_f8_0000_word_0000_default.trace) mostra:

1. `0x01009B6A` e `0x01009B74`: letture della halfword `0x0FE80108`, valore sintetico zero.
2. Calcolo dei due fattori, entrambi 1 nel profilo zero.
3. `0x01009B84`: `sr 0,[0x41]`, eseguita e tracciata.
4. `Extract: 0x1009b8c: sfmt_empty`, sui byte originali `0c 28 fe 03`, disassemblati da GNU ARC700 come `muldw 0,r0,r15`.
5. Segnale 4. Non si raggiunge l'esecuzione della lettura `0x0FE80100` a `0x01009B94`.

Il motore può predecodificare un blocco successivo e ripetere l'ultima riga di trace prima dell'istruzione illegale: la sola ultima riga `sr` non identificava correttamente la causa. Gli `Extract` successivi nel file non provano che quelle istruzioni siano state eseguite.

## Sei casi isolati: causa distinta dal MMIO

I probe usano ingresso sintetico `0x1000`, stack sintetico del linker di prova, byte DSP espliciti e uscita con la stessa syscall `trap_s 1` dei test preesistenti. Non modificano istruzioni del firmware per farlo avanzare.

| Probe | Contenuto specifico | Risultato verificato |
|---|---|---|
| `sr_only` | Byte originali `sr 0,[0x41]` | Esecuzione di `sr`, raggiunto `trap_s`, exit 0 |
| `muldw_only` | `r0=2`, `r15=3`, byte `0c 28 fe 03` | `sfmt_empty` a `0x1008`, segnale 4 |
| `sr_muldw` | Scrittura AUX originale seguita da MULDW | `sr` passa, `sfmt_empty` a `0x1010`, segnale 4 |
| `muludw_only` | `r0=2`, `r15=3`, byte `0d 28 fe 03` | `sfmt_empty` a `0x1008`, segnale 4 |
| `muldw_zero` | Stessa MULDW con fattori zero | Stesso decode vuoto e segnale 4 |
| `read_r57` | Byte originali `extw r13,r57` | Eseguita come `extw r13,mlo` nella nomenclatura del motore; raggiunto trap, exit 0 |

I due controlli positivi provano che quelle istruzioni possono essere eseguite in questo stato di laboratorio, non il contratto completo di AUX_MACMODE o dei registri DSP Nikon. La lettura di r57 azzerato non convalida la produzione di un risultato DSP. Il nome GNU `mlo` non basta per equiparare le diverse estensioni DSP o `mul64`/`mulu64` a `muldw`/`muludw`.

L'inventario locale di `cpu7.h`, `decode7.h`, `decode7.c`, `sem7.c`, `sim-if.c` conserva gli hash; nei file verificati non compaiono nomi MULDW/MULUDW. È un riscontro limitato su questi sorgenti, da leggere insieme al test dinamico, non una ricerca esaustiva di ogni versione GNU. Il binario rimane quello del handoff, senza ricompilazione.

## Continuazione

Il prossimo punto verificabile è il supporto delle **estensioni DSP effettivamente usate da Nikon**: ricostruire codifica, stato AUX, destinazioni e accumulo di MULDW/MULUDW da fonti indipendenti prima di intervenire su una copia separata del motore. I probe appena conservati sono il criterio minimo di regressione; serviranno anche valori limite e controlli di risultato, non il solo superamento del segnale 4. Le ipotesi del precedente dossier [MULUDW](MULUDW_SEMANTICS.md) non sono convalidate da questo test GNU, che non esegue quella codifica.

Solo dopo si può completare il calcolo candidato, attribuire la successiva halfword `0x0FE80100`/`0x0FE80118` e seguire il suo consumatore. MainCode, task, interrupt, periferiche complete, boot/UI, salvataggio e recupero rimangono aperti. Nessun valore fisico dei registri, compatibilità V1.0 o sicurezza flash è dimostrato; NO-GO e circa 10% funzionale invariati.
