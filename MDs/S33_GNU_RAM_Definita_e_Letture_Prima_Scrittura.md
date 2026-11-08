# GNU ARC700: controllo dei byte RAM prima delle letture

20 ottobre2026 — R3/R4. **Nuovo motore separato con provenienza per byte nella banca laboratorio128MiB.** I test distinguono contenuti dichiarati, byte scritti dal programma e byte sconosciuti. I due prefissi di avvio raggiungono i limiti precedenti senza nuove letture sconosciute nei percorsi controllati; nessun boot completo, circa10% funzionale e NO-GO invariati.

## Motore e limiti del controllo

[Builder](../Python_Trace_Scripts/s33_build_gnu_defined_memory.py), [sorgente del controllo](../S33-sections/analysis_codex/s33_gnu_defined_memory.c), [buildv2](../outputs/gnu_arc700_defined_memory/build_v2/verified_evidence.json), [verificatore](../Python_Trace_Scripts/s33_verify_gnu_defined_memory.py), [nuove prove](../outputs/gnu_arc700/20261020T124323Z_858515dc/verified_evidence.json).

Il motore è `work/gnu_arc700_defined_memory_v2/install/bin/arc-elf32-run`, SHA-256 `d89684ef85cad75087d4185759d4a8a34f9868f053d7bfbe79e6a22cc1b9f893`, derivato dal DSPv7 provvisorio senza cambiare le istruzioni Nikon. L’originale GNU, il parentDSPv7 e i runner precedenti sono preservati. Il runner Main ordinario continua a usare il profilo precedente: il nuovo controllo si applica alle prove esplicite del verificatore qui indicato, non automaticamente a ogni esecuzione del progetto.

La bancaCPU scelta dal laboratorio è `[0,0x08000000)`, non una misura di RAM Nikon. Un bitmap registra i byte conosciuti. Prima di GETMEM viene controllata tutta la larghezza; solo dopo un SETMEM riuscito i byte scritti diventano conosciuti. GETIMEM controlla separatamente le letture del decoder. Una word non è considerata inizializzata dopo il solo store di un byte o di una halfword.

Gli input iniziali sono esplicitati tramite `S33_DEFINED_RANGES`: sezioni ELF allocate con contenuto nel file, controllate contro i segmenti e i loro byte; non interi PT_LOAD che includano header e buchi. Le sezioni NOBITS e gli argomenti/stack scritti dall’host non sono dichiarati per i profili Nikon. Il loader GNU usa le sezioni SEC_LOAD, come verificato nel suo sim-load.c: il test di lettura a800 evita di attribuire automaticamente provenienza agli header ELF non caricati.

La preparazione host di sim_create_inferior precede l’attivazione del controllo. Viene esclusa come fase dello strumento, senza dichiarare quei byte automaticamente validi per letture successive del guest. I registri iniziali argc/argv, gli altri registri CPU e AUX rimangono contesto del simulatore, separato dal controllo della RAM.

## Prove effettivamente eseguite

Comando dalla radice: `python3 Python_Trace_Scripts/s33_verify_gnu_defined_memory.py`, senza-O. **29casi** nel nuovo manifest:

| Gruppo | Casi | Esito |
|---|---:|---|
| Byte/halfword/word mai scritti |3|Arresto su primo byte sconosciuto |
| Byte o halfword scritti, poi lettura word |2|Arresto rispettivamente al byte+1 e+2 |
| Store/read byte,halfword,word |3|Passano; per la word viene confrontato il valore |
| Header ELF non caricato e stack NOBITS non scritto |2|Arresto sulle letture dati |
| Salto a codice mai caricato o scritto |1|Arresto decoder_fetch |
| Cinque descrizioni iniziali assenti/invalide |5|Arresto di configurazione controllato |
| Smoke,alias e nove testCPU precedenti |11|Passano con ABI C zero-NOBITS dichiarata soltanto per questi test |
| BaselineTBIB e Main avanzato |2|Limiti precedenti invariati |

I11test C di regressione usano esplicitamente le loro sezioni NOBITS a zero come input ABI. Per esempio lo smoke legge un globale C che dovrebbe partire da zero. Questa eccezione non viene applicata a TBIB/Main e non rende conosciuta tutta la loro RAM.

**TBIB:**10952 nel profiler; lettura MMIO108 a01009B6A come prima. **Main:**583306, lettura2byteFED2018 a169A84, nessuna segnalazione S33_UNDEFINED. L’intera traccia Main è identica per SHA-256 `70afb52bfe41e0e1f131758b27f6ef3672b72373f142a1ed81099d9ad10c2d7d` a quella precedente. Le letture nella RAM seguite da questi hook hanno dunque una provenienza dichiarata o uno store guest precedente, nel prefisso e nel modello attuali.

Questo rafforza le precedenti [prove con tre riempimenti](S33_Copertura_Esecuzione_e_Audit_Modello.md). Non dimostra che la ROM carichi realmente quei payload o che le istruzioni, i dispositivi e i dati dichiarati siano corretti per la fotocamera.

## Errori di costruzione conservati

La v1 attivava il controllo durante una lettura host di argc, prima del contesto di arresto dell’engine: produceva bad-long-jump prima del codice Nikon. Rimane conservata come prova respinta, non guasto firmware. La v2 lo attiva dopo sim_create_inferior. Un’altra verifica ha correttamente fermato lo smoke che presumeva BSS C a zero: è stato esplicitato il suo contratto ABI, senza estendere quella presunzione ai boot Nikon.

Il primo verificatore basato sui segmenti ELF è stato affinato per dichiarare soltanto sezioni realmente caricate. Il nuovo test800 controlla questa distinzione. Tutti i risultati accettati qui sono quelli del manifest finale29casi, non dei tentativi intermedi.

## Che cosa resta fuori

Il controllo copre gli accessi CGEN GETMEM/SETMEM/GETIMEM, non ogni trasferimento DMA, callback host o altra via diretta di accesso alla memoria. Non è un tracciamento dell’inizializzazione dei registri. MMIO e finestre oltre128MiB non sono inclusi nel bitmap; i dispositivi non mappati continuano a fermare il simulatore.

`decoder_fetch` può includere lookahead del parser PBB: una sua segnalazione non va automaticamente interpretata come istruzione eseguita dalla CPU. Le prove attuali non mostrano tali arresti nei boot. Il bitmap è globale al singolo processo/CPU del runner; riavvii multipli nello stesso processo e CPU concorrenti richiederebbero gestione del ciclo di vita.

DSP resta provvisorio, timer/IRQ non certificati; restano ingressi indipendenti TBIB/Main con contesto laboratorio. Passaggio reale dal caricatore, fisica delle finestre alte, overlay e recupero non risolti. FirmwareV1.1,16payload e input preservati perhash, nessun hardware. Prossimo: servizi SD al selettore e collocazione del codice per il [prototipo collegato](S33_HiddenMenu_Prototipo_Collegato_Offline.md), poi proseguire i dispositivi/handoff mantenendo il controllo delle letture.
