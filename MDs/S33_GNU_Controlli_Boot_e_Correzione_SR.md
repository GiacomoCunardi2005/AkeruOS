# GNU ARC700: controlli TBIB, correzione SR nel delay slot e limite AUX201

**Continuazione GNU corrente:** [sorgente IRQ software e MainCode](S33_GNU_Sorgente_IRQ_Software_e_Proseguimento_Main.md). Il nuovo profilo esplicito DSPv7/sorgente software vuota supera AUX201 e arriva a letturaFED2018 a169A84; non è un reset hardware convalidato. I profili SRdelayv2/DSPv6 precedenti restano disponibili senza il nuovo flag.

20 ottobre2026 — R3/R4. Risultato corrente: corretto un difetto del motore nei salti con `SR` nel delay slot. MainCode candidato arriva ora al salvataggio di contesto L1 e si arresta esplicitamente sulla lettura AUX0x201 a000B3106. La consegna IRQ proviene dal modello timer GNU preesistente; non prova il comportamento interrupt Nikon. Firmware completo, UI, fotografia e recupero restano non dimostrati; circa10% funzionale e NO-GO hardware invariati.

Questo rapporto sostituisce per il punto di ripresa GNU [AUX/IRQ e fonti](S33_GNU_AUX_Interrupt_e_Fonti_Archiviate.md). I risultati precedenti restano storia; DSPv5 e AUXv2 conservano il difetto SR qui isolato.

## Difetto SR e correzione verificata

Nel percorso Main osservato, `beq.d` a000B306C selezionava000B3084, eseguiva `sr r0,[0x43]` nel delay slot000B3070, ma il motore continuava erroneamente a000B3074. Questo selezionava il tratto L2 anche quando il ramo aveva scelto il tratto L1. [Osservazione iniziale](../outputs/gnu_arc700/20261020T113745Z_40f1fa64/verified_evidence.json), [10 probe preliminari](../outputs/gnu_arc700/20261020T113911Z_5c394228/verified_evidence.json).

Le tre forme SR generate hanno `SEM_BRANCH_INIT/FINI`; il FINI sostituisce lo stato PBB del salto precedente con “non preso”. I descrittori SR sono marcati COND_CTI e tale confine deve restare fuori dal delay slot. La correzione non modifica i byte Nikon: il parser PBB marca l'istruzione nel delay slot usando il byte ARGBUF riservato `unused`, azzerato all'estrazione; soltanto in quel caso SR preserva lo stato del salto precedente. Fuori dal delay slot mantiene il FINI originale. Nessun layout CPU viene cambiato.

La prima variante che eliminava FINI sempre è stata respinta: i piccoli probe passavano, ma la baseline finiva in un ciclo spurio fino a storeFFFFFFFC a0101F50A. [Verifica fallita conservata](../outputs/gnu_arc700/20261020T114140Z_6be25b38/verified_evidence.json); `work/gnu_arc700_srdelay_fixed_v1` non va usato. Non è stata attribuita quella divergenza al firmware né aggiunta RAM per nasconderla.

La variante corretta è `work/gnu_arc700_srdelay_fixed_v2`, SHA-256 `fcd5513e0ee0f12fd5e1993a83fe30342d81c37f7fc460a75dd50e10969a1cb2`. [Costruttore](../Python_Trace_Scripts/s33_build_gnu_srdelay_fixed.py), [patch e manifest](../outputs/gnu_arc700_srdelay/build_v2/verified_evidence.json), [verificatore](../Python_Trace_Scripts/s33_verify_gnu_srdelay.py).

`python3 Python_Trace_Scripts/s33_verify_gnu_srdelay.py`: [54casi PASS_SR_DELAY_FIX](../outputs/gnu_arc700/20261020T114353Z_9d307271/verified_evidence.json).21combinazioni per motore:7slot (NOP,3formeSR con4destinazioni,LR,store) ×3rami (BEQ preso/non preso eB incondizionato);8discrepanze vecchie,0nelle21nuove. Seguono11smoke/alias/testCPU e baselineTBIB10952→MMIO108 a01009B6A, invariata. I test non certificano ogni scrittura AUX speciale: flushcache, loop, timer e consegna IRQ restano ambiti distinti. Esclusi operandi LIMM nel delay slot; il manualeARCompact5115-029 p85 li elenca fra le sequenze non consentite.

## DSP composto e MainCode

Il [costruttore DSP](../Python_Trace_Scripts/s33_build_gnu_dsp_lab.py) compone ora DSPv6 sopra SRdelayv2, conservando bounds AUX e sanitizer. Binario `work/gnu_arc700_dsp_lab_v6`, SHA-256 `04ac28109a5a44f925d2067406c7ffdbc977f1bd82b1b0f5ce613bc2b5c01acb`; [manifest](../outputs/gnu_arc700_dsp/build_v6/verified_evidence.json). Il mapping raw56/57 e la semantica DSP restano inferiti nel dominio limitato già dichiarato, non certificati dalla nuova correzione SR.

| Verifica effettivamente eseguita | Evidenza | Risultato e limite |
|---|---|---|
| `python3 Python_Trace_Scripts/s33_verify_gnu_dsp_lab.py` | [47casi](../outputs/gnu_arc700/20261020T114500Z_2648a736/verified_evidence.json) | PASS_EXPERIMENT_ONLY; baseline,core,prodotti isolati,rifiuti e2percorsi TBIB. Non semantica DSP fisica |
| `python3 Python_Trace_Scripts/s33_run_gnu_main.py` | [Main senza DSP](../outputs/gnu_arc700/20261020T114500Z_007cfae5/verified_evidence.json) | SRdelayv2,444557profiler→letturaFE80108 a17A6D6 |
| `python3 Python_Trace_Scripts/s33_run_gnu_main.py --dsp-lab --clock100-lab` | [Main conDSPv6 e100zero](../outputs/gnu_arc700/20261020T114535Z_46432105/verified_evidence.json) |475857profiler→AUX201 sconosciuto a000B3106,signal5 e nessun faultmemoria; PASS_LIMITED_EXPERIMENT |
| `python3 Python_Trace_Scripts/s33_verify_gnu_boot_control_cluster.py` | [12casi](../outputs/gnu_arc700/20261020T114500Z_aaacaa81/verified_evidence.json) | PASS_CONDITIONAL_MODEL; dettagli sotto |

Il nuovo flag `--clock100-lab` richiede `--dsp-lab` e aggiunge solo la halfwordFE80100 sintetica zero, oltre alle precedenti F8/64/108zero. Non mappa i controlli TBIBFE400xx/FE80070/FED3800: Main prende un percorso diverso. Un tentativo precedente che aggiungeva quei profili aMain si fermava già suAUX201, prima del loro uso; quelle opzioni non sono state mantenute nel runner. Il default resta l'esperimento senza DSP, con solo SR/AUX corretti.

La traccia Main mostra un evento timerGNU su15934C, salto al vettore000818 e ingresso000B2F9E con r1=3. Nel tratto verificato, dopo BEQ000B306C e SR000B3070 si eseguono ora000B3084/86 e il salvataggio STATUS32_L1/ILINK1. Il verificatore controlla presenza di queste istruzioni ed esclusione del vecchio tratto000B3074/7A in quella sezione. Il numero475857 è il profiler del simulatore, non tempi fisici né prova di ogni istruzione ritirata.

Prossimo prioritario Main: **AUX_IRQ_HINT0x201, lettura000B3106**, contratto del software interrupt e contesto timerGNU. Il manuale già archiviato5115-029 p55 identifica AUX201 come software interrupt; va raccordato a reset/lettura/scrittura/cancellazione senza fingere interrupt disponibili. Non fornire un valore zero solo per avanzare. Verificare anche l'aggiornamento dello stato sticky IRQ e la corrispondenza fra modello timer e salvataggio L1 prima di chiamare operativo lo scheduler.

Main usa ancora ingresso candidatoBB540, RAM128MiBzero, base vettori e avvio di laboratorio; BSS nel nuovo run non verificata separatamente, nessun passaggio resetROM→Main dimostrato e nessun overlay11–15 residente insieme. Caricamenti ELF0/1/TBIB confrontati interamente con i payloadV1.1; non sono stati sostituiti opcode. GNU originale e firmware originale verificati per hash e intatti.

## Contratto condizionale dei controlli TBIB

Il [verificatore](../Python_Trace_Scripts/s33_verify_gnu_boot_control_cluster.py) segue la routine01009314 dopo il precedente stopFE80070. Quattro contenuti iniziali espliciti per11celle halfword:0000,FFFF,A5A5,5A5A. Per ogni profilo esegue sia un ingresso isolato con SRdelayv2 senza DSP, sia TBIB candidato conDSPv6 e le4halfword clockzero;8casi si fermano prima di leggereFED3800 a01009464. Nessun valore è assunto come reset fisico.

| Cella | Valore finale nel modello R/W, dato inizialex |
|---|---|
| FE80070 | x&4FFF (cancella12/13/15) |
| FE8009C | x&DC7F |
| FE800A8,FE800B4 |0,dopo impulso4000→0 |
| FE800BC |F300,dopo5300 se(x&C00)==0,altrimenti5700 |
| FE800C0 |x&10FF |
| FE800C8 |(x&0CFF)\|F000 |
| FE800CC |BFF8 |
| FED2800,FED2804 |0300,2311 |
| FED3000 |0,dopo5140→0 |

Controllati17pool di4byte e16finestre GNU separate dai dati;18store e8loadMMIO nel tratto per ciascun ingresso. I file conservano valori iniziali/finali e padding esternoA5 immutato. Il modello conserva le scritture e ne rilegge il valore: è un'ipotesi R/W, non semanticaW1C, impulso fisico, temporizzazione o risposta periferica convalidata.

Altri4casi esploranoFED3800=0/1 con gli altri controlliA5A5. Conzero, la vera routine ritorna02C00030, conservandoSP e r13..r16 nel chiamante sintetico; il chiamante boot a01000128 prosegue direttamente verso010030F4 senza controllare subito quel ritorno. Il boot si ferma poi su letturaFED2040 a01003318 (34384profiler). Con1, entra01012104/01011FF4 e si ferma su letturaFEF0020 a01011F68 (33315profiler). Il significato fisico del codice02C00030 e dello stato rimane aperto: non chiamare il ramozero un'inizializzazione riuscita.

La prima versione dei file di prova ignorava il padding del memory-mapfile GNU: per indirizzi non multipli di8, `sim-memopt.c` usa buffer+addr%8. Il test ha rilevato valori lettiA5A5 al posto del profilo e si è fermato; i risultati falliti restano conservati. Lo script corretto colloca i dati all'offsetaddr%8 e controlla il padding prima/dopo. Non è una correzione del firmware o un nuovo difetto CPU.

Pista TBIB successiva: stato nonzero→FEF0020/01011F68, statozero→FED2040/01003318. Entrambe sono ipotesi di laboratorio; il punto prioritario corrente per Main è AUX201. Non confondere i due ingressi o trasferire automaticamente fra essi il significato delle periferiche.

## Riproduzione e limiti

Comandi sopra dalla radice, Python senza-O. Ogni esecuzione produce una nuova directory con manifest, comandi, tracce, hash e snapshot. I54testSR,47DSP,12controlli e2ingressiMain indicati sono stati eseguiti in questo checkpoint; le47moltiplicazioni helper e49divisioni dei rapporti precedenti non sono state rieseguite qui e restano prove storiche distinte.

Nessun avvio completo, task fotografico AkeruOS, acquisizioneJPEG, salvataggioSD o recupero dimostrato. I PASS con ipotesi hardware/DSP attestano solo quei modelli e percorsi. Nessuna prova hardware effettuata, nessun invioUSB/PTP o scrittura della macchina.
