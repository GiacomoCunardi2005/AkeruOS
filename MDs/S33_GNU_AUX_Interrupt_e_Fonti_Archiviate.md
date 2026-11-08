# GNU ARC700: limiti AUX corretti, interrupt e fonti conservate

**Continuazione GNU corrente:** [SRdelay e controlli boot](S33_GNU_Controlli_Boot_e_Correzione_SR.md). Il default usa SRdelayv2; DSP separato v6.54test correggono la perdita del salto conSR nel delay slot. Main conclock100zero arriva adAUX201 a000B3106 (475857profiler); TBIB ha profili condizionali FED3800zero/nonzero distinti. Non usare la variante SRdelayv1 respinta, né le sintesi storiche sotto come punto corrente.

## Continuazione: scritture iniziali verificate e arresto FE80070

Il [verificatore dedicato](../Python_Trace_Scripts/s33_verify_gnu_boot_device_writes.py) esegue il corpo TBIB originale010091E4 e il wrapper01000C18 con motore AUXv2, senza DSP. [Quattro prove conservate](../outputs/gnu_arc700/20261020T113107Z_165b4b5d/verified_evidence.json): init con celle iniziali0, init con0xA5, wrapper con0xA5, poi proseguimento TBIB conDSPv5. Prima delle letture aggiunte dal chiamante sintetico, le routine Nikon non leggono le celleMMIO. Verificati ritorno0, SP/r13 conservati,12scritture init e14nelwrapper; non sono stati inventati valori di lettura del dispositivo.

La mappa aggiunta contiene esclusivamente12celle di2byte, inizializzate0xA5: FE40004=4321; FE40008/0C/10=FFFF; FE40018/1C/20/24=0; FE40028=2; FE4002C=100; FE40030/34=0. Il wrapper sostituisce FE40008 con4321 e FE4000C conECA2, costruendo campi dai suoi4argomenti. Sono valori scritti dal software, non risposte hardware convalidate. Identità e significato dei registri restano aperti.

Il proseguimento limitato conDSPv5 e quattrohalfword clockzero raggiunge **lettura halfword0FE80070 a01009324,33198nel profiler**. Le14scritture sono confermate nella traccia e non sono seguite da letture delle celle FE400xx nel percorso controllato. Non è stato modellato il comportamento fisico del dispositivo. Questo è il nuovo punto di ripresa: routine01009314, origineFE80070, maschere e consumatore; il precedente stop FE40004 sotto resta il checkpoint intermedio. Nessuna prova di bootcompleto oSD, nessun cambiamento alla percentuale funzionale.

Comando riproducibile: `python3 Python_Trace_Scripts/s33_verify_gnu_boot_device_writes.py` oppure `make -C AkeruOS gnu-device-verify`. I disassemblaggi GNU sono divisi ai confini dei pool, evitando che i dati intermedi vengano usati come istruzioni.17finestre e16parole di pool controllate; i soli due calcoliPC-relative dichiarati riguardano i loadshort91E8/91EA.

20 ottobre 2026 — R3/R4. Questo checkpoint sostituisce, per il punto di ripresa GNU, le sintesi v3 del [rapporto precedente](S33_GNU_MainCode_Divisione_e_DSP_Sperimentale.md). L'obiettivo resta l'esecuzione completa del firmware, ancora non raggiunta. Circa 10% funzionale e NO-GO hardware invariati.

## Difetto verificato nel simulatore originale

La banca `h_auxr[64]` del GNU originale viene indicizzata direttamente anche per AUX estesi. La variante diagnostica con `-fsanitize=bounds -fno-sanitize-recover=all` rileva accessi fuori array nei probe LR0x94/SR0x45 e nella vera esecuzione TBIB: indice67, prima del confine MMIO storico. Non è un difetto dimostrato della CPU Nikon. Le vecchie esecuzioni restano osservazioni riproducibili del motore storico, ma non certificano la correttezza CPU.

Prove: [probe isolati](../outputs/gnu_arc700/20261020T111026Z_3926bb75/verified_evidence.json), [TBIB con sanitizer](../outputs/gnu_arc700/20261020T112150Z_165c1cb1/verified_evidence.json), [verificatore](../Python_Trace_Scripts/s33_verify_gnu_aux_bounds.py). Il binario originale SHA-256 `7d6ccd1bc2291f377201e8cd1027c6ecf94d30901f13251c1c6bf647aa8a43dc` resta intatto.

## Motori separati e controlli eseguiti

Il [costruttore AUX](../Python_Trace_Scripts/s33_build_gnu_aux_fixed.py) produce `work/gnu_arc700_aux_fixed_v2`, con banca2048 e layout coerente nei tre header CPU5/6/7, ricompilati insieme ai relativi accessor. Letture AUX estese non configurate e indici fuori banca si arrestano esplicitamente. Le scritture generiche restano semplice conservazione del valore, senza effetti fisici modellati. AUX0x94 mantiene l'ipotesi di laboratorio reset0, identificata nel log. Il binario AUXv2 ha SHA-256 `1fd3987c0cb8c8911d3b412160c5772773cc8b3b23f46aa3a2bacede0f128044`.

Il manuale ARCompact5115-029, figura51 p54 e tabella22 pp75–76, permette di aggiungere per ARC700: AUX0x43 con cancellazione dei bit0/1 scrivendo1, e AUX0x200 con priorità IRQ3..31, bit0..2 riservati a zero e priorità iniziale livello1. Il modello parte senza interrupt ricevuti; generazione/consegna e transizioni sticky da hardware restano da verificare. I test W1C partono da zero: non provano la consegna di un interrupt.

| Comando eseguito dalla radice | Risultato conservato | Copertura e limite |
|---|---|---|
| `python3 Python_Trace_Scripts/s33_verify_gnu_aux_fixed.py` | [24 casi PASS_AUX_FIXED](../outputs/gnu_arc700/20261020T112618Z_2720554a/verified_evidence.json) | 11 smoke/alias/CPU, baseline,12 probe AUX/IRQ; nessun errore sanitizer nei percorsi controllati |
| `python3 Python_Trace_Scripts/s33_verify_gnu_dsp_lab.py` | [47 casi PASS_EXPERIMENT_ONLY](../outputs/gnu_arc700/20261020T112719Z_fa834d6a/verified_evidence.json) | DSPv5 basato su AUXv2;26 prodotti isolati,7 rifiuti,11 core,baseline e2 ingressi TBIB |
| `python3 Python_Trace_Scripts/s33_verify_gnu_tbib_arithmetic.py --multiply` | [47 prodotti TBIB](../outputs/gnu_arc700/20261020T112720Z_38631b45/verified_evidence.json) | Corpo originale0103ECBC; risultato modulo2^32 secondo ipotesi DSP, nessuna prova fisica |
| `python3 Python_Trace_Scripts/s33_run_gnu_main.py` | [PASS_AUX_FIXED](../outputs/gnu_arc700/20261020T112709Z_85e8d2c7/verified_evidence.json) | Ingresso candidatoBB540,444557 nel profiler, stop lettura2byte FE80108 a17A6D6 |
| `python3 Python_Trace_Scripts/s33_run_gnu_main.py --dsp-lab` | [PASS_EXPERIMENT_ONLY](../outputs/gnu_arc700/20261020T112710Z_e518b2fa/verified_evidence.json) | 444568 nel profiler, stop lettura2byte FE80100 a17A700 |

La variante DSPv5 ha SHA-256 `e70ffb96da8f5fa41a0f5facc3eff73820512f87a11a504270cb5eaff178a99d`. Costruttore, patch e manifest sono in [build_v5](../outputs/gnu_arc700_dsp/build_v5/verified_evidence.json). I tentativi precedenti restano conservati per provenienza; v3 e precedenti avevano anche il difetto AUX. L'interpretazione DSP resta provvisoria: ZA/noF/MACMODE esplicitamente zero, prodotti unsigned per canale16bit senza possibile saturazione; signed limitato a piccoli positivi o fattorezero. Mapping raw r56/r57 e altri effetti DSP non sono provati indipendentemente. Nessuna istruzione Nikon è saltata o sostituita.

Le49 divisioni TBIB precedenti [restano una prova storica distinta](../outputs/gnu_arc700/20261020T110024Z_0596588b/verified_evidence.json), non sono state rieseguite in questo checkpoint. Il loro risultato aritmetico non dipende dal nuovo modello DSP.

## Nuovo limite raggiunto

Nel TBIB, con sole halfword FE800F8/FE80064/FE80108/FE80100 sintetiche zero e DSPv5, il precedente arresto AUX512 è superato. Il [probe esplorativo](../outputs/gnu_arc700/20261020T112709Z_db6738a6/verified_evidence.json), confermato dal verificatore DSP, arriva a **scrittura halfword FE40004 a010091F8**, dopo33079 nel profiler. La traccia carica FE40004 e4321 con due load PC-relative a010091E8/EA; salta i pool intermedi ed esegue `stw.di r0,[r1,0]`. La natura della periferica e il suo protocollo non sono ancora identificati: non trattare questo indirizzo come RAM.

Prossimo: verificare con GNU la routine010091E4, pool e chiamanti, poi ricostruire registro4321, letture successive ed eventuali attese prima di introdurre un modello dispositivo. Non azzerare registri sconosciuti per superare il confine. Restano assunti RAM GNU zero, avvio/argomenti e base vettori; non sono dimostrati resetROM, BSS nel nuovo run, residenza overlay, scheduler, UI, JPEG o SD. Il profiler è una misura del simulatore, non di tempi fisici o prova di tutte le istruzioni ritirate.

## Fonti scaricate per le prossime sessioni

Per richiesta esplicita dell'utente, conservare i file pubblici utili con URL, byte e SHA-256. Il PDF DSP Synopsys dietro login è stato dichiarato non ottenibile dall'utente: non è un prerequisito per continuare e non è stato scaricato.

| Fonte locale | Provenienza e uso |
|---|---|
| [ARCompact5115-029,341p](../outputs/gnu_arc700_aux/sources/ARCompact_5115-029.pdf) | [Mirror pubblico](https://docs.alexrp.com/arc/arcompact.pdf), [manifest](../outputs/gnu_arc700_aux/sources/manual_manifest.json), testo estratto e immagini pp54/75/76 conservati. Hash af273e63c128965e5789fc48d3318842ba19753c1449e157dee59b2f10b545d0. Fonte dei due registri IRQ descritti sopra |
| [ARC700 External Interfaces,66p](../outputs/arc700_public_references/ARC700_ExternalInterfaces_Reference.pdf) | Riferimento per bus, segnali e interrupt esterni; acquisito e testo estratto, nessun raccordo ASIC Nikon già provato |
| [ARC700 Memory Components,14p](../outputs/arc700_public_references/ARC700_MemoryComponents_Reference.pdf) | Riferimento per componenti memoria; acquisito e testo estratto, non prova della RAM fisica S33 |
| [ARC700 MMU,46p](../outputs/arc700_public_references/ARC700_MemoryManagementUnit_Reference.pdf) | Riferimento per traduzione/protezione; acquisito e testo estratto, non prova della configurazione Nikon |
| [Sorgenti MAME fissati per commit](../outputs/gnu_arc700_dsp/sources/source_manifest.json) | Doppio prodotto signed16; contratto unsigned/raw non risolto |

Per gli ultimi tre PDF, [manifest URL/hash](../outputs/arc700_public_references/source_manifest.json). Sono documenti ARC International ospitati su mirror pubblico, non fonti Nikon o misure hardware. Il manifest registra anche il certificato del mirror non valido per il nome host; il trasferimento non ha richiesto credenziali e l'hash identifica la copia acquisita, non autentica da solo l'editore. Verificati formatoPDF, apertura conpdfinfo ed estrazione testo; nessun PDF modificato. Tutti i file Nikon originali restano intatti e non vengono ridistribuiti.
