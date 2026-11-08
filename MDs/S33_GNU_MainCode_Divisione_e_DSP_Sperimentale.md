# GNU: MainCode eseguito, divisione Nikon verificata e DSP sperimentale separato

**Continuazione corrente,20 ottobre2026:** leggere prima [AUX/IRQ e fonti archiviate](S33_GNU_AUX_Interrupt_e_Fonti_Archiviate.md). Il motore GNU originale ha un difetto AUX fuori array confermato nel TBIB. `gnu-main` usa ora AUXv2 corretto; DSP separato v5 supera il vecchio limite AUX512 e arriva a scrittura4321→FE40004, restando provvisorio. I riferimenti a v3, attesaPDF e motore originale come default nelle sezioni storiche sotto sono superati.

20 ottobre 2026, R3/R4. Continua [l'integrazione GNU](S33_GNU_ARC700_Integrazione_e_Limite_DSP.md) verso l'esecuzione completa del firmware. Il risultato più forte di questo checkpoint è **MainCode sul motore GNU originale**, senza semantica DSP aggiunta: 444.557 istruzioni dichiarate dal profiler, fino alla lettura MMIO `0x0FE80108` a `0x0017A6D6`. Sono inoltre verificate 49 divisioni della routine TBIB originale. Una variante DSP distinta consente esperimenti oltre il precedente limite, ma resta esplicitamente provvisoria.

L'obiettivo «eseguire tutto il firmware sull'emulatore» **non è raggiunto**. Non sono dimostrati boot completo, scheduler operativo, UI, foto, JPEG o persistenza SD. Non aumentano il circa 10% funzionale e non cambia il NO-GO hardware.

## Comandi e risultati riproducibili

Dalla radice:

```bash
make -C AkeruOS gnu-main
make -C AkeruOS gnu-div-verify
make -C AkeruOS gnu-dsp-verify
make -C AkeruOS gnu-verify
```

`gnu-main` usa sempre il motore originale. La selezione sperimentale richiede invece un'opzione esplicita:

```bash
python3 Python_Trace_Scripts/s33_run_gnu_main.py --dsp-lab
```

| Gruppo | Esecuzione conservata | Risultato |
|---|---|---|
| MainCode, GNU originale | [manifest](../outputs/gnu_arc700/20261020T110255Z_24c70879/verified_evidence.json) | PASS: fault atteso, 444.557 istruzioni |
| MainCode, DSP provvisorio | [manifest](../outputs/gnu_arc700/20261020T110306Z_5b0f7a72/verified_evidence.json) | PASS_EXPERIMENT_ONLY: MMIO100 a17A700, 444.568 istruzioni |
| Divisione TBIB originale | [manifest](../outputs/gnu_arc700/20261020T110024Z_0596588b/verified_evidence.json) | 49/49 quozienti e resti corretti sul GNU originale |
| DSP laboratorio v3 | [manifest](../outputs/gnu_arc700/20261020T110409Z_bcdeed70/verified_evidence.json) | 41 casi conformi ai limiti del modello, non certificazione ISA |
| Regressione motore originale | [manifest](../outputs/gnu_arc700/20261020T110411Z_49724761/verified_evidence.json) | 23 casi del checkpoint precedente nuovamente PASS |

Le suite condividono alcuni controlli di baseline: questi numeri non si sommano per calcolare una copertura ISA. Il profiler GNU e i record della traccia restano misure diverse; la differenza della baseline TBIB è ancora aperta.

## Caricamento MainCode, distinto dal reset hardware

Il nuovo [runner Main](../Python_Trace_Scripts/s33_run_gnu_main.py) riusa `verified_payloads`, ricontrolla il firmware CMP3 V1.1 e genera un ELF di laboratorio con **byte originali**, senza prefissi di codice aggiunti. Usa due soli payload TBM e il corpo TBIB separato:

| Sezione | Base | Dimensione | Provenienza |
|---|---|---:|---|
| MainCode | `0x000AD800` | `0x2AE400` | Payload0 verificato |
| Dati | `0x00360800` | `0xC7E00` | Payload1 verificato |
| TBIB | `0x01000000` | `0x44BBC` | Corpo originale già verificato |
| Stack di servizio ELF | `0x010D0000` | `0x10000` | NOBITS sintetica del laboratorio |

L'ingresso ELF è il candidato `0x000BB540`, già usato dal precedente modello P-code. Sono ricontrollati i byte di ingresso e della `mov sp,0x005DADDC` a `0x000BB5BC`: il firmware imposta il proprio SP e poi sottrae `0x10`. La stack ELF di servizio non viene dichiarata memoria libera per AkeruOS.

L'ELF ha quattro PT_LOAD espliciti, uno per ogni sezione; il runner confronta integralmente i byte con i payload originali. L'uso di PHDRS evita che il linker introduca gli header ELF prima di MainCode nel segmento caricato. Il primo tentativo di generazione, conservato in `20261020T110227Z_21d83da7`, si ferma proprio sul controllo di identità del segmento: non fu eseguito come firmware.

Il profilo Main è **128 MiB zero** di laboratorio. Non implementa l'arresto sulle letture RAM sconosciute del P-code. Non vengono caricati insieme i payload11–15 sovrapposti né inventate finestre alte. La nuova prova non misura capacità fisica e non riporta come appena verificato il vecchio controllo BSS da A5: il suo manifest indica `bss_clearing_proven_in_this_run=false`.

Con F8=0 e halfword64=0, il motore originale arriva a `0x0017A6D6`, lettura da due byte di `0x0FE80108`, exit11. È lo stesso confine MMIO del ramo statico/P-code precedente, raggiunto ora eseguendo MainCode su GNU. Non è dimostrata la transizione reale ROM/TBIB→MainCode: i due ingressi restano prove separate.

## Routine di divisione: esecuzione originale, nessun DSP sostitutivo

Il [verificatore aritmetico](../Python_Trace_Scripts/s33_verify_gnu_tbib_arithmetic.py) carica il corpo TBIB originale mediante un file mmap **copiato nella directory di prova**. Un piccolo chiamante sintetico a0x1000 chiama realmente `0x0103EDE4` mediante `jl [r12]`; non simula il servizio e non ne riscrive il risultato. Controlla `r0=quoziente`, `r1=resto` contro `divmod` Python e termina con il trap di laboratorio solo dopo il confronto.

Sono eseguite 7×7 coppie: dividendi0,1,15,12.000.000,7FFFFFFF,80000000,FFFFFFFF e divisori1,3,16,1024,8192,80000000,FFFFFFFF. Il motore è quello originale con SHA-256 `7d6ccd1bc2291f377201e8cd1027c6ecf94d30901f13251c1c6bf647aa8a43dc`. Tutti i casi tornano con quoziente e resto attesi; il corpo mappato è identico prima/dopo. Non sono provati divisione per zero o ingresso signed0103EDF4.

Sono conservati anche i disassemblati del chiamante clock01009B60 e del gruppo aritmetico0103ECBC..0103EF20. Il getter010099D0 usa il pool01009AE8, che punta alla word originale **010412C4=00B71B00=12.000.000**. Questo è un valore software verificato nel corpo TBIB; non è una misura di oscillatore o una frequenza hardware attribuita.

## Fonti DSP e ciò che rimane inferenza

È stata acquisita una nuova fonte primaria di implementazione: [MAME, commit da56c5a, arcompact.cpp](https://github.com/mamedev/mame/blob/da56c5ac5031db8383f69b07890ffd9a3bd659b5/src/devices/cpu/arcompact/arcompact.cpp), con i relativi [handler MULDW](https://github.com/mamedev/mame/blob/da56c5ac5031db8383f69b07890ffd9a3bd659b5/src/devices/cpu/arcompact/arcompact_execute_ops_05.cpp). Il sorgente esegue due prodotti signed16×16 separati e tratta a parte il risultato compattato. [Copie con hash e URL](../outputs/gnu_arc700_dsp/sources/source_manifest.json).

Questo riscontro non implementa MULUDW per Nikon e non convalida da solo la pubblicazione raw nei registri r56/r57. Per la variante locale l'ordine alto→r56, basso→r57 resta un'inferenza dal consumatore Nikon e dalla ricombinazione del suo helper di prodotto. Non è stata convertita in una conclusione hardware.

La pagina del produttore elenca il documento **ARC700 DSP Options Reference**. Il [link Synopsys al PDF](https://www.synopsys.com/dw/doc.php/iip/DWC_ARC_VIDEO_401V/latest/doc/ARC700_DSPOptions_Reference.pdf) rimanda alla pagina di accesso; il corrispondente collegamento MIPS ha restituito404. Il contenuto del manuale non è stato acquisito e il link è stato passato all'utente, che si è offerto di provare. Il datasheet pubblico ARCv1 DSP descrive le opzioni XY ma non risolve i contratti delle due istruzioni. Le ricerche di nomi o l'esistenza di un link non sono considerate definizioni della CPU.

## Variante DSP sperimentale, arresti mantenuti

Il [costruttore](../Python_Trace_Scripts/s33_build_gnu_dsp_lab.py) copia sorgenti e build GNU in `work/gnu_arc700_dsp_lab_v3/` e ricompila soltanto quella copia dentro la stessa immagine Podman. [Patch, comando, log e hash](../outputs/gnu_arc700_dsp/build_v3/verified_evidence.json). Binario v3 SHA-256 `bc41a7653b889eb479742a68342d6b4f3d41a07a2931a0011a59f88cdfeef868`; il binario del handoff resta immutato.

Il dominio supportato è ristretto: formato registro/registro, destinazione0, F=0, registri ordinari0..31, scrittura **esplicita** di MACMODE0; entrambi gli operandi devono stare in0..32767 oppure almeno uno deve essere interamente zero. Nel primo caso il canale alto vale zero; nel secondo entrambi i prodotti di canale valgono zero anche con l'altro operando largo. Non si modellano valori negativi, prodotti con due canali nonzero, altre modalità, .f, destinazioni generali o XY.

La variante usa il descrittore interno GNU R/R a quattro byte di MULULW come contenitore del formato; per le codifiche MULDW/MULUDW intercettate esegue un blocco semantico distinto. **La riga GNU della traccia può quindi chiamarsi `mululw`**, mentre i record `S33_DSP_LAB` conservano PC, word originale, ingressi, r56/r57 e `provisional=1`. Non è una sostituzione dei byte Nikon e non viene usata come prova che Nikon abbia eseguito MULULW. Il motore originale continua a rifiutare gli stessi byte.

Gli ingressi fuori dominio si fermano con `S33_DSP_GUARD` e segnale5; le forme non decodificate continuano a fermarsi con segnale4. Non sono accettati timeout come successi. La variante registra `independent_complete_semantics_proven=false`, e i suoi manifest sono `PASS_EXPERIMENT_ONLY`.

I 41 casi comprendono 11 controlli core preesistenti, la baseline TBIB esatta, 20 prove con controllo di r56/r57, conservazione degli operandi e dei flag, 7 rifiuti intenzionali e 2 proseguimenti TBIB. I test verificano la coerenza del dominio implementato; il risultato atteso sui registri raw rimane basato sull'ipotesi documentata.

Gli errori locali sono conservati: i primi due tentativi del costruttore si fermarono nella selezione dei frammenti generati, prima della build. La prima build spostava h_cr e rompeva i getter condivisi ARC5: lo smoke test fermato aSP−4 lo rilevò (`20261020T105309Z_f06a1817`). La correzione aggiunge lo stato sperimentale **dopo tutti i campi hardware originali** e ricompila il sottosistema sim; i controlli successivi superano smoke/alias/suite e baseline. La v2 aveva34 casi; la v3 aggiunge i prodotti con operandozero e conserva l'arresto sugli altri input. Non attribuire questi errori di sviluppo a Nikon o al motore originale.

## Confine raggiunto e prossima verifica

Nel TBIB, MMIO108=0 produce fattori1×1. La variante esegue MULDW01009B8C, la successiva `extw r13,r57` legge1 e il firmware arriva alla lettura MMIO100 a01009B94. MainCode riproduce il corrispondente percorso MULDW17A6F8→lettura100 a17A700.

Nel secondo tentativo TBIB anche **MMIO100=0** è dichiarato sintetico. Due MULUDW con un fattorezero passano nell'helper0103ECBC. Più avanti la stessa routine riceve r0=00B71B00 e r2=00010000: il modello si ferma intenzionalmente a **0103ECC8**, word280D00BE, senza inventare il prodotto dei canali nonzero. GNU dichiara11.347 istruzioni nel tentativo; il calcolo clock non è ancora concluso.

Il prossimo punto utile è il contratto DSP raw e MACMODE, idealmente dal PDF pertinente, poi prove indipendenti su canali nonzero, flag/sticky e accumulo. L'helper0103ECBC fornisce un vincolo matematico sulla ricombinazione, non una certificazione autonoma dell'istruzione. Per arrivare al risultato richiesto restano poi caricamento/fasi degli altri payload, MMIO ulteriori, timer/interrupt, task, periferiche fotografiche e storage con completamento osservabile. Questo checkpoint mantiene l'obiettivo completo attivo; nessun punto di ingresso candidato o risultato sperimentale viene promosso a «tutto il firmware eseguito».
