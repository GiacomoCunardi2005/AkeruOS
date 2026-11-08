# GNU ARC700: sorgente IRQ software vuota e proseguimento MainCode

20 ottobre 2026 — R3/R4. Il nuovo esperimento MainCode supera AUX201, legge quattro volte lo stato software vuoto e percorre quattro ritorni dal gestore del contesto. Si ferma sulla lettura halfword **0x0FED2018 a 0x00169A84**, dopo 583.306 nel profiler GNU. Non è un boot completo: circa 10% funzionale e NO-GO hardware invariati.

Questo è il punto di ripresa GNU successivo a [SR nel delay slot](S33_GNU_Controlli_Boot_e_Correzione_SR.md). La correzione SRdelayv2 resta conservata; non viene modificata in questo checkpoint.

## Contratto AUX201 e scelta del laboratorio

Il [manuale ARCompact 5115-029](../outputs/gnu_arc700_aux/sources/ARCompact_5115-029.pdf), p55, figura52, identifica AUX201 come `AUX_IRQ_HINT`: la lettura espone la richiesta software corrente e una scrittura zero la cancella. Il testo descrive anche generazione, valori riservati e restrizioni; la gestione completa di quei casi non è implementata qui.

Il codice Nikon a B3106 legge AUX201, confronta con r1 e, solo se uguali, esegue `sr 0,[0x201]` a B310E. Nell'esperimento precedente il timer GNU entra con r1=3. Una sorgente timer non implica una richiesta software pendente. La sorgente software del nuovo modello parte esplicitamente vuota: nessuna iniezione host e nessuna richiesta guest nonzero accettata. Lo zero letto deriva da quel contesto di simulazione, **non da una misura o un reset hardware Nikon attribuito al registro**.

Il modello consente lettura dello stato vuoto e cancellazione con SR0. Qualunque scrittura nonzero ferma la CPU con `S33_IRQ_HINT_UNSUPPORTED ... delivery_not_implemented=1`: non simula una consegna mai implementata, non maschera il valore a cinque bit e non inventa il comportamento dei valori riservati. Anche SR0 è stato verificato solo sullo stato vuoto; cancellazione di una richiesta effettivamente pendente e consegna di IRQ software restano lavoro aperto.

## Motori e verifiche riproducibili

[Costruttore della sorgente software](../Python_Trace_Scripts/s33_build_gnu_irq_hint.py): copia separata di SRdelayv2, senza nuovi layout CPU. Modifica soltanto cpu7.h. Banca AUX controllata, correzione SR, sanitizer bounds e comportamento timer GNU precedente sono conservati.

- Motore senza DSP: `work/gnu_arc700_irq_hint_v1`, SHA-256 `0c877953f6aa8e963ec60f4e645f9a5800c4269a4fe1b5b50168c7eab75a7c84`; [build e patch](../outputs/gnu_arc700_irq_hint/build_v1/verified_evidence.json).
- Motore DSP composto: `work/gnu_arc700_dsp_lab_v7`, SHA-256 `af0f00ae23db6645aca4baeb73202fb9c3a8cf73e00919035c66f1809ac4c4de`; [build e parent](../outputs/gnu_arc700_dsp/build_v7/verified_evidence.json). Raw r56/r57 e semantica DSP restano le ipotesi limitate dei rapporti precedenti.

| Comando eseguito dalla radice | Evidenza | Copertura |
|---|---|---|
| `python3 Python_Trace_Scripts/s33_verify_gnu_irq_hint.py` | [22 casi PASS_EMPTY_SOURCE_MODEL](../outputs/gnu_arc700/20261020T115043Z_b221008d/verified_evidence.json) | Vecchia lettura fermata su unknown; 11 smoke/alias/CPU; baseline TBIB 10952 invariata; 4 lettura/cancellazione; 5 richieste nonzero fermate, comprese classi riservate |
| `python3 Python_Trace_Scripts/s33_verify_gnu_dsp_lab.py` | [47 casi su DSPv7](../outputs/gnu_arc700/20261020T115305Z_9d4d42d6/verified_evidence.json) | PASS_EXPERIMENT_ONLY: core, baseline, prodotti isolati, rifiuti e due ingressi TBIB; non prova fisica DSP |
| `python3 Python_Trace_Scripts/s33_run_gnu_main.py --dsp-lab --clock100-lab --irq-hint-empty-lab` | [MainCode verificato](../outputs/gnu_arc700/20261020T115305Z_b0bb8232/verified_evidence.json) | PASS_LIMITED_EMPTY_SOFTWARE_SOURCE: lettura2byte FED2018 a169A84, 583306 nel profiler |

Il runner [MainCode](../Python_Trace_Scripts/s33_run_gnu_main.py) mantiene separati i profili precedenti. Senza `--irq-hint-empty-lab`, `--dsp-lab --clock100-lab` usa ancora DSPv6 e il suo arresto AUX201; il default senza DSP resta SRdelayv2 e stop MMIO108. Il nuovo flag richiede gli altri due. Il verificatore DSP ora controlla DSPv7; i verificatori storici di altri rami restano associati alle varianti dichiarate nei rispettivi script.

Le verifiche di questo checkpoint non rieseguono i 54 casi SR, i 12 controlli TBIB o le prove aritmetiche helper precedenti: quelle restano evidenze storiche distinte. La composizione DSPv7 usa il parent SR già verificato, conservato nel manifest.

## Che cosa mostra realmente MainCode

La traccia contiene quattro letture a B3106, tutte con r0=0, e quattro ritorni a B32B8 (`j.f [ilink2]`) dal percorso di gestione del contesto. Il verificatore le conta e controlla che B310E non venga eseguita e non ci siano cancellazioni software nel log. Il fatto che il ritorno usi ilink2 è riportato come istruzione osservata; non viene usato da solo per classificare il livello hardware dell'IRQ.

Nessuna richiesta software nonzero è stata accettata. Il timer e i suoi eventi derivano dal GNU preesistente; temporizzazione, stato sticky IRQ, priorità, annidamento e consegna hardware non sono certificati. Questi quattro ritorni non provano uno scheduler operativo in ogni condizione o il contratto completo del task fotografico.

La routine successiva comincia a 169A74. La traccia carica FED2018 tramite il pool a 169A80, r15=0, poi si ferma alla prima lettura a169A84: il registro non è stato riempito con zero o incluso nella RAM. **Prossimo punto: verificare routine169A74, bit di controllo e registri letti dopo FED2018, prima di un modello dispositivo o temporale.** Non assegnargli una frequenza fisica sulla sola vicinanza ad altre funzioni.

## Limiti e conservazione

Restano: RAM GNU128MiB zero, ingresso Main candidato BB540, base vettori e contesto d'avvio di laboratorio; nessun resetROM→Main dimostrato. I quattro input clock F8/64/108/100 sono halfword sintetiche zero. BSS nel nuovo run non è verificata separatamente. Non sono mappati gli overlay11–15 insieme o i profili TBIB FE400xx/FED3800 in Main.

Ogni prova conserva comandi, log, tracce, snapshot e hash. Il runner riconferma il firmware V1.1 originale da29.602.084byte, SHA-256 `1d34e990a8f99019ffa53ca5de785399df863e942739a667ceb314ec6ce62a39`, i16payload e i segmenti ELF caricati. Firmware Nikon e GNU originale restano intatti. Nessun comando hardware, USB/PTP o scrittura della macchina è stato eseguito.

Il PDF DSP dietro login rimane non ottenibile e non è un prerequisito per questo lavoro. I manuali pubblici e le fonti già scaricati restano conservati con URL e hash come richiesto dall'utente. Il firmware completo e tutte le funzioni fotografiche richieste restano aperti.
