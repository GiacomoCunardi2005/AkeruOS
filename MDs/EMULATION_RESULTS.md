# Risultati effettivi Ghidra/P-code

19 ottobre 2026, R4. **Test riuscito della sola istruzione a 0x001353F6**, originale e patchata. Non è una prova di boot, apertura menu o Service Mode. Nessuna implementazione sostitutiva delle istruzioni, stub o GNU Simulator usato.

## Riproduzione

Dalla radice: `python3 S33-sections/safety_audit_codex/run_audit.py` (senza `-O`). Il runner riusa `analysis_codex/audit_patch.py`, verifica i 16 payload tramite gli helper esistenti, estrae copie temporanee del payload00 dai due input e le importa separatamente a base candidata `0xAD800`. Nessuna scrittura ai firmware. Comandi headless completi: [originale](../S33-sections/safety_audit_codex/evidence/original_command.json), [patchato](../S33-sections/safety_audit_codex/evidence/patched_command.json); i percorsi temporanei vengono ricreati dal runner.

Strumento: `tools/ghidra-arcompact/ghidra_12.2_DEV/support/analyzeHeadless`, linguaggio `ARCompact:LE:32:default`, `BinaryLoader`, `-noanalysis`, `-deleteProject`. GNU objdump usa `-m arc:ARC700 -EL`. Il tempo del test è rimasto entro il limite richiesto di circa 30 minuti.

## Correzione ed errori conservati

Lo script [ProbeARC700.java](../S33-sections/analysis_ghidra/scripts/ProbeARC700.java) conteneva newline reali dentro stringhe Java. Corretto direttamente, originale conservato in [copia precedente](../S33-sections/safety_audit_codex/evidence/ProbeARC700.before.java). Il vecchio [log](../S33-sections/analysis_ghidra/emulation_probe.log) conserva gli errori `unclosed string literal` e il mancato caricamento dello script.

Il primo runner ha respinto il testo GNU perché attendeva un immediato decimale, mentre GNU stampa `0x3`: [tentativo1](../S33-sections/safety_audit_codex/evidence/attempt1.log), [tentativo2 con disassemblato](../S33-sections/safety_audit_codex/evidence/attempt2.log). Il controllo è stato corretto per il formato esadecimale; non è stato alterato il decoder. Nessuno dei tentativi falliti è contato come test Ghidra riuscito.

Il runner richiede exit code zero **e** assenza di errori Java/script **e** file appena generato con marcatore finale. Lo script fallisce se byte, decode, lunghezza, step, PC, r0 o flag Z/N non coincidono con i controlli. I log finali contengono avvisi Java di deprecazione/riflessione, senza errori Java o script: [originale](../S33-sections/safety_audit_codex/evidence/original_headless.log), [patchato](../S33-sections/safety_audit_codex/evidence/patched_headless.log).

## Byte, esecuzione e flag

Offset file `0xCFEAE = 0x482B8 + (0x1353F6-0xAD800)`. Byte originali `83 E0`, patchati `81 E0`. GNU conferma entrambi: [originale](../S33-sections/safety_audit_codex/evidence/original_gnu.txt), [patchato](../S33-sections/safety_audit_codex/evidence/patched_gnu.txt). Il successivo `bne_s` a `0x1353F8`, destinazione `0x135410`, è identico e **non eseguito** in questo test.

Ogni caso usa un nuovo `EmulatorHelper`, r0 controllato e flag Z/N/C/V inizializzati a zero. Tutti i 14 step ritornano `true`, `error=null`, PC `0x1353F6→0x1353F8`, r0 invariato. Tracce complete con P-code: [originale](../S33-sections/safety_audit_codex/evidence/original_pcode.txt), [patchato](../S33-sections/safety_audit_codex/evidence/patched_pcode.txt).

| r0 | Originale Z N C V | Patchato Z N C V |
|---|---|---|
|0|0 1 1 0|0 1 1 0|
|1|0 1 1 0|1 0 0 0|
|2|0 1 1 0|0 0 0 0|
|3|1 0 0 0|0 0 0 0|
|0x7FFFFFFF|0 0 0 0|0 0 0 0|
|0x80000000|0 0 0 1|0 0 0 1|
|0xFFFFFFFF|0 1 0 0|0 1 0 0|

Il linguaggio installato rappresenta i flag come registri separati Z/N/C/V (offset register `0x120..123`); non espone qui un aggregato `status32` da leggere. Il P-code osservato contiene `INT_SUB`, `INT_EQUAL`, `INT_SLESS`, `INT_LESS`, `INT_SBORROW`; nessuna istruzione non supportata in questo perimetro. C/V sono registrati, non confrontati con misure della CPU fisica. La semantica deriva dal linguaggio SLEIGH installato (`ARCompact.slaspec`, `cmp_s` e `update_flags_sub_zncv`), non prova l'intera implementazione ARC700.

## Copertura e limiti

[Esito runner](../S33-sections/safety_audit_codex/evidence/run_audit.log), [hash e manifest](verified_evidence.json). Integrità e immutabilità input superate. Eseguito anche (e integrato nel runner finale) `python3 S33-sections/analysis_codex/audit_storage_followup.py`: [esito](../S33-sections/safety_audit_codex/evidence/storage_recheck.log), 23 finestre/40 istruzioni; non è emulazione di operazioni storage. Nessuna esecuzione di chiamate Nikon, updater, bootloader, interrupt o hardware. Prossimo punto R4: contratto di aggiornamento e recupero; estendere l'emulatore non è necessario per stabilire il NO-GO attuale.

## Estensione del runner: updater SD

Il runner comprende ora anche i tre verificatori statici collegati nel [rapporto updater/recupero](SD_UPDATE_RECOVERY_PATH.md): 48 finestre GNU e145istruzioni. Questi controlli **non** aggiungono emulazione del boot o dell'updater ai14step P-code già descritti. Il manifest include script ed evidenze delle nuove prove; il candidato di fallback TBIB resta statico.

## Seguito richiesto: getter e salti effettivi

Il [nuovo test di flusso](HIDDENMENU_FLOW_EMULATION.md) aggiunge36percorsi P-code reali (18perimmagine), con getter129920, letture controllate dello stato, call/ritorni, confronto, salti e delay slot. Arresto prima della sondaCDA24 o a135426, senza inventare esiti filesystem. Stato stabile1: originale nessuna sonda/patchHiddenMenu; stato3: originaleHiddenMenu/patchENABLE_NAND_TOOL. [Runner dedicato](../S33-sections/safety_audit_codex/run_hiddenmenu_flow.py), [manifest](hiddenmenu_flow_verified.json). Nessun filesystem/UI/boot emulato efirmware invariati; NO-GO flash invariato.

## Verifica successiva richiesta sulla variante CMP3

Il [nuovo controllo boot/ripristino CMP3](CMP3_BOOT_RESTORE.md) usa il campione con confronto3, verificato dai byte.25scenari P-code registrano21confini corretti e4limiti del modello; una prova isolata conferma un difetto `ld.ab` con alias nel decoder, riscontrato con GNU ARC700/QEMU. Nessuna conclusione di mancato boot va ricavata dal PC0 emulato. Nuove14finestre/71istruzioni dei backend BootCode restringono origine dei metadati e aggiornamento della mappa, ma non provano una copia recuperabile dopo interruzione. Il linguaggio non è stato modificato; firmware e hardware invariati. NO-GO flash confermato.
