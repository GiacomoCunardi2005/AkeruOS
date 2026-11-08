# Firmware V1.1 — confronto CMP1 e CMP3

**Recupero,continuazione20ottobre2026:** [il nuovo raccordo TBIB](recovery_reset_report.md) verifica scanner e confronto dello stesso formato persistente nel caricatore:29finestreGNU/155istruzioni/64casi astratti. Resta da provare ROM/reset→caricamentoTBIB e sopravvivenza/selezione delle copie fisiche durante una scrittura interrotta. La presenza del lettore nelTBIB non dimostra che quelTBIB sia ancora caricabile. **NO-GO invariato.**

**Continuazione differenziale, 19 ottobre 2026.** Il [nuovo rapporto](MENU_DIFFERENTIAL.md) esegue28scenari con esiti FS simulati esplicitamente: main e callback ingresso root raggiunte in entrambi i casi positivi, ma fallback diverso se HiddenMenu fallisce e il marcatore NAND è disponibile (CMP3→4A, CMP1 nessuna apertura). Verificato anche un tratto del loop con record già estratto. Due prove aggiuntive per variante con kernel sintetico pubblicano ResetCameraConfirmMenu come corrente e si fermano su muludw1563F4; nessuna conferma reset. Non sono provate UI visibile, inizializzazione/chiusura complete, equivalenza globale o sicurezza flash; NO-GO invariato.

**Continuazione per la valutazione flash:** [decoder corretto e prove estese](ALIAS_FIX_BOOT.md), [commit BootCode e fallback RAM](recovery_commit_report.md). Le prove corrette aggiungono ritorno del loader e azzeramento MainCode, con 44 confini/6 limiti su 50 scenari; i 42/8 qui sotto si riferiscono al decoder originale. Nessun GO: restano contesto CPU, updater residente V1.0 e selezione persistente/reset non verificati.

19 ottobre 2026, R0/R3/R4. **Confronto integrale dei file e dei due listati concluso: una sola istruzione diversa, più tre byte di checksum.** Le prove di comportamento coprono porzioni precise: non dimostrano avvio completo, apertura del menu o recupero della macchina. Nessun firmware modificato e nessun accesso hardware; avanzamento funzionale circa 10% e decisione NO-GO al flash invariati.

## Campioni e listati

Usiamo CMP1/CMP3 per indicare l'immediato realmente presente, senza dedurre la storia delle modifiche dai nomi dei file. Il byte di stato RAM iniziale a `0x366880`, pari a 1 nel payload, è distinto dall'immediato dell'istruzione.

| Variante | Input locale, 29.602.084 byte ciascuno | SHA-256 |
|---|---|---|
| CMP3 | `OriginalSoftware_NikonS33_V1.1/firmware.bin` | `1d34e990a8f99019ffa53ca5de785399df863e942739a667ceb314ec6ce62a39` |
| CMP1 | `S33-sections/firmware_HIDDENMENU_RHIR_KHIR_OFFLINE_NOT_FLASH.bin` | `932281f89b840a45dc1b050dac52d5250f040ea6576b94696b55f3b93e123f1c` |

Creati [Firmware1.1.asm, CMP3](../Risultati/Disassemblati/Firmware1.1.asm) e [Firmware1.1_CMP1.asm](../Risultati/Disassemblati/Firmware1.1_CMP1.asm), rispettivamente 399.542.290 e 399.542.316 byte di testo. Ciascuno contiene 6.125.576 righe primarie, ricontrollate contro tutti i byte del proprio input. [Formato, regioni e limiti del disassemblaggio](S33_Firmware1_1_Disassemblato_Integrale.md).

## Differenze complete

| Offset file | CMP3 | CMP1 | Significato verificato |
|---|---|---|---|
| `0x480D6` | `37` | `35` | Somma RHIR del payload 0 |
| `0x482AE` | `DD` | `DB` | Somma KHIR |
| `0x482B2` | `22` | `24` | Complemento KHIR |
| `0xCFEAE` | `83` | `81` | CPU `0x1353F6`: `cmp_s r0,3` / `cmp_s r0,1` |

Il confronto riga per riga trova **3 righe primarie diverse, di cui una istruzione**, e 6.125.573 righe primarie identiche. I tre byte di checksum occupano due direttive dati. Il [diff completo](../Risultati/Disassemblati/Firmware1.1_CMP3_vs_CMP1.diff) comprende anche le differenze dichiarative di nome e hash nei commenti dei listati.

Tutte le 22 regioni sono confrontate: cambiano soltanto l'area di header `DATA_00044C38` e un byte in `TBM_00`. Corpo TBIB, payload TBM 1–15, risorse e trailer sono identici. Le 16 somme RHIR, somma/complemento KHIR e checksum TBIB sono validi nei due campioni. [Manifest del confronto](../Ghidra_Results/ghidra_reports/firmware11_comparison/verified_evidence.json), [audit checksum rieseguito](../Ghidra_Results/ghidra_reports/firmware11_comparison/patch_audit.json), [log](../Ghidra_Results/ghidra_reports/firmware11_comparison/comparison.log).

## Cosa cambia nell'esecuzione controllata

Il [confronto di comportamento](COMPARE_BEHAVIOR.md) esegue 36 casi reali P-code del selettore, comprese variazioni fra le due letture dello stato, e 4 casi del servizio percorsi. Per uno stato stabile:

| Stato letto | CMP1 | CMP3 |
|---|---|---|
| 0 | Nessuna sonda | Nessuna sonda |
| 1 | Sonda `B:\HiddenMenu` | Nessuna sonda |
| 2 | Sonda `ENABLE_NAND_TOOL` | Sonda `ENABLE_NAND_TOOL` |
| 3 | Sonda `ENABLE_NAND_TOOL` | Sonda `B:\HiddenMenu` |
| 4 / 255 | Sonda `ENABLE_NAND_TOOL` | Sonda `ENABLE_NAND_TOOL` |

Quindi, **con stato stabile 1, usare il confronto 3 impedisce a questo tratto di richiedere la sonda HiddenMenu**. Non significa che la CPU smetta di avviarsi. Con stato 3 cambia anche quale percorso viene sondato. Le due letture possono osservare valori diversi: non generalizzare la tabella oltre il caso stabile.

Le quattro esecuzioni del servizio da `0xCDA24`, due marcatori per immagine, coincidono e arrivano dopo 51 istruzioni a `0x12B17C`, prima di leggere la quantità dei volumi runtime dalla tabella `0x442340`. Non è stato inventato un volume montato o un ritorno del filesystem. Attributi del percorso, gestore menu, hook, stato occupato e rendering restano oltre questa prova: **sonda richiesta non equivale a menu aperto**.

## Avvio e ripristino

Il [confronto boot](COMPARE_BOOT.md) esegue 25 scenari per immagine: 42 confini attesi e 8 arresti del modello su 50 scenari totali, più due prove isolate del difetto `ld.ab`. Le tracce registrate coincidono dopo la sola normalizzazione dichiarata nel rapporto. Nessuno di questi scenari raggiunge il confronto modificato.

TBIB e descrittore RHIR tipo 2 sono identici; sotto precondizioni esplicite il corpo del loader pubblica `0xBB540` e il dispatch vi trasferisce il controllo. I tentativi più lunghi incontrano il [difetto del decoder Ghidra con alias destinazione/offset](CMP3_EMULATOR_ALIAS.md). Un ritorno emulato a PC0 non dimostra un brick. Non sono state sostituite istruzioni per superarlo. L'uguaglianza riguarda registri ed esiti registrati, non ogni stato interno possibile.

Per il recupero restano valide le analisi statiche precedenti: [updater SD](SD_UPDATE_RECOVERY_PATH.md) e [writer BootCode](CMP3_STORAGE_RECOVERY.md). La UI V1.1 raggiunge writer distinti MainCode e BootCode; TBIB identico nei pacchetti non prova che l'updater eviti di riscriverlo. Restano ignoti il raccordo fra commit `0x1EE148` e scelta della copia al reset, i valori runtime di geometria/mapping, e la sopravvivenza delle dipendenze del fallback. Questi percorsi di scrittura e recupero non sono stati eseguiti dal nuovo confronto. Il codice residente della macchina V1.0 non è quello V1.1 qui analizzato.

## Riproduzione e prossimo punto

```bash
python3 Python_Trace_Scripts/s33_disassemble_firmware11.py --variant CMP3
python3 Python_Trace_Scripts/s33_disassemble_firmware11.py --variant CMP1
python3 Python_Trace_Scripts/s33_compare_firmware11.py
python3 S33-sections/safety_audit_codex/run_compare_boot.py
python3 S33-sections/safety_audit_codex/compare_behavior.py
```

I primi due comandi ricreano i listati grandi; non sono necessari per consultare le evidenze salvate. Usare Python senza `-O`. Le generazioni hanno controllato 17 roundtrip ELF ciascuna, contiguità delle righe e ricostruzione dell'hash dell'intero input. Il comparatore ricontrolla nuovamente ogni riga e ogni hash dei listati. Gli script riusano parser e verificatori del progetto e terminano con assert se cambia un risultato atteso.

Validazione al termine del confronto integrale, prima delle successive estensioni del probe, nel [log storico](../Ghidra_Results/ghidra_reports/firmware11_comparison/final_validation.log): hash allora correnti di 33 file fra evidenze e sorgenti dei tre manifest P-code, entrambi gli input e i listati interi, generatore, comparatore e diff; collegamenti dei rapporti correnti e alias dell'indice validi. Compilazione sintattica Python dei quattro script principali riuscita. Il runner comportamento è stato rieseguito dopo uniformare i percorsi del manifest e aggiungere l'assert di uguaglianza integrale delle tracce del servizio: tutti i 40 casi confermati.

Il confronto integrale risponde a **quali byte cambiano**; le esecuzioni controllate chiariscono alcuni effetti. Codice identico può ricevere stati diversi dopo il ramo modificato: non è una prova globale di equivalenza o sicurezza. La correzione locale della semantica dell’alias è ora verificata nella continuazione; prima di proseguire oltre i nuovi arresti serve il contratto del contesto CPU e di `status32`; per il recupero serve seguire la selezione delle copie al reset. Nessun esito disponibile rende installabile o recuperabile con certezza una delle due varianti.
