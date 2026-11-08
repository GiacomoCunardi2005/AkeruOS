# S33 — controlli di completamento e close senza contesto file

Analisi statica V1.1, 18 ottobre 2026. Continuazione del [backend SD](S33_Dispositivo_SD_e_Completamento.md). Nessuna esecuzione hardware.

## Risultato

Risolti due controlli inferiori: nel wrapper PMSD:/PMNAND: **`0x2015` acquisisce la sincronizzazione e `0x2016` la rilascia**. I due rami non chiamano il trasferimento dei metadati. Non sono quindi, da soli, comandi di flush.

Il **comando filesystem `3`**, nel ramo ammesso dal dispatcher, chiama **`0x2A1270(contesto, 2)`** e propaga il risultato della sequenza di aggiornamento già ricostruita. Trovato anche un chiamante concreto nel close di un handle senza contesto file: quel chiamante **ignora il risultato del comando `3`** e prosegue con altre operazioni e rilascio delle risorse.

Il flag volume+`0x49` che può saltare il backend è zero nei due record iniziali ed è controllato dal risolutore del volume. Il suo produttore runtime rimane aperto. Circa 10% funzionale invariato; persistenza fisica ancora da provare.

## 1. Dispatcher del wrapper di partizione

Il controllo **`0x2A0A14`**, già attribuito alla famiglia PMSD:/PMNAND:, sottrae `0x2015` dal comando e usa una tabella di **12 byte signed a `0x2A0A46`**. Il target è base + 2*byte; `ldb.x` e `add1_s` sono verificati. Sono escluse dal disassemblaggio lineare le celle della tabella e il pool che interrompe i corpi dei rami.

| Comando | Cella byte | Valore signed | Destinazione |
|---|---|---|---|
| `0x2015` | `0x2A0A46` | 26 | `0x2A0A7A` |
| `0x2016` | `0x2A0A47` | 53 | `0x2A0AB0` |

Il ramo `0x2015` passa **contesto wrapper+4** a **`0x23ECA4`**; poi copia la prima parola dell'argomento di controllo a **contesto wrapper+`0x20`**. Il ramo `0x2016` prepara lo stesso indirizzo e raggiunge **`0x23EE48`** a `0x2A0AF2`. Entrambi confluiscono nel ritorno comune con stato locale inizializzato a zero. Il risultato della sincronizzazione non diventa lo stato del controllo in questi rami.

Il ritorno comune copia inoltre il campo errore dell'handle grezzo in quello dell'handle wrapper. Stato restituito e campo errore sono dunque canali distinti: la copia del campo errore non trasforma questi controlli in una verifica di trasferimento.

Il servizio **`0x2A0C60`** emette i controlli prima e dopo il trasferimento soltanto quando contesto filesystem+`0x350` è zero. In entrambi i siti **`0x2A0C88/0x2A0D2E`** il risultato del controllo non viene conservato come esito del trasferimento. La coppia protegge una sequenza di operazioni; non stabilisce la persistenza sulla scheda.

I comandi fuori dai casi locali possono essere inoltrati all'handle grezzo dal ramo `0x2A0B0C`; non si attribuisce a ogni controllo la semantica dei due qui risolti.

## 2. Comando filesystem 3: aggiornamento con risultato propagato

Nel dispatcher superiore **`0x1F56B4`**, superati i controlli preliminari, il confronto a **`0x1F579A`** tratta il comando **3** separatamente dalla tabella dei comandi `0x3002` e successivi. Destinazione **`0x1F59C0`**:

```text
contesto = file[0]->userdata (+0x24)
risultato = 0x2A1270(contesto, 2)
slot_ritorno_stack(+0x0C) = risultato
ritorno = slot_ritorno_stack(+0x0C)
```

Le istruzioni `0x1F59C2` (modo 2), `0x1F59C6` (chiamata), `0x1F59CA` (salto a `0x1F617E`) e il ritorno comune sono verificate. Questo percorso **conserva l'esito**, diversamente dai comandi `0x3015/0x3038` esaminati nel [rapporto callback](S33_Callback_Filesystem_e_Controlli_Close.md).

Il modo 2 tenta nell'ordine **`0x1F2484 → 0x2A10F4 → 0x2AB5E0`**, fermandosi al primo errore. Sono aggiornamenti del contesto e delle copie pendenti; il contratto fisico dello strato SD resta distinto. Non tutti gli stati ammettono il comando: il dispatcher contiene guardie precedenti al confronto.

Il servizio generico **`0x1F2348`** tratta specialmente soltanto i comandi 1 e 2. Il comando 3 arriva al callback control del dispositivo a +`0x1C`, se presente, e ne conserva il ritorno. Non è un codice intercettato prima dal servizio generico.

## 3. Un chiamante concreto nel close e il suo limite

Il callback close filesystem **`0x1F48A4`** distingue il campo **file+4**. Se nullo, chiama **`0x1F46C4`**. Non si tratta automaticamente del close ordinario di una fotografia, il cui contesto file può essere nonnullo.

Quest'ultimo risolve il contesto e usa il predicato backend **`0x1F35FC`**. Quando il predicato è zero entra a **`0x1F4710`** e chiama:

```text
0x1F2348(handle_originale, 3, 0)
```

L'handle resta quello originale del filesystem. Il wrapper PM non è il destinatario diretto di questo comando 3. Alla prima istruzione dopo il delay slot, **`0x1F471A`**, il registro di risultato viene sostituito dall'handle per chiamare di nuovo **`0x2A12D8`**. Nessuna conservazione o confronto del risultato del comando 3 nel tratto locale.

Il close prosegue con **`0x2A45E4`**, operazioni condizionali e rilascio di diversi buffer. Il tratto `0x1F4834..0x1F48A4` mostra che, raggiunta la sua uscita ordinaria di pulizia, imposta **r13=0 a `0x1F488E`** e restituisce quel valore a `0x1F489A`. Altri rami hanno un esito proprio: non si afferma che ogni close restituisca zero.

Conclusione limitata: **questo chiamante non propaga l'eventuale errore del comando di aggiornamento**. Non prova che il comando fallisca a runtime, che ogni errore perda dati o che lo spegnimento attraversi questa routine. La distruzione successiva dei buffer rende però rilevante verificare la gestione di quell'esito a monte.

## 4. Flag volume+0x49: stato iniziale e ammissione

I byte iniziali **`0x376061`** (record SD) e **`0x3761B1`** (record NAND) valgono entrambi **0** nel payload verificato. È un dato del campione iniziale, non una lettura della RAM dopo avvio.

Il risolutore **`0x1F19E0`** individua il record per prefisso e applica diverse guardie. Nel ramo che raggiunge **`0x1F1A4E`**, se byte record+`0x49 == 1` restituisce il valore del pool **`0x1F1DAC = 0x01A00010`**. Guardie precedenti possono saltare questo controllo. Il nome simbolico di quell'errore non è attribuito.

Quindi il flag non viene letto soltanto dal write grezzo: può anche incidere sull'ammissione tramite risoluzione del volume. Questo limita l'ipotesi che il ramo senza callback sia liberamente raggiungibile da qualsiasi operazione ordinaria; non la esclude per handle già esistenti o altri percorsi.

La ricerca iniziale di istruzioni con offset 73 ha restituito anche accessi a strutture diverse. Per esempio la scrittura a `0x25AE36` usa una struttura ricevuta in r2, raggiunta da un chiamante con base r14+`0x18`; la sola coincidenza dell'offset non la collega alla tabella volumi. Non è stata promossa a produttore del flag.

## Evidenze e continuazione

[Script](../Python_Trace_Scripts/s33_trace_storage_completion_controls.py), [JSON](../Ghidra_Results/ghidra_reports/storage_completion_controls/verified_evidence.json), [GNU](../Ghidra_Results/ghidra_reports/storage_completion_controls/gnu_verified.txt). Riproduzione: `python3 Python_Trace_Scripts/s33_trace_storage_completion_controls.py`.

Verificati **16 SHA-256**, roundtrip ELF del blocco 00, **16 finestre, 10 collegamenti diretti, 27 istruzioni chiave e 12 destinazioni della tabella**. La verifica copre le affermazioni statiche descritte, senza misurare la fotocamera.

Prossimo: attribuire i chiamanti del close senza contesto file; completare il percorso di `0x2A45E4`; seguire l'aggiornamento della tabella volumi per trovare il produttore del flag; ricostruire contratto ed esiti dei servizi SD `0x25B9C0/0x25BB5C`.

## Continuazione — r/FAT/PMSD/DEVSD/close integrati

[S33_Dumper_RAM_SD_Catena_PMSD_DEVSD_e_Contratto_Conteggi.md](S33_Dumper_RAM_SD_Catena_PMSD_DEVSD_e_Contratto_Conteggi.md):22casi contratto conteggi/flag e13matrici r/FAT/close ora attraversano PMSD, DEVSD e adattatore SD originale, con2015/16 e semafori. Count raw intero/0 ed errore copiato; flag49=1 può riportare successo senza aggiornare buffer. Separazione FAT/r superata; motori dati e runtime flag restano aperti. Nessun hardware, GNU o BIN modificato.
