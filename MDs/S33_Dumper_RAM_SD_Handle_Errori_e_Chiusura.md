# Dumper RAM: handle SD, errori e confini della chiusura

23 ottobre 2026. Continuazione offline del [binding SD](S33_Dumper_RAM_Binding_SD_ABI.md), successiva ai rapporti su [task e attesa](S33_Dumper_RAM_Task_Attesa_e_Clock_Binding.md) e [launcher residente](S33_Dumper_RAM_Launcher_Residente_Coda_Main.md). **25 casi sulle istruzioni originali V1.1** chiariscono quando un handle viene pubblicato, conservato o consumato. Nessuna fotocamera, SD o NAND è stata aperta dal verificatore.

Il risultato modifica il contratto del futuro adattatore: **un errore di open può lasciare un file aperto; un errore di close può lasciare il file ancora posseduto oppure consumarlo**. Il solo codice di ritorno non basta. L'interfaccia astratta di `ram_dump.h` richiede che il proprio adattatore consumi il file alla chiusura: non è una proprietà universale del wrapper Nikon.

## Prove riproducibili

- [Runner](../Python_Trace_Scripts/s33_verify_ram_dump_sd_lifecycle.py), [probe P-code](../S33-sections/analysis_ghidra/scripts/ProbeDumpSDLifecycle.java).
- [Manifest](../Risultati/Runtime_Kernel/RAM_Dumper_SD_Lifecycle/20261022T230847Z/verified_evidence.json), [25 esiti](../Risultati/Runtime_Kernel/RAM_Dumper_SD_Lifecycle/20261022T230847Z/trace.txt), [finestre GNU](../Risultati/Runtime_Kernel/RAM_Dumper_SD_Lifecycle/20261022T230847Z/gnu_verified.txt), [log](../Risultati/Runtime_Kernel/RAM_Dumper_SD_Lifecycle/20261022T230847Z/headless.log).

```bash
python3 Python_Trace_Scripts/s33_verify_ram_dump_sd_lifecycle.py
```

Ogni esecuzione crea una cartella distinta. I 16 payload sono verificati dal helper esistente; il runner conserva hash e snapshot dei propri sorgenti. Il probe usa `ARCompact:LE:32:loopfix`, esegue i corpi `0x12DBFC`, `0x12D604`, tre casi separati di `0x1F22C0` e il millicode originale. Altri sei casi eseguono il frammento di selezione backend descritto sotto, con input espliciti e registrar sostituito. Stack preservato in tutti i casi. GNU viene soltanto letto/eseguito; nessun builder GNU.

**Confini espliciti:** resolver del volume, lock/unlock, controllo volume, open/close inferiore, ioctl ed error getter sono fixture nei 16 casi superiori. Nei tre casi inferiori esegue invece il vero `0x1F22C0`, sostituendo callback dispositivo, mutex e free. Non si concatenano artificialmente questi due gruppi come se fosse stata eseguita l'intera FAT.

## Open: pubblicazione prima dell'ultimo errore

`0x12DBFC(path,mode,&file)` risolve il volume, prende il suo lock e cerca una cella nulla fra **60 slot**, a `0x376018 + volume*0x150 + 0x60 + slot*4`. Il test usa volume0 con tre slot occupati, pertanto il primo slot libero è3. Il caso di tabella piena esegue la scansione completa e non chiama l'open inferiore.

La selezione mode3 raggiunge la stringa `n`, già verificata nel rapporto precedente. Qui l'open generico è un confine simulato: questa prova **non estende** la garanzia new-only agli altri backend.

| Ramo provato | Stato | Cella di uscita | Slot3 |
|---|---|---|---|
|open riuscito|0|nuovo handle|nuovo handle|
|open riuscito, unlock fallito|errore unlock|**nuovo handle**|**nuovo handle**|
|open inferiore nullo, collisione|`0x01A00011`|0|0|
|collisione più unlock fallito|`0x01A00011`|0|0|
|60 slot pieni|`0x01A00032`|0|occupato, invariato|
|resolver o lock fallito|errore relativo|**valore precedente invariato**|invariato|

A `0x12DCBE` viene scritto lo slot, a `0x12DCC0` viene pubblicato `*file`, poi `0x12DCD0` richiede l'unlock. Il suo eventuale errore viene restituito **senza chiusura o rimozione dello slot**. Sul ramo di open nullo, invece, l'errore ottenuto da `0x1F19B0` viene preservato e l'esito unlock ignorato.

Conseguenza: inizializzare localmente l'uscita a0 evita di scambiare un valore vecchio per un nuovo handle. Dopo la chiamata, stato nonzero con handle nonzero va trattato come un'acquisizione seguita da errore, con cleanup ancora necessario. Non è lecito assumere che ogni errore significhi «nessun file creato».

## Close: distinguere prima e dopo la chiamata inferiore

`0x12D604(&file)` risolve il volume dal nome del dispositivo: il primo campo del file è il puntatore dispositivo; **`[device+8]`** è il nome passato al resolver. Non è `[file+8]`.

Dopo il lock cerca l'handle fra gli stessi60slot. Se lo trova:

1. `0x12D682 → 0x1F2348(file,0x3038,0)`: il ritorno è ignorato.
2. `0x12D69A → 0x1F2348(volume_handle,0x3015,0)`: il ritorno è controllato. `volume_handle` viene dalla tabella volume+0x58; non è il puntatore al contesto filesystem.
3. Soltanto dopo esito0 del secondo ioctl chiama `0x1F22C0(file)` a `0x12D6BC`.
4. A `0x12D6D4/6D6` azzera slot e `*file`, anche se il close inferiore aveva restituito errore.
5. L'errore dell'unlock finale, se nonzero, prevale sul risultato inferiore.

| Ramo provato | Close inferiore | Cella/slot | Esito |
|---|---:|---|---|
|successo|1 chiamata|azzerati|0|
|errore primo ioctl3038|1 chiamata|azzerati|0 nel caso provato|
|errore secondo ioctl3015|**0 chiamate**|**conservati**|errore ioctl|
|errore close inferiore|1 chiamata|**azzerati**|errore close|
|errore close e unlock|1 chiamata|azzerati|errore unlock|
|handle non registrato|0 chiamate|conservati|`0x01A00002`|
|resolver o lock fallito|0 chiamate|conservati|errore relativo|
|handle nullo|0 chiamate|nullo|`0x01A00013`|

I selettori3038/3015 sono verificati numericamente. La prova non attribuisce al loro successo una persistenza fisica: il backend ioctl è simulato e un ritorno0 non misura la SD.

## Close generico: rilascio dell'oggetto anche con errore

Nei tre casi separati viene eseguito `0x1F22C0`:

- legge la callback **`[device+0x10]`**;
- se presente, prende il mutex **`[0x369348]+0x334`**, invoca la callback con il file inr0 e rilascia il mutex;
- chiede sempre `0x25980C(file)` dopo la callback e restituisce il risultato che essa aveva prodotto, compreso un errore;
- se la callback manca, chiede comunque il free e restituisce `0xFFFFFFFF`.

Il free è una fixture che registra la richiesta, non una prova di liberazione dell'heap Nikon. Il risultato conferma comunque perché, una volta superato quel confine, il wrapper superiore non può offrire un handle da riutilizzare semplicemente perché il close ha restituito errore.

## Il backend7 ha un produttore nel montaggio

Il ramo originale `0x1F3F90..3FAA` passa flag1 a `0x1F35D4` se **byte sp+0x10==7 e word unsigned sp+0x18>=0x04000000**; passa flag0 negli altri casi. `0x1F35D4(context,1)` pubblica il contesto in `0x3693B4`, richiede la registrazione `0x2A4528(0x1F6250,0x1F6270)` e scrive **7 a context+0x70**. Con flag0 il corpo non azzera quel campo: conserva il valore precedente. Questo negativo locale non dimostra che l'intero montaggio lasci un valore vecchio, perché gli altri inizializzatori rimangono fuori prova.

Sei casi CPU partono dopo la query e provano tipo0/tipo255, tipo7 immediatamente sotto/alla/sopra soglia e `0xFFFFFFFF`. Il valore iniziale del campo è0x15; nei tre casi selezionati diventa7, negli altri rimane0x15. Non viene simulato l'intero montaggio né misurato il backend attuale di una SD.

È stato inoltre verificato staticamente il produttore del record esaminato:

- `0x1F3F82` richiede ioctl **0xA0A1** con record d'uscita a sp+0xC. I due input sono quindi **record+4** e **record+12**.
- Il dispatcher `0x2A05F4` inoltra quel selettore alla callback della tabella volume+0x3C. Per il record SD originale0, la word **0x376054 contiene0x168990**.
- `0x168990→0x168970→0x1688AC`: nel ramo che verifica la word globale a `0x1688E8` uguale6, il produttore scrive byte7 a record+4 e la differenza r17 a record+12. Scrive inoltre512 a record+0x10. Il ramo alternativo chiama `0x16859C`, non viene confuso con la sintesi del record provata qui.

Non attribuiamo un nome di filesystem, un significato elettrico o una capacità della scheda ai soli valori7/0x04000000. Il dato utile è il collegamento software: **backend7 può essere scelto dal montaggio del volume SD**, non è escluso dall'uso del prefisso B:. Per quel backend il parser `n` condivide già il ramo di `w`, come documentato nella verifica precedente. Rimane quindi necessaria una scelta del backend verificata sotto la sincronizzazione corretta, prima di associare mode3 a `open_new`.

## Conseguenze per il binding e prossimo passo

Il prototipo C non è stato modificato per fingere già risolta l'integrazione. Un adattatore non può essere una semplice conversione degli indirizzi Nikon in callback `open_new`/`close`:

- deve distinguere un open fallito senza handle da un open che ha già pubblicato un handle;
- deve distinguere close fallito prima del consumo da close fallito dopo il consumo;
- deve mantenere separati errore originario e fallimento del cleanup;
- non può dichiarare «chiusura consuma sempre» se si limita a inoltrare una volta `0x12D604`.

Rimane prioritario il vincolo del [binding SD precedente](S33_Dumper_RAM_Binding_SD_ABI.md): provare la stabilità della selezione backend e del campo contesto+190*4 durante il percorso `n`. L'alternativa `x` ha nomi propri e un backend separato; non usarla come sostituto implicito della creazione esatta.

Il prossimo passo offline è seguire i produttori dei campi che selezionano i backend e raccordare il preflight alla stessa sincronizzazione dell'apertura. In parallelo restano mappa fisica RAM completa, lifetime launcher/payload9 e massimo stack. **NON_INSTALLARE**, nessun dump RAM reale o avanzamento funzionale AkeruOS dedotto dai test.

## Continuazione — semaforo e inizializzazione, 23 ottobre 2026

[22 casi successivi](S33_Dumper_RAM_SD_Semaforo_Campo_Temporaneo_e_Inizializzazione.md) provano azzeramento iniziale852 byte, campo760/backend+0x70 a0 e semaforo+388 iniziale1. Il campo temporaneo di d è ripristinato prima del post; n non normalizza un valore1 già presente. La primitiva è un semaforo a conteggio: seconda wait nello stesso task si accoda. Non pre-acquisirlo per chiamare un open che lo acquisisce nuovamente. Restano scrittori successivi/backend e mount/unmount; nessuna integrazione hardware, NON_INSTALLARE.

## Continuazione — montaggio e chiusura, 23 ottobre 2026

[16 nuovi casi](S33_Dumper_RAM_SD_Mount_Chiusura_e_Stabilita_Backend.md) eseguono mount1F3EF0 e callback close1F48A4/ramo volume1F46C4. La scelta backend è sotto semaforo ma+424 è pubblicato prima; una query fallita salta il post nel modello. Close backend7 azzera+424 dopo il post, backend1 riacquisisce e controlla la halfword+108. Restano lifetime e livello superiore di sincronizzazione; non è prova di race/deadlock hardware. Prossimo: scrittori+108 e chiamanti close. NON_INSTALLARE.
