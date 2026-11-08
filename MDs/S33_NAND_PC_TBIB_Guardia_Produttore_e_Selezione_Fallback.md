# NAND dal PC: guardia TBIB, produttore e selezione del fallback

21 ottobre2026 — R0/R3/R4. Continuazione del [dispatch dell’aggiornamento](S33_NAND_PC_Dispatch_Pacchetto_Boot_Invariato_e_Contatore.md) e del [fallback statico storico](boot_recovery.md). **Eseguita la scelta delle sorgenti con i corpiTBIB originali**, separando guardia hardware, produttore del flag anticipato e servizi di lettura simulati. Il percorsoB è ora delimitato meglio, ma non costituisce ancora un avvio daSD o un recupero fisico dimostrato.

## Evidenze

- [Verificatore](../Python_Trace_Scripts/s33_verify_nand_pc_tbib_fallback.py).
- [Manifest](../Risultati/USB_SCSI/Accesso_NAND_PC/tbib_fallback_20261021T100905Z/verified_evidence.json), [28 casi produttore/flag](../Risultati/USB_SCSI/Accesso_NAND_PC/tbib_fallback_20261021T100905Z/producer_cases.json), [256 casi di selezione](../Risultati/USB_SCSI/Accesso_NAND_PC/tbib_fallback_20261021T100905Z/routing_cases.json).
- [Sostituzioni del produttore](../Risultati/USB_SCSI/Accesso_NAND_PC/tbib_fallback_20261021T100905Z/producer_patches.json), [sostituzioni dei serviziBootTask](../Risultati/USB_SCSI/Accesso_NAND_PC/tbib_fallback_20261021T100905Z/routing_patches.json).

```bash
python3 Python_Trace_Scripts/s33_verify_nand_pc_tbib_fallback.py
```

Quattro esecuzioniGNU senza fault:65.536valori della guardia,5bypass senzaMMIO mappato,28input del produttore e256combinazioni di routing. Qui basta il motoreGNU di base già fissato, senza usare o modificare la varianteDSP. Tutti gli inputMMIO sono espliciti valori di laboratorio, non letture della fotocamera.

## GuardiaB completa fino al registro

La catena originale è:

```text
01000488 → 01007168 → 0101FCC4 → 010033AC
                                         ↓
                            halfword[0FED2068], bit4
```

La guardia01000488 restituisce1 se il byte **01041104 è nonzero**. Altrimenti07168 confronta il suo argomento0 con byte01041274: se questo byte è diverso da0, ritorna0; se è0, il backend legge il bit4 della halfword0FED2068 e lo inverte.

Per la chiamata usata dalBootTask:

```text
guardia = 1                                se byte01041104 != 0
guardia = 0                                se byte01041104 == 0 e byte01041274 != 0
guardia = 1 − ((halfword[0FED2068] >> 4)&1)  altrimenti
```

Tutti i65.536valori della halfword sono passati attraverso le istruzioni originali. I cinque casi di bypass non mappano affatto0FED2068: ogni lettura accidentale avrebbe prodotto un fault. Flag1/2/255 producono1; flag0 con selettore1/255 produce0.

**Distinzione:** ilBootTask anticipaB solo quando01041104 è **esattamente1**, mentre la guardia accetta qualsiasi valore nonzero. Il frammento di inizializzazione provato sotto produce valori0/1. Non ricavare dalla sola formula una nuova procedura fisica con valori diversi.

Il significato fisico del bit4 non è stabilito. La stessa lettura compare nel predicatoMain169884→138D58→137774 già documentato per CaptureImage; la coincidenza non dimostra tasto, presenzaSD o polarità di un contatto reale.

## Origine del flag di tentativo anticipato

Il getter01005A2C restituisce la word a **01095A3C+30 =01095A6C**. Ora è collegato al produttore originale01018390:

1. Chiama01025A40 con argomento1, servizio sostituito nel test.
2.01025A9C legge le halfword dei registri **0FE70224** e **0FE70228**, combinandole come`(reg224<<10)|reg228`.
3.01018390 salva il risultato aoggetto+30; salva anche la coppia alta/bassa nei campi halfword+28/+2A.
4. Il frammento originale010002A4..2C8 legge il getter, salva il complemento a0104112C e controlla il suo bit15. Quando è1, scrive01041104=1 e01041105=0. Altrimenti lascia i flag iniziali0/1 usati dalla fixture.

Con i due input halfword a,b del test, il tentativo anticipato viene quindi abilitato quando il bit15 di`(a<<10)|b` è0: equivalentemente, a.bit5 e b.bit15 sono entrambi0. Questa è una relazione fra i valori restituiti dai registri, **non una mappa dei tasti**.

I28casi includono entrambi i contributi al bit15, rumore negli altri bit e valoriFFFF. Getter, complemento, flag eSP coincidono con l’atteso; gli altri byte dell’oggetto inizialmenteA5 restano intatti. Il servizio01025A40 è solo un registratore, la chiamata0100135C che preparaBootTask è simulata e il frammento termina esplicitamente a010002C8. È fornito r17=0, valore già ricostruito nel prefissoTBIB.

Non sono dimostrati protocollo o significato fisico dei registri0FE70224/228, completamento reale della periferica, ordine globale del produttore rispetto alla query, né scheduling diBootTask rispetto agli store dei flag. Non suggerire una combinazione di pulsanti sulla base di questa sola prova.

## Scelta originale delle sorgenti

Le256combinazioni variano flag anticipato, flag fallback, selettore01041274, bit4, errore dell’attesa iniziale ed esiti dei tre lettori. I servizi di attesa, segnalazione di stato, evento e scheduler sono registratori. **010010C0 e0100125C sono sostituiti da servizi che registrano sorgenti ed esiti: non caricano dati in questa matrice.** La guardia resta originale fino alla letturaMMIO esplicita.

| Condizione | Comportamento verificato |
|---|---|
|attesa iniziale fallita|nessuna sorgente provata; status dell’attesa salvato|
|flag anticipato1 eB riuscita|soloB:, poi stato finale0|
|tentativo anticipato non scelto o fallito|lettore a settori|
|settori riusciti|nessun fallbackA/B|
|settori falliti|fileA:\\TBM_SK501.BIN|
|ancheA fallita|B:\\TBM_SK501.BIN soltanto se flag fallback1 e guardia nonzero|
|tutte le sorgenti tentate fallite|salvato l’ultimo esito, senza inventare un caricamento riuscito|

Le stringhe passate ai servizi coincidono integralmente con i pathTBIB. Con flag anticipato1, fallback1 ed errori suB/settori/A, B può essere richiesto sia prima sia dopo: la fixture verifica anche questa combinazione, senza attribuirla alla configurazione normale dell’init.

La word **01041108** conserva lo status finale. Il ritornoordinario delBootTask nel test è invece0 dal servizio scheduler simulato: non va scambiato per lo status del caricamento.

## Il byteINFO20 non prova un file caricato

Con puntatoreINFO esplicito900, BootTask scrive il selettore a928:

- `0x10` dopo successo del lettore a settori;
- `0x20` dopo successoB anticipato, ma anche **prima** di provareA quando fallisce il lettore a settori;
- Se falliscono anche i file,20 rimane pur con status01041108 nonzero.

Quindi il byte20, da solo, non dimostra caricamento da file completato. La matrice controlla separatamente sorgenti richieste, status e byteINFO, oltre aSP e notifiche finali. La relazione col lettoreMain che consulta928 rimane condizionata al vero trasferimento e alla gestione dell’errore.

## Cosa manca per usare questo percorso

È ora provata la logica locale che seleziona un fileB, anche prima della NAND quando il flag è1. **Non è ancora disponibile una procedura di avvioSD verificata.** Restano da collegare:

1. Il fileRHIR letto da0100125C ai trasferimenti effettivi del candidato, includendo il nuovo record17.
2. I namespaceA:/B: ai supporti fisici e ai driver pronti, senza assumere l’identità dalla lettera.
3. L’origine runtime dei valori hardware che selezionano il tentativo anticipato, senza inventare pulsanti o marker.
4. Il successo del caricamento al trasferimento e alla disponibilitàUSB/lettoreNAND; boot da file non equivale automaticamente a recupero persistente.

Il candidato e il clientPC sono invariati. Non sono stati creati file sullaSD, inviati comandi alla fotocamera o riscritta la flash. Nessun reset/ROM, caricamento fisico, avvioAkeruOS o foto dimostrati. **NO-GO**, obiettivo attivo e circa10% funzionale invariato.

## Continuazione: lettore file eseguito

La [prova successiva](S33_NAND_PC_Lettore_File_TBIB_Record17_e_Limite_Status.md) esegue22casi sul candidato e sul record17. Confermata associazione staticaB→DEVSD nella tabellaTBIB, disponibilitàfisica aperta. Il ritorno0 può seguire letture assenti con RAM giàvalida: non certifica lettura o recupero.
