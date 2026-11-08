# NAND dal PC: guardia dello status di boot e invocazione dell'ingresso

21 ottobre 2026 — R0/R3/R4. **16 casi CPU** verificano il controllo finale dello status nel frammento di inizializzazioneTBIB; un caso separato verifica il wrapper di chiamata indiretta all'ingresso. Un errore del loader impedisce il ramo locale di prosecuzione anche conBB540 già pubblicato. Questo non dimostra l'intero passaggio alMain, lo spegnimento reale in caso di errore o un recupero fisico. **NON_INSTALLARE resta.**

## Prove e riproduzione

- [Verificatore](../Python_Trace_Scripts/s33_verify_nand_pc_boot_status_gate.py), [manifest](../Risultati/USB_SCSI/Accesso_NAND_PC/boot_status_gate_20261021T141404Z/verified_evidence.json).
- [16 combinazioni](../Risultati/USB_SCSI/Accesso_NAND_PC/boot_status_gate_20261021T141404Z/gate_cases.json), [confini di laboratorio](../Risultati/USB_SCSI/Accesso_NAND_PC/boot_status_gate_20261021T141404Z/laboratory_patches.json).
- [Frammento originale](../Risultati/USB_SCSI/Accesso_NAND_PC/boot_status_gate_20261021T141404Z/gnu_1000390.log), [wrapper originale](../Risultati/USB_SCSI/Accesso_NAND_PC/boot_status_gate_20261021T141404Z/gnu_10000c4.log).
- [Lettore file e status](S33_NAND_PC_Lettore_File_TBIB_Record17_e_Limite_Status.md), [routing delBootTask](S33_NAND_PC_TBIB_Guardia_Produttore_e_Selezione_Fallback.md), [ultimo controllo RAM](S33_NAND_PC_API_Regioni_e_Configurazione_Successiva.md).

```bash
python3 Python_Trace_Scripts/s33_verify_nand_pc_boot_status_gate.py
```

Firmware originale e GNU fissati per hash, nessuna modifica ai sorgenti GNU. Ingresso del test01000390, r17=0, r18 fornito esplicitamente. Attesaevento e preparatoreINFO01000610 sono fixture; il test si ferma agli inizi dei due rami successivi. Non viene simulato lo scheduler né eseguita tutta l'inizializzazione.

## Il risultato del BootTask viene consumato

Il BootTask aveva scritto lo status finale a **01041108**. Il frammento verificato chiama l'attesa010069E0, poi legge proprio quella word tramite base01041100+8:

| Passaggio | Istruzioni | Effetto locale |
|---|---|---|
|attesa|01000390..3A8|un errore diventa r18 soltanto se r18 era0|
|status del loader|010003AA..3B8|un errore di01041108 diventa r18 soltanto se r18 è ancora0|
|preparatoreINFO|010003BA..3CA|errore di01000610 assunto soltanto se non c'era già un errore|
|decisione|010003CC..3D0|r18 nonzero salta a0100042A; altrimenti prosegue a010003D2|

Il criterio è dunque il **primo errore nonzero**, nell'ordine stato precedente, attesa, loader, preparatoreINFO. I16casi combinano0/303,0/101,0/13,0/5 nei quattro ingressi. Attesa e preparatore vengono chiamati una volta ciascuno anche quando un errore precedente è già presente; il primo errore rimane conservato.

In tutti i casi la word d'ingresso01041100 contiene già **BB540**, compresi quelli con loader=13. Questo riproduce la condizione rilevante del [record16 elaborato prima di un errore sul17](S33_NAND_PC_Lettore_File_TBIB_Record17_e_Limite_Status.md). La presenza del puntatore non supera il controllo dello status. Stack preservato in tutti i casi.

Il risultato non rende sufficiente lo status0: il lettore file può restituirlo con RAM già valida anche dopo una lettura assente/corta, come nelle prove precedenti. La guardia controlla lo status che riceve, non misura autonomamente l'I/O.

## Rami successivi: limite della conclusione

Il ramo010003D2 contiene preparazioniINFO, richieste a servizi e infine01006D20. Quello a0100042A contiene richieste di uscita/segnalazione e chiama01000718 con lo status. Il corpo di01000718 contiene attese e richieste di segnalazione, seguite da01000478; quest'ultimo richiama servizi che dipendono dall'hardware. Non sono eseguiti nel test del frammento.

Quindi è provato **«errore evita il ramo locale di prosecuzione»**, non «nessun ingressoMain può più essere invocato in qualunque condizione». L'effetto dello spegnimento, un suo eventuale fallimento e il seguito del runtime non sono stabiliti da questa prova. Non ne deriva una procedura sicura di retry, spegnimento o tasti.

## Wrapper di ingresso, prova indipendente

Il percorso originale **01000C10→010000C4** legge la word01041100 e chiama indirettamente il puntatore contenuto. Nel caso separato quel puntatore è una callback di laboratorio che registra l'argomento e ritorna55AA. Il wrapper conserva lo stack e restituisce55AA; alla callback arriva **r0=01041100**. Non si assume che l'argomento sia0 soltanto perché il wrapper inizia con `mov r0,0`.

La callback sostituisce il Main, che non viene eseguito. Non si usa questo caso per collegare artificialmente il ramo di successo del frammento alla chiamata indiretta: scheduler, teardown kernel e ordine globale rimangono separati.

## Stato hardware e decisione

Nel [nuovo controlloUSB](../Risultati/Hardware/MSDC_Default/20261021T140858Z/observation.json) nessuna Nikon è comparsa in10campioni; nessun errore di raccolta. Questo descrive soltanto la connessione osservata, non la causa dell'assenza o un guasto. La confermaMSDC22MiB del controllo091255Z resta storica. Sono stati letti metadati/cached descriptors/sysfs, senza comandi vendor, lettura grezza o scritture sulla macchina.

È stata chiesta all'utente la condizione fisica attuale della fotocamera per poter riprendere verifiche di sola lettura. Non si presume una risposta o un'autorizzazione a flash/SD dal trascorrere del tempo.

CandidatoSHA256 `0bb25fd6603488e30d41ac6ad96f4fe4e8fe5e838deda7cfc7e9c6ab7cb324e9` invariato; vecchio52f8714d escluso. Per un BIN pronto restano durata complessiva/scrittori, integrità USB/NAND e recupero fisico. Nessun avvio/fotoAkeruOS; circa10% funzionale invariato. Obiettivo aperto.
