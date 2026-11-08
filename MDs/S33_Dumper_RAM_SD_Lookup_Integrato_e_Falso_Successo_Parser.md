# Dumper RAM: lookup integrato e falso successo dopo errore parser

23 ottobre 2026, R0/R1/R4. **20 casi collegano coordinatore, parser, walker directory e scanner originali a un unico albero di settori sintetici;7 ulteriori sequenze partono dalla callback open r e arrivano al close del file e del volume.** I livelli precedentemente provati separatamente sono ora eseguiti insieme. Lettura settori, heap/pool inferiore e cache restano confini simulati.

**Risultato prioritario:** nel profilo scratch0, se fallisce l'allocazione257 interna al parser, il lookup integrato può restituire **un record vuoto con stato0**. La callbackr lo accetta e registra un oggetto file. Non è stato trovato il record richiesto. Il comportamento resta anche quando la fixture dell'allocatore nullo fornisce un errore nonzero, conservato dal codice originale nel task. Nessuna creazione di file viene chiamata e nessun settore del modello viene modificato.

Questo corregge l'aspettativa ricavata dalle prove a confini separati: il precedente01A00002 per nome vuoto dipendeva dal finder simulato che non trovava una corrispondenza. Non va assunto come esito dell'intera catena originale. Il risultato nuovo è condizionato al modello esplicito, non un'osservazione hardware.

## Prove riproducibili

| Gruppo | Sorgenti | Risultati |
|---|---|---|
|20lookup integrati|[runner](../Python_Trace_Scripts/s33_verify_ram_dump_sd_lookup_tree.py), [probe](../S33-sections/analysis_ghidra/scripts/ProbeDumpSDLookupTree.java)|[manifest](../Risultati/Runtime_Kernel/RAM_Dumper_SD_Lookup_Tree/20261023T081346Z/verified_evidence.json), [traccia](../Risultati/Runtime_Kernel/RAM_Dumper_SD_Lookup_Tree/20261023T081346Z/trace.txt), [13 finestre GNU](../Risultati/Runtime_Kernel/RAM_Dumper_SD_Lookup_Tree/20261023T081346Z/gnu_verified.txt)|
|7r/open e close|[runner](../Python_Trace_Scripts/s33_verify_ram_dump_sd_read_tree.py), [probe](../S33-sections/analysis_ghidra/scripts/ProbeDumpSDReadTree.java)|[manifest](../Risultati/Runtime_Kernel/RAM_Dumper_SD_Read_Tree/20261023T081333Z/verified_evidence.json), [traccia](../Risultati/Runtime_Kernel/RAM_Dumper_SD_Read_Tree/20261023T081333Z/trace.txt), [18 finestre GNU](../Risultati/Runtime_Kernel/RAM_Dumper_SD_Read_Tree/20261023T081333Z/gnu_verified.txt)|

```bash
python3 Python_Trace_Scripts/s33_verify_ram_dump_sd_lookup_tree.py
python3 Python_Trace_Scripts/s33_verify_ram_dump_sd_read_tree.py
```

Il secondo probe riusa lo stesso harness con ingresso dalla callbackr: la matrice20è stata rieseguita dopo l'aggiunta del profilo. Snapshot, hash e payload canonici identificano esattamente i byte eseguiti. GNU è solo letto/eseguito; firmware e dump originali immutati.

## Catena originale eseguita

Nel gruppo20 l'ingresso è2A3360. Nel gruppo7 è1F43AC, parserr→21A0D0. Da lì tutti i livelli seguenti eseguono le istruzioni originali:

`1F43AC → 21A0D0 → 2A3360 → 29FFB0/29FF74 → 2A318C → 2A2D88 → 2A1178 (settore fixture)`

Lo scanner usa parser/confronto dei nomi brevi e filtro attributi originali; il walker estrae i cluster dai record che quello scanner ha effettivamente trovato. Non viene più restituito un puntatore preconfezionato nei due livelli2A318C e2A2D88. Nel gruppo r vengono inoltre eseguiti2AC528/lista oggetti, semaforo e primitive critiche, callback close1F48A4→21AD30→2AC564 e close volume1F46C4 con guardia2A45E4.

**Fixture rimaste:**2E4EC4 fornisce buffer con guardie, contenuto0/A5 o nullo; registrazione metadati/free sono recorder.2A1178 restituisce settori predisposti oppure errore01A00021.21B2CC/21A454 escludono gli oggetti cache esterni;2A29B4 restituisce cache miss, lasciando che il codice originale prosegua nel percorso normale. Su errori di lettura iniettati,2ABC68 termina l'avanzamento: non viene seguita una catena FAT.

Per le sette sequenze r: contesto montato backend1, wrapper generico, lista e semaforo sono predisposti;2F7ABC fornisce un oggetto da80byte e2F7AF0 registra il rilascio. Clock21B300 e predicato cache21A424 del close sono fixture, campo dirty0; ioctl3 del volume ritorna0. Non sono eseguiti gli open/close generici superiori che allocano e distruggono il wrapper.

## Albero di settori condiviso

| Directory logica del modello | Record predisposti | Buffer |
|---|---|---|
|radice, cluster0|AKERUDMP.ON; DIR con attributo0x10 e cluster2; record vuoto|0x0200B000|
|DIR, cluster2|AKERUDMP.ON; SUB con attributo0x10 e cluster3; record vuoto|0x0200B200|
|sub, cluster3|FILE.BIN; record vuoto|0x0200B400|

Ogni buffer è da512byte,16record. Il valore corrente relativo0x123 è un alias della radice dichiarato dal test: non una mappatura fisica scoperta. Ogni directory occupa un solo settore. I nomi brevi sono quelli realmente confrontati dal firmware; nessun filesystem viene creato o montato sul computer.

I percorsi validi producono le rotte osservate **0**, **0→2**, **0→2→3**; un percorso relativo usa0x123. Pointer del record, cluster e indice devono concordare. Gli input con slash e backslash raggiungono gli stessi record attesi. Il profilo A5 dei20casi conserva i risultati per i percorsi validi provati, ma non è usato nei due casi di errore parser delle sequenze r.

Tutti i settori rimangono byte per byte invariati e i nomi di input sono preservati. Ogni buffer scratch acquisito viene liberato una volta, con guardie intatte, stack e nesting critico ripristinati.

## Matrice integrata e classificazione degli errori

| Caso nel gruppo20 | Esito | Letture settore |
|---|---|---:|
|nome assoluto/relativo valido in radice|0, record0|1|
|DIR seguito dal nome|0, record nel cluster2|2|
|DIR/sub/FILE.BIN|0, record nel cluster3|3|
|file MISSING.TXT assente|01A00002|1|
|directory NOPE assente|01A00003|1|
|errore di lettura sul record finale|01A00021|1 alla radice,2 nel caso annidato|
|stesso errore durante ricerca della directory|01A00003|1|
|allocazione517 iniziale nulla|01A00006|0|
|allocazione257 del parser nulla, scratch0|**0, record vuoto indice2**|1|
|allocazione256 del coordinatore nulla|01A00006|0|
|allocazione256 del walker nulla|01A00003|0|
|puntatore nome nullo|01A00013|0|

Sono inclusi anche nome diretto vuoto, separatore finale, flagcontext+720 a0 e i profili di riempimento. Il nome vuoto restituisce il record vuoto nella directory relativa0x123; il caso con separatore finale trova il record DIR nella radice. Nessuno dei due implica che il successivo open debba accettare una directory o un nome iniziale vuoto: i chiamanti hanno controlli propri.

Il codice locale del livello in cui nasce l'errore conta: la stessa fixture di lettura01A00021 rimane21 se accade nella ricerca del record finale, ma viene compressa nella sentinella1 del walker e tradotta in03 durante la ricerca della directory.

## Falso successo: ricostruzione completa del caso

1. Il chiamante richiede AKERUDMP.ON; lo scratch517 viene allocato e inizialmente riempito con0.
2. L'allocazione257 di29FFB0 fallisce: il parser ritorna01A00006 prima di produrre directory e nome finale.
3. 2A3360 non verifica quel ritorno:2A33B0 lo sovrascrive con context+720. Le stringhe nel buffer517 restano vuote.
4. Walker e scanner originali ricevono quindi un componente finale vuoto.2A2D88 **non si comporta come una ricerca per corrispondenza esatta con nome vuoto**: nel settore del modello raggiunge il primo record vuoto e ne restituisce il puntatore, con stato0 e indice2.
5. Nel gruppo r,21A0D0 vede un record con byte attributi0, alloca un oggetto e copia quei32byte vuoti; la callback restituisce0. Il test confronta la copia nell'oggetto con il record indice2, non con il record AKERUDMP.ON indice0.
6. La lista oggetti passa a1 e impedisce il close del volume. Close del file rimuove l'oggetto, complementa la magic e richiede il rilascio; il successivo close volume riesce.

Le due sequenze di errore parser del gruppo7 differiscono nel canale inferiore dell'allocatore:

| Allocazione nulla: errore d'uscita fornito dalla fixture | Stato finale callbackr | task+0x38 dopo codice originale | Oggetto |
|---|---|---|---|
|0|0|0|copiato dal record vuoto2|
|01A00006|0|01A00006|copiato dallo stesso record vuoto2|

Nel secondo caso **231158 originale** conserva l'errore nel task. Non occorre supporre che il vero allocatore restituisca nullo senza un errore: il falso successo è riprodotto anche con un errore nonzero esplicito. Il numero01A00006 è però un input della fixture, non una misura del codice esatto emesso dal pool fisico Nikon. Lo stato nel task è un canale distinto, non automaticamente una soluzione per il binding: gestione/azzeramento degli errori precedenti e tutti i chiamanti non sono verificati qui.

**Nessun create2AC2B4 viene eseguito:** il probe lo rifiuterebbe. Nessun settore viene modificato. È un falso riconoscimento/apertura del record nel modello, non una creazione persistente osservata o una prova di corruzione della SD.

## Sette sequenze r e cleanup

Tre casi validi aprono il file alla radice, in DIR e in DIR/sub, poi:

- verificano oggetto/magic, copia record e metadata;
- tentano close volume, che rifiuta01A00010 mentre l'oggetto è vivo;
- chiudono il file con le istruzioni originali, verificando rimozione dalla lista e un rilascio al pool;
- chiudono il volume, che ora ritorna0 e azzera context+424.

Il file assente e l'errore di lettura non pubblicano oggetti. I due casi di falso successo invece seguono lo stesso ciclo oggetto/guardia/cleanup dei casi validi, pur avendo copiato il record sbagliato. Il campo pointer della traccia r è il ritorno finale dopo il cleanup; il controllo dell'oggetto avviene prima del suo rilascio, tramite assert e snapshot del probe.

## Aggiornamento delle conclusioni e prossimo passo

Le [prove precedenti con finder fixture](S33_Dumper_RAM_SD_Lookup_Parser_Errori_e_Buffer.md) restano riproducibili nella loro portata, ma non possono predire il risultato di questo caso integrato: la fixture a corrispondenza esatta nascondeva il comportamento originale sul nome vuoto. Anche [la verifica separata di walker e scanner](S33_Dumper_RAM_SD_Directory_e_Scanner_Record_Originali.md) è ora seguita da un'esecuzione condivisa, con le nuove condizioni esplicite.

Per il futuro binding, un ritorno0 e un oggetto vivo **non bastano a provare l'identità del file di appoggio richiesto**. Non viene aggiunto un adattatore C che assuma risolta questa condizione. Prossimo: verificare identità e contratto del record per il binding, poi eseguire lettore settori2A1178 e gestione cache/avanzamento dei cluster, ancora simulati.

Fuori prova: SD fisica, FAT reale, cache/dirty reali, più settori per directory, catene di cluster, nomi lunghi completi, percorso DCIM, altri backend, concorrenza, perdita di alimentazione, wrapper generici superiori e completa mappa RAM fisica/lifetime launcher.

Nessun C applicativo o BIN modificato, nessun hardware usato. **NON_INSTALLARE**, circa10% funzionale AkeruOS invariato; obiettivo generale attivo.

## Continuazione — lettore e trasferimento eseguiti

[S33_Dumper_RAM_SD_Settori_Cache_e_Trasferimento_Originale.md](S33_Dumper_RAM_SD_Settori_Cache_e_Trasferimento_Originale.md): lettore/cache28casi, trasferimento25, lookup integrato20 fino a callback dispositivo sintetica. ProdottoDSP dichiarato e driver simulato; non prova persistenza fisica o r/open/close integrati. Il rapporto distingue regressioni e limiti; nessun hardware.

## Continuazione — FAT multisettore e r/driver/close

[S33_Dumper_RAM_SD_Catena_FAT_Multisettore_e_Identita_File.md](S33_Dumper_RAM_SD_Catena_FAT_Multisettore_e_Identita_File.md):34casi avanzamento/decoder,13catena multisettore e7r/driver/close. Il precedente limite del lettore sostituito nella sequenza r è superato per l’albero con un settore per directory; la FAT multisettore è provata separatamente. Nuovi casi errore FAT perso, voce0 che riporta alla root, ciclo limitato e root esaurita. Close libera tre buffer ma non ne azzera le celle. Driver/DSP/pool dichiarati; nessun hardware o BIN.
