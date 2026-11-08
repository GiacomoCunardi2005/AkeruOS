# Dumper RAM: candidato launcher residente nella coda Main0

22 ottobre 2026. Verificato staticamente il candidato `[0x35BB20,0x35BC00)` richiesto per la guardia dopo `0xC58E0`. **L'intervallo più conservativo è `[0x35BB20,0x35BBF0)`, capacità208byte**, preservando il template originale e la posizione `0x35BBF0` ancora presente come valore nei dati Nikon. È una collocazione sperimentale offline: non prova ownership, permessi di esecuzione o lifetime hardware.

[Verificatore](../Python_Trace_Scripts/s33_verify_ram_dump_launcher_tail.py), [evidenza](../Risultati/Runtime_Kernel/RAM_Dumper_Launcher_Tail/20261022T084022Z/verified_evidence.json), [finestre GNU](../Risultati/Runtime_Kernel/RAM_Dumper_Launcher_Tail/20261022T084022Z/gnu_verified.txt). Riproduzione: `python3 Python_Trace_Scripts/s33_verify_ram_dump_launcher_tail.py`. Esito `PASS_LAUNCHER_TAIL_STATIC_CENSUS_NOT_OWNERSHIP`; nessun accesso hardware, modifica firmware o GNU.

## Censimento riprodotto

Tutti i16payload originali e il corpoTBIB sono verificati prima della scansione. Ricerca raw a passo **un byte**, distinta per parole LE e LIMM middle endian, nell'intero intervallo di valori `0x35BB00..0x35BBFF`:

| Immagine | Sito CPU | Encoding | Valore | Classificazione |
|---|---:|---|---:|---|
|Main0|`0x3329D8`|LE|`0x35BB01`|pool realmente letto a `0x3327A4`|
|Main0|`0x333B78`|LE|`0x35BB04`|pool realmente letto a `0x333972`, sorgente template16byte|
|Main0|`0x279EBA`|ME|`0x35BB48`|straddle: seconda metà della wordLE `0x00351E30` a279EB8 e prima metà della wordLE `0x0036BB48` a279EBC; non LIMM allineato del flusso ricostruito|
|payload6|`0xA814A0`|LE|`0x35BBF0`|valore in dati, nessun reader pcl provato; semantica lasciata aperta|
|payload9|`0xD0CF13`|ME|`0x35BB1D`|disallineato3 modulo4, indirizzo dispari: fuori candidato e non LIMM di istruzione ARC allineata|

Il negativo raw è esatto per questi encoding; non copre costruzione aritmetica di puntatori o branch PC-relative. La scansione allineata GNU storica del vicinato trova soltanto i due reader pcl sopra. Gli originari `[0x35BB04,0x35BB14)` sono letti con `r2=16` verso `0x128C20`, come già verificato nel [rapporto memcpy](S33_NAND_PC_Memcpy_Guardia_Template_e_Canarie.md). La coda `[0x35BB02,0x35BC00)` contiene254byte zero nell'immagine originale: questa proprietà è controllata ma non usata come prova di memoria libera.

Ricalcolate inoltre le333 scritture di prossimità con ruolo base contenute nello [sweep originale](S33_NAND_PC_Sweep_Scrittori_Estensione.md): **nessuna interseca `[0x35BB20,0x35BC00)`**. La prova resta limitata alle24istruzioni successive al caricamento del pool e non è dataflow completo; i puntatori installati altrove e gli scrittori calcolati rimangono fuori copertura.

## Rami del listato lineare: risultato mantenuto esplicito

La ricerca di destinazioni `0x35BBxx` nel listato integrale produce63decodifiche `b0` nei byte zero della stessa coda, più **otto candidati nonzero** da `0x34DB66`, `0x359BD8`, `0x35B3D6`, `0x3F5AA6`, `0x70EB90`, `0x958F94`, `0xB01EF4`, `0xB4BADA`. Sono conservati nel JSON, senza attribuire al listato lineare una CFG dimostrata. In particolare il listato include dati interpretati come istruzioni: **questa verifica non dichiara zero branch globali raggiungibili**. Una prova definitiva della collocazione deve classificare questi ingressi o dimostrare che i loro siti sono dati.

## Contratto del launcher richiesto

Il [binding task](S33_Dumper_RAM_Task_Attesa_e_Clock_Binding.md) ancora il sito `0xC58E0` a `bl 0x159128` dopo Load Resource. Il launcher deve eseguire la chiamata originale, verificare **prima di ogni trasferimento** firma/versione del nuovo contenuto payload9, e soltanto nel caso valido chiamare il wrapper proposto `0xE99E00`. Firma e indirizzo wrapper sono parte del nuovo artefatto da verificare, non byte originali Nikon qui attribuiti al codice esistente. Load Resource può fallire e il coordinatore ne ignora l'esito.

Il candidato208byte evita il template16byte, lascia12byte di margine dopo di esso e preserva gli ultimi16byte con il valore ambiguo35BBF0. Non prova che il caricamento Resource abbia esito positivo, che non si ripeta, che il task sia creato una sola volta o che il codice Resource rimanga residente. Questi sono requisiti indipendenti del firmware sperimentale.

Nessun AkeruOS o indice condiviso modificato da questo controllo. NON_INSTALLARE; nessuna lettura RAM reale acquisita.
