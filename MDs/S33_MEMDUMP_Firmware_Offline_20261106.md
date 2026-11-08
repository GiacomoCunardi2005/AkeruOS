# Candidato MEMDUMP V1.1 — laboratorio, NON INSTALLARE

6 novembre 2026. È stato creato un [contenitore firmware.bin sperimentale](../Risultati/Firmware_sperimentali/MEMDUMP/OFFLINE_NON_INSTALLARE_20261106T141100700116Z/firmware.bin), **solo per analisi offline**. SHA-256 `33fa20e059e8f1cee4f5b0a49b1a046c661e9a311191259a8fe1cb3fc7bdef21`. Non copiarlo su SD e non installarlo: la prova non dimostra avvio sicuro o dump affidabile. Originale V1.1 immutato, SHA-256 `1d34e990a8f99019ffa53ca5de785399df863e942739a667ceb314ec6ce62a39`. Nessuna fotocamera, NAND o SD usata.

## Costruzione

Il [builder](../Python_Trace_Scripts/s33_build_memdump_offline.py) parte dal contenitore originale e modifica tre regioni:

* Il call site `0xC58EE` diventa un branch alla guardia, dopo il caricamento C4. La guardia esegue la chiamata Nikon originale `0x158CBC`, conserva il suo ritorno e cerca firma/versione della risorsa.
* Una guardia di 68 byte è inserita nel candidato a `0x35BB20`; se la firma è presente chiama l'ingresso nella risorsa. **Gli zeri originali e il censimento statico non dimostrano proprietà, eseguibilità o residenza dell'area.**
* Firma e payload di 300 byte sono inseriti nel blocco Resource 9 a `0xE99E00`. Il payload crea un task con priorità 19, ricavata dal record V1.1 del task Load Later, e stack proposto `0x8000`; né questa scelta né la disponibilità dell'area sono verificate sulla macchina. Il worker controlla flag volume e base `B:`, poi chiama `0x16ED40`.

Il builder controlla l'identità originale, gli offset, la struttura del contenitore, le checksum dei 16 blocchi, i campi KH​IR e XOR, e limita le differenze alle tre regioni e alle checksum. La ricostruzione inversa del delta restituisce byte per byte l'originale. [Delta e hash](../Risultati/Firmware_sperimentali/MEMDUMP/OFFLINE_NON_INSTALLARE_20261106T141100700116Z/delta.json); la verifica del contenitore non dimostra l'installabilità.

## Esecuzione CPU con fixture

Il [verificatore](../Python_Trace_Scripts/s33_verify_memdump_offline_hook.py) estrae il codice dal contenitore e usa il simulatore GNU ARC700. Nella [prova 20261106T141301947254Z](../Risultati/Runtime_Kernel/MEMDUMP_Offline_Hook/20261106T141301947254Z/verified_evidence.json), sette casi verificano la chiamata originale alla segnalazione e lo stack: risorsa valida, risorsa originale senza firma, versione errata, volume non pronto, percorso diverso, indice invalido e creazione task fallita. Nel caso valido la fixture registra una creazione e il task, invocato successivamente dal banco, raggiunge `0x16ED40` e la prima chiamata di salvataggio con nome e lunghezza attesi. Gli altri casi non chiamano il salvataggio.

Il banco esegue hook, guardia, payload e parti del codice Nikon originali, ma simula la segnalazione, la creazione e l'esecuzione del task e la scrittura su file. Per tornare al banco modifica la continuazione soltanto nella copia emulata. La fixture di scrittura restituisce un errore alla prima chiamata: non è stata scritta una SD e non è stato acquisito un dump. Il caso valido usa stati volume e tabella sintetici.

## Limiti che impediscono l'installazione

Non sono provati mappa fisica e copertura RAM, lifetime delle aree modificate, integrità del caricamento Resource, priorità e stack effettivi, SD pronta/stabile, spazio e gestione delle attese. Il candidato **non protegge un file precedente e non impedisce avvii ripetuti**; i controlli di percorso e volume sono separati dalla scrittura e possono diventare obsoleti. Il task non riprova se la SD non è pronta; non comunica integrità o persistenza del file. Il risultato della segnalazione originale non blocca la creazione del task in questo prototipo. Non esiste prova di boot o recupero fisico.

Il file è un artefatto per proseguire le verifiche, non l'esito completo della richiesta. Ulteriori dettagli sul comportamento e sui limiti di `MEMDUMP.BIN` sono nel [rapporto diagnostico](S33_MEMDUMP_Verifica_20261106.md).

## Secondo candidato: limitazione degli avvii ripetuti

È disponibile un [secondo firmware.bin di laboratorio](../Risultati/Firmware_sperimentali/MEMDUMP/OFFLINE_NON_INSTALLARE_20261106T141656432554Z/firmware.bin), SHA-256 `38f9e16207a422264864259f387100713fb91a95057e7098131351d268867a31`. Anche questo è **NON INSTALLARE**. Mantiene hook e guardia precedenti; il payload Resource misura ora 456 byte e contiene un flag inizializzato a zero, in una posizione la cui proprietà, scrivibilità e durata restano ipotesi di laboratorio.

Il [protocollo one-shot](../AkeruOS/nikon_v11_memdump_once.c) imposta il flag dentro la coppia di primitive Nikon `0x1786E8/0x179354`, esce dalla sezione critica e poi chiede la creazione del task. Un secondo ingresso mentre il flag è impostato non crea un altro task; se la creazione fallisce, il flag viene rilasciato per consentire un nuovo tentativo. Il flag rimane invece impostato se il task viene creato ma poi rifiuta il dump per volume o percorso. Il ricaricamento della risorsa può azzerare il flag: non è una garanzia fra reload o avvii della macchina.

Il [test ARC isolato](../Risultati/Runtime_Kernel/MEMDUMP_Once/20261106T141837057744Z/verified_evidence.json) esegue le primitive Nikon originali con kernel/task sintetici, incluso un ingresso simulato durante la creazione. Il [test del contenitore](../Risultati/Runtime_Kernel/MEMDUMP_Offline_Hook/20261106T141823598742Z/verified_evidence.json) esercita otto casi con due ingressi consecutivi ciascuno: nel caso valido e nel caso con rientro simulato durante la creazione registra un solo task; se la creazione fallisce registra due tentativi e nessun dump. Segnalazione, scheduler e I/O rimangono fixture e la continuazione è sostituita nella sola copia emulata. Non dimostra concorrenza fisica, più CPU o proprietà della RAM.

La nuova guardia non protegge un `MEMDUMP.BIN` preesistente, non controlla spazio o persistenza e non rende il dump atomico. Non sono stati verificati avvio, caricamento e recupero reali; nessuna SD o fotocamera è stata usata. La prova non completa l'obiettivo e non autorizza l'installazione.

## Versione della firma corretta

La seconda versione usava ancora la firma/versione del primo payload: un blocco Resource vecchio avrebbe potuto essere accettato senza la nuova guardia one-shot. Il [terzo candidato offline](../Risultati/Firmware_sperimentali/MEMDUMP/OFFLINE_NON_INSTALLARE_20261106T141935661872Z/firmware.bin), SHA-256 `ab4cda82b6880d182bff5ac24f4809caf7d392918dc74c385d30c17bb33c5832`, usa versione `2` sia nella guardia sia nel payload. È anch'esso **NON INSTALLARE**.

La [prova ARC aggiornata](../Risultati/Runtime_Kernel/MEMDUMP_Offline_Hook/20261106T141955930834Z/verified_evidence.json) comprende nove casi con due ingressi per caso: oltre a versioni assenti o errate, presenta alla guardia il Resource firmato del primo candidato e verifica che non venga creato alcun task. Restano fixture e limiti della prova precedente. La firma controlla due word: non certifica l'integrità del resto del payload o la validità fisica della memoria.

## Prenotazione esclusiva e salvataggio Nikon

Il [test di prenotazione](../Python_Trace_Scripts/s33_verify_memdump_reservation.py) collega i wrapper Nikon originali a una FAT12 sintetica con contesto già predisposto. Nell'[esecuzione 20261106T142257692986Z](../Risultati/Runtime_Kernel/MEMDUMP_Reservation/20261106T142257692986Z/evidence.json), l'apertura esclusiva `n` crea e mantiene un handle; mentre è vivo, `0x12BD5C` sullo stesso nome ritorna `0x01A00012`. Il primo handle rimane vivo e tutti i 110 settori simulati restano invariati rispetto a prima del tentativo concorrente; anche il secondo wrapper e oggetto usati nel modello vengono rilasciati.

Dopo la chiusura del primo handle, lo stesso wrapper salva correttamente 256 byte nel modello; un contesto filesystem nuovo li rilegge, un controllo host li confronta e `fsck.fat -n` passa. Il modello usa due oggetti e wrapper distinti, heap e controller sintetici: non stabilisce tutti i contratti dei backend fisici o le condizioni di rimozione SD.

Nel profilo provato non si può quindi conservare la prenotazione e aspettarsi che `0x12BD5C` riapra lo stesso file. Chiuderla prima della scrittura lascia una finestra in cui un altro soggetto potrebbe intervenire: la prova non dimostra una protezione atomica del file. La versione 2 precedente non contiene la prenotazione; la versione 3 seguente la usa con questo limite.

## Candidato con verifica preliminare del nome

Il [candidato versione 3](../Risultati/Firmware_sperimentali/MEMDUMP/OFFLINE_NON_INSTALLARE_20261106T142642215902Z/firmware.bin), SHA-256 `cdc64e8fd3a94d741f26b999bf606694188ed3c35aa1fc7e695ddda3f9af8062`, è **NON INSTALLARE**. Dopo i controlli di volume e percorso, il task tenta la creazione esclusiva di `B:\\MEMDUMP.BIN`, controlla la chiusura e ricontrolla il percorso prima di chiamare il diagnostico Nikon. Un errore ferma il tentativo; può rimanere un file vuoto e un errore di chiusura può lasciare risorse occupate. L'intervallo tra chiusura e riapertura resta esposto a modifiche concorrenti: non è una protezione atomica.

Il builder ha verificato checksum, perimetro delle differenze e ricostruzione inversa dell'originale. Il [test del contenitore](../Risultati/Runtime_Kernel/MEMDUMP_Offline_Hook/20261106T142739521305Z/verified_evidence.json) supera 12 casi CPU con scheduler e I/O simulati, inclusi file esistente, errore di chiusura e percorso cambiato. Il [test FAT](../Risultati/Runtime_Kernel/MEMDUMP_Worker_FAT/20261106T142842923048Z/trace.txt) esegue il task compilato e i wrapper Nikon su FAT sintetica: con file esistente non chiama il diagnostico e i 110 settori confrontati restano invariati; con nome libero effettua due scritture, ma il volume simulato si riempie a 4096 byte e la seconda ritorna `0x01A00014` dopo 3840 byte. È una prova di quel modello, non di tutti i backend o di una SD fisica.

Rimangono non verificati mappa e copertura fisica della RAM, integrità e completezza del dump, scheduling, durata e proprietà delle aree, avvio e recupero hardware. Nessuna fotocamera o SD è stata utilizzata. Il candidato non soddisfa ancora l'obiettivo di un dump affidabile e ripetibile.

## Task del candidato su FAT sintetica estesa

Il [verificatore](../Python_Trace_Scripts/s33_verify_memdump_large_fat.py) con `--candidate` estrae il task dal Resource del candidato identificato dal suo SHA-256 e lo invoca direttamente, con volume, filesystem e DMA sintetici. La [prova](../Risultati/Runtime_Kernel/MEMDUMP_Worker_Large_FAT/20261106T144649861251Z/evidence.json) raggiunge creazione/chiusura preliminare e due salvataggi Nikon: il file `MEMDUMP.BIN` ricostruito dalla FAT è lungo 17.041.228 byte, i conteggi riportati sono completi e `fsck.fat -n` passa. I primi 710.656 byte corrispondono al pattern iniziale predisposto.

Rispetto all'istantanea della memoria emulata presa all'ingresso del secondo salvataggio, il file differisce in 1052 byte; 1021 di questi sono nella pagina sintetica `0x54E000`. Il banco registra un trasferimento DMA modellato in scrittura il cui intervallo sorgente comprende quella pagina. Questo confronto dimostra che il file non corrisponde esattamente all'istantanea precedente; non attribuisce tutte le differenze a una causa specifica e non stabilisce il comportamento fisico.

Il task è avviato dal banco, non dallo scheduler o dall'hook di boot. La geometria FAT, i buffer, la RAM e il controller sono predisposti o modellati: l'esito non prova copertura della RAM reale, continuità temporale, persistenza su SD o avvio e recupero della macchina. La prenotazione resta soggetta alla finestra tra chiusura e riapertura. Il firmware rimane **NON INSTALLARE**.

## Hook e task nello stesso banco

La [prova integrata](../Risultati/Runtime_Kernel/MEMDUMP_Hook_Large_FAT/20261106T145002369613Z/evidence.json), riproducibile con `python3 Python_Trace_Scripts/s33_verify_memdump_large_fat.py --hook`, carica il blocco principale e il Resource del candidato verificato. Il banco entra due volte nel call site modificato `0xC58EE`: la segnalazione originale è una fixture, mentre guardia, payload e primitive della sezione critica vengono eseguiti. Una fixture di creazione task registra una sola richiesta, con ingresso `0xE99EB8`, priorità 19 e stack `0x8000`; il banco esegue poi quell'ingresso. La continuazione del call site è intercettata per tornare al banco. Seguono prenotazione, diagnostico e filesystem Nikon nel modello FAT esteso: file da 17.041.228 byte, conteggi completi e `fsck.fat -n` riuscito.

Il file differisce in 1052 byte dall'istantanea presa prima del secondo salvataggio. Tutte le differenze cadono nella regione del trasferimento DMA principale; il confronto host verifica che i suoi **11.124.736 byte** nel file coincidano con la memoria emulata acquisita al momento di quel trasferimento. Nel modello, dunque, quei byte erano già diversi dall'istantanea precedente quando la DMA è partita; non si può dedurre da questo la causa di ogni modifica o una proprietà della fotocamera.

L'ingresso nell'hook, la creazione ed esecuzione del task sono orchestrati dal banco, non da un boot o scheduler reali. Segnalazione, FAT, geometria, RAM e DMA hanno fixture o stati sintetici. Restano aperti disponibilità e durata delle aree, mappa fisica, collisioni nel periodo fra prenotazione e riapertura, SD e recupero; il candidato resta **NON INSTALLARE**.

## Versione 4: attesa limitata del volume

Il [nuovo firmware.bin offline](../Risultati/Firmware_sperimentali/MEMDUMP/OFFLINE_NON_INSTALLARE_20261106T145245285906Z/firmware.bin), SHA-256 `02cf8d32792b878df76003a889c228c8fa1cc4bde7cb796137527fe3d3533266`, è **NON INSTALLARE**. La firma versione 4 impedisce alla sua guardia di accettare il Resource della versione 3. Il builder ha verificato formato, checksum, perimetro del delta e ricostruzione inversa dell'originale.

Il task controlla il volume al massimo 30 volte; fra controlli falliti richiede una pausa da 1000 ms tramite `0x19A774`, fino a 29 pause. Solo dopo stato zero e flag pronto procede alla verifica del percorso e alla prenotazione. La durata e il numero di tentativi sono scelte di laboratorio: il ritardo effettivo dipende dal tick e dallo scheduler. Se i tentativi terminano, il task esce senza creare il file; il flag one-shot rimane impostato e non garantisce un ulteriore tentativo senza ricaricare la risorsa. Errori di percorso, prenotazione o chiusura non sono ritentati.

I test host con ASan/UBSan e il [test ARC del worker](../Risultati/Runtime_Kernel/MEMDUMP_Worker_Prototype/20261106T145234433295Z/verified_evidence.json) verificano disponibilità dopo due pause e timeout dopo 29. Il [test ARC del contenitore](../Risultati/Runtime_Kernel/MEMDUMP_Offline_Hook/20261106T145310613977Z/cases.json) passa 14 casi, inclusi timeout, disponibilità ritardata, rientro, file esistente e Resource precedente; attese, scheduler e I/O sono fixture. Nel [test P-code integrato](../Risultati/Runtime_Kernel/MEMDUMP_Hook_Delayed_Large_FAT/20261106T152321029649Z/evidence.json) la fixture rende pronto il volume dopo due pause e il percorso del candidato produce il file sintetico da 17.041.228 byte con conteggi completi e `fsck.fat -n` riuscito. La memoria e il controller restano modellati, e il file non è una fotografia atomica.

Nessuna prova dimostra che il tick sia attivo a quel punto, che la SD reale sia pronta entro il limite, o che aree e stack siano disponibili e sicuri. La finestra tra prenotazione e riapertura rimane; mappa RAM, persistenza, boot e recupero fisici non sono verificati. Nessuna fotocamera o SD è stata utilizzata.

### Attesa originale e tick sintetico

La [prova P-code con delay originale](../Risultati/Runtime_Kernel/MEMDUMP_Hook_Real_Delay/20261106T152643775565Z/evidence.json), riproducibile con `python3 Python_Trace_Scripts/s33_verify_memdump_large_fat.py --hook-real-delay`, esegue il candidato e le routine Nikon `0x19A774`, accodamento e tick software `0x2F70C4`. Con clock **predisposto dal banco a 10 Hz**, ciascuna delle due attese richieste da 1000 ms accoda il task e viene fatta scadere con 10 chiamate del tick; il banco rende pronto il volume dopo la seconda. Seguono il salvataggio su FAT sintetica e la verifica del file da 17.041.228 byte.

Nel [caso di timeout](../Risultati/Runtime_Kernel/MEMDUMP_Hook_Delay_Timeout/20261106T152711226160Z/evidence.json), con volume sempre non pronto, 29 attese richiedono 290 tick sintetici. Il task termina senza chiamare la prenotazione o la scrittura e i 110 settori del modello restano invariati. Un successivo ingresso nel call site non crea un secondo task: il flag one-shot resta impostato.

L'orologio, l'invocazione dei tick, la disponibilità del volume e il cambio di contesto CPU sono predisposti o simulati; hook e task sono avviati dal banco. Queste prove non verificano il tick fisico, il risveglio dello scheduler reale, i tempi effettivi o la sicurezza dell'installazione. **NON INSTALLARE**.

### Intervento fra prenotazione e salvataggio

Il [test di interleaving](../Risultati/Runtime_Kernel/MEMDUMP_Reservation_Race/20261106T153032982094Z/evidence.json), riproducibile con `python3 Python_Trace_Scripts/s33_verify_memdump_worker_isolated.py --race`, esegue il task della versione 4 su FAT sintetica. Dopo la chiusura della prenotazione, ma prima di entrare in `0x16ED40`, il banco fa chiamare a un secondo soggetto modellato il wrapper Nikon originale `0x12BD5C`, che aggiunge 512 byte riconoscibili a `MEMDUMP.BIN` e chiude. Il task riprende poi il proprio percorso senza ricontrollare il contenuto del file.

Un parser host ricostruisce il file: i primi 512 byte del secondo writer sono conservati, mentre i primi 256 byte del dump iniziano all'offset 512. Il volume sintetico si riempie a 4096 byte durante la seconda scrittura diagnostica, che riporta `0x01A00014`; `fsck.fat -n` passa. Questa prova mostra una modifica indesiderata del file e un dump disallineato nel profilo simulato: non prova che il prefisso preesistente venga sovrascritto né misura la probabilità dell'interleaving reale.

L'intervento concorrente è orchestrato sullo stesso emulatore; scheduler, filesystem, DMA e SD fisici non sono verificati. La prenotazione preliminare della versione 4 **non garantisce l'esclusività fino al salvataggio**. Risolvere questa finestra richiede un contratto di scrittura e ownership diverso, verificato anche rispetto alle routine Nikon; il candidato rimane **NON INSTALLARE**.

### Studio: mantenere l'handle esclusivo

Nel [test con handle mantenuto](../Risultati/Runtime_Kernel/MEMDUMP_Held_Writer/20261106T153357159598Z/evidence.json), `0x12DBFC` apre il file in modo esclusivo e due chiamate originali a `0x12DE3C` scrivono rispettivamente 256 e 513 byte sullo stesso handle. Fra le due, un tentativo modellato di aprire lo stesso nome tramite `0x12BD5C` ritorna `0x01A00012`; i 110 settori restano invariati durante il tentativo. Dopo close, una riapertura in un contesto nuovo rilegge tutti i 769 byte attesi; il controllo host e `fsck.fat -n` passano.

Un [secondo esperimento](../Risultati/Runtime_Kernel/MEMDUMP_Held_Diagnostic/20261106T153345964696Z/evidence.json) esegue `0x16ED40` originale, ma **una fixture intercetta le sue due chiamate a `0x12BD5C`** e le dirige a `0x12DE3C` con l'handle mantenuto. La prima scrive 256 byte; un concorrente modellato viene respinto; la seconda incontra volume pieno, riporta 3840 byte e `0x01A00014`, e il diagnostico seleziona `Write fail`. L'handle viene chiuso una sola volta e i 4096 byte presenti coincidono con la sorgente sintetica. Per i casi stato zero/conteggio corto la fixture prevede un errore sintetico: non è un codice Nikon dimostrato né un ramo esercitato da questo esperimento.

Questa è una pista per togliere la finestra nel backend FAT modellato, non una correzione già presente nel firmware: serve ancora un adapter eseguibile, limitato al task corretto, con gestione di conteggi, close, errori e concorrenza. Il diagnostico originale continua normalmente a riaprire il file. Non sono provate esclusività su tutti i backend, SD fisica, avvio o recupero; **NON INSTALLARE**.

### Adapter compilato per l'handle mantenuto

Il [prototipo C](../AkeruOS/nikon_v11_memdump_held.c) riceve esplicitamente contesto, identità del task, nome e argomenti della scrittura. Per un task diverso inoltra alla routine originale; per il proprietario controlla nome, selettore e ordine dei due segmenti, usa l'handle fornito e richiede sia stato zero sia conteggio completo. Un conteggio corto con stato zero diventa il valore locale nonzero `1`, usato come fallimento nel prototipo, non come codice Nikon attribuito. Lo stato passa temporaneamente a errore prima della chiamata per rifiutare un rientro nello stesso contesto.

I [test host](../AkeruOS/tests/nikon_v11_memdump_held_test.c) con ASan/UBSan e la [prova GNU ARC](../Risultati/Runtime_Kernel/MEMDUMP_Held_Adapter/20261106T153605453189Z/verified_evidence.json) coprono inoltro di altri task, entrambi i segmenti, rientro, ordine, nome errato, stato errore e conteggio corto; I/O e identità restano fixture. Nel [test P-code FAT](../Risultati/Runtime_Kernel/MEMDUMP_Held_Adapter_FAT/20261106T153752240452Z/verified_evidence.json), il codice ARC compilato esegue realmente `0x12DE3C` sul filesystem modellato: il diagnostico originale riceve la prima scrittura corretta e l'errore di volume pieno sulla seconda, mentre un concorrente modellato è respinto. La deviazione dai due call site all'adapter e l'identità del proprietario sono predisposte dal banco, non implementate nel candidato.

Il contesto richiede pubblicazione, lifetime e sincronizzazione verificati; la prova non stabilisce un hook sicuro, esclusività fisica, gestione completa del close o del backend reale. Non è stato generato un nuovo firmware che contenga l'adapter. **NON INSTALLARE**.

Continuazione 6 novembre 2026: [versione 5, handle esclusivo integrato](S33_MEMDUMP_Versione5_Handle_Esclusivo_20261106.md).
