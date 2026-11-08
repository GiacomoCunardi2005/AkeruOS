# NAND dal PC: dispatch del pacchetto, Boot invariato e contatore

21 ottobre2026 — R0/R3/R4. Continuazione del [componenteMain](S33_NAND_PC_Main_Updater_Rilettura_Retry_e_Limite_Recupero.md). Eseguiti registrazione dei nomi, lettura dei descrittori, XOR, dispatcher e callback originali sui tre componenti del candidato, con servizi inferiori registratori. **Il dispatch richiede una scritturaBootCode anche se il componente è invariato.** Una seconda richiesta diretta dopo un errore può inoltre terminare con successo prematuro a causa del contatore conservato. Non è un aggiornamento fisico o una sessioneUI completa: **NON INSTALLARE** rimane.

## Fonti e riproduzione

- [Script](../Python_Trace_Scripts/s33_verify_nand_pc_package_dispatch.py).
- [Evidenza](../Risultati/USB_SCSI/Accesso_NAND_PC/package_cpu_20261021T095804Z/verified_evidence.json), [dieci casi e richieste ordinate](../Risultati/USB_SCSI/Accesso_NAND_PC/package_cpu_20261021T095804Z/dispatch_cases.json).
- [Confini di laboratorio](../Risultati/USB_SCSI/Accesso_NAND_PC/package_cpu_20261021T095804Z/laboratory_patches.json).
- [Registratore](../Risultati/USB_SCSI/Accesso_NAND_PC/package_cpu_20261021T095804Z/000bc3a0_gnu.txt), [dispatcher](../Risultati/USB_SCSI/Accesso_NAND_PC/package_cpu_20261021T095804Z/000bc3f8_gnu.txt), [lookup](../Risultati/USB_SCSI/Accesso_NAND_PC/package_cpu_20261021T095804Z/000bc478_gnu.txt), [iterazione pacchetto](../Risultati/USB_SCSI/Accesso_NAND_PC/package_cpu_20261021T095804Z/0012a794_gnu.txt), [callbackBoot](../Risultati/USB_SCSI/Accesso_NAND_PC/package_cpu_20261021T095804Z/0012aa3c_gnu.txt), [routineBoot](../Risultati/USB_SCSI/Accesso_NAND_PC/package_cpu_20261021T095804Z/0012ae00_gnu.txt).

```bash
python3 Python_Trace_Scripts/s33_verify_nand_pc_package_dispatch.py
```

Il candidato rimaneSHA256`0bb25fd6603488e30d41ac6ad96f4fe4e8fe5e838deda7cfc7e9c6ab7cb324e9`, [manifest](../Risultati/USB_SCSI/Accesso_NAND_PC/container_20261021T092600Z/verified_evidence.json). Nessun nuovoBIN creato e nessuno dei precedenti candidati esclusi viene rivalidato.

## Catena eseguita e confini

Il test usa i getter originali dei tre nomi e chiama il registrarBC3A0 originale, poi12A794 con filename ordinario e callbackBC3F8. Sono eseguiti XOR12B060, parser12AFF0, ricercaBC478, dispatcherBC3F8 e callback12AA3C/12A9FC/12AAA8. Le routineBoot12AE00 eMain12AD58 conservano i validatori, confronti e retry originali.

La tabella dei nomi è a **42D15C**, dieci record da68byte;42D19C è il campo callback del primo record,64byte più avanti. I tre record attesi sono verificati integralmente per nome e callback, insieme alla guardia finale. Il primo tentativo aveva mappato soltanto da42D19C e si era arrestato sulla scrittura del nome a42D15C: è un errore della fixture conservato comeFAIL, non un difetto del firmware.

Il byte **365411** conta le registrazioni; **365410** conta i componenti completati dal dispatcher. Sono inizialmente0 nella copiaMain1. Non sono lo stesso campo e non sono dati letti dalla fotocamera accesa.

| Confine sostituito | Effetto nel laboratorio |
|---|---|
|12AB24|fornisce il candidato effettivo e i puntatori al buffer/scratch; può restituire errore di caricamento|
|12A738|registra il rilascio della risorsa20|
|1EEA4C|registra selettore/buffer/offset/lunghezza; può restituire erroriBoot/Main|
|1ED27C|registra la riletturaBoot e copia ilBoot del file nel buffer di confronto|
|1ECD6C|registra la riletturaMain e copia ilMain del file nel buffer di confronto|
|16F200|registra la richiesta di commitBoot|
|129460|registra la richiesta relativa alle risorse e l’eventuale errore|

Queste riletture sono fixture del contenuto atteso, **non una memoria scritta dal writer**: questo test prova selezione, argomenti, ordine e controllo degli esiti, non la persistenza o l’integrità fisica. Il precedente testMain copre separatamente writer/preparatori e rilettura con memoriaRAM condivisa. Il registrarBBB60 completo, l’allocatore delle risorse, il filesystem e laUI non sono eseguiti qui.

GeometriaF0/P1IDSTR e motoreDSPv7 hanno gli stessi limiti dichiarati nei rapporti precedenti. Il modello non certifica controller, timing, ECC, rimappatura, cache o letture RAM sconosciute generali.

## Ordine confermato dei componenti

Nel caso normale, il contenitore produce questa sequenza:

| Componente | Percorso e richiesta |
|---|---|
|BootCode|12AA3C→12AE00; writer1EEA4C con selettore0, offset0, lunghezza48000; poi rilettura, confronto originale e richiesta16F200|
|MainCode|12A9FC→12AD58; writer1EEA4C con selettore6, offset0, lunghezza10CDC00; poi34414settori di rilettura e confronto originale|
|P1RES|12AAA8→129460; argomenti494D5245,01200000, puntatore alP1RES rilocato nel candidato, lunghezzaB26616|

I puntatori sorgente e le lunghezze registrate corrispondono ai descrittori del candidato. Boot eP1RES sono identici agli originali secondo il builder. **Questo non li esclude dal dispatch:** la richiestaBoot precede qualsiasi rilettura di confronto del componente. Non è ancora provato se il driver inferiore eviti programmazioni identiche; non attribuire a questo test cancellazioni o scritture fisiche osservate.

Il caso normale termina0, con un rilascio della risorsa e contatore365410 tornato0 dopo il terzo componente. La richiesta di commitBoot viene registrata una volta. Il rischio dell’aggiornamento pubblico comprende quindi anche il percorsoBoot, pur senza nostre modifiche ai suoi byte.

## Dieci casi

| Caso | Ritorno | Richieste writer, selettori | Richieste risorse | Contatore finale |
|---|---|---|---:|---:|
|normale|0|0,6|1|0|
|XOR errato|01C00141|nessuna|0|0|
|errore loader|01C00135|nessuna|0|0|
|errore writerBoot persistente|01C00122|0,0,0|0|0|
|errore writerMain persistente|01C00112|0,6,6,6|0|1|
|errore riletturaBoot persistente|01C00122|0,0,0|0|0|
|errore riletturaMain persistente|01C00112|0,6,6,6|0|1|
|errore risorse|4567 della fixture|0,6|1|2|
|seconda richiesta dopo erroreMain|0 al secondo giro|primo:0,6,6,6; secondo:0,6|0 in entrambi|0|
|seconda richiesta dopo errore risorse|0 al secondo giro|primo:0,6; secondo:0|1 solo nel primo|0|

Tutti i casi preservanoSP, i byte sorgente del pacchetto e le guardie di registro/scratch. Sono controllati anche il numero di caricamenti e rilasci. Nell’errore del loader, il confine restituisce direttamente l’errore senza allocare; non viene attribuito al chiamante un rilascio che il codice non esegue.

## Seconda richiesta e successo prematuro

BC444 chiama il callback selezionato. Quando ritorna0, BC450 incrementa365410. A **BC456** viene confrontato soltanto il valore3: quando raggiunto, BC45C azzera il byte e il dispatcher restituisce0; altrimenti restituisce01C00139, che12A794 interpreta come «prosegui al descrittore successivo».

Un errore non azzera quel contatore nei corpi provati. I due casi di seconda richiesta non lo impostano artificialmente a1/2: tali valori derivano dalla **prima chiamata effettivamente fallita**; la seconda usa la stessa vitaRAM e non ripete la registrazione.

- Dopo erroreMain, il primoBoot è già contato:365410=1. Nella seconda richiestaBoot porta a2 eMain porta a3; il dispatcher restituisce0 e il pacchetto termina senza passareP1RES al callback.
- Dopo errore risorse, Boot eMain sono già contati:365410=2. Nella seconda richiesta basta il soloBoot per arrivare a3; il pacchetto termina0 senza richiedereMain né nuovamenteP1RES. L’errore della fixture risorse viene rimosso prima di questa seconda richiesta, ma quel servizio non viene più chiamato.

**Confermato nella sequenza diretta testata:** ritorno0 della seconda richiesta con componenti saltati. **Non dimostrato sullaUI reale:** potrebbero intervenire reinizializzazioni, riavvii o altri percorsi prima di consentire un nuovo aggiornamento. Il prefissoUI8086A8→8086E0 non contiene uno store diretto a365410, ma i serviziUI/timer e tutti gli scrittori indiretti non sono eseguiti nel test. Non dedurre da questo una procedura sicura di retry o spegnimento dopo un errore reale.

## Stato e continuazione

Il dispatch del pacchetto e i relativi limiti sono ora eseguiti, oltre alla precedente ricostruzione statica. Rimangono **fisici** writerBoot/commit, percorso risorse e sopravvivenza delle copie al reset. Il fatto che il componenteBoot sia invariato non risolve questi punti.

Prossimo: chiarire la selezione delle sorgenti nel fallbackTBIB e le guardie per il caricamento alternativo, quindi delimitare quale recupero possa esistere quando ilMain è incompleto. Restano durataRAM e verificaUSB/NAND reale. Nessuna scrittura sulla fotocamera; obiettivo attivo, **NO-GO** e circa10% funzionaleAkeruOS invariati.

## Continuazione — guardia e produttore eseguiti

La [verifica successiva](S33_NAND_PC_TBIB_Guardia_Produttore_e_Selezione_Fallback.md) collega il bit4 diFED2068 e i registriFE70224/228 ai predicati originali, poi esegue256routing con servizi simulati. Il byteINFO20 può comparire anche quando falliscono tutti i file. Nessuna combinazione di tasti o proceduraSD fisica attribuita; proseguire sul lettorefile0100125C e sull’identità dei supporti.
