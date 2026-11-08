# Nikon S33 V1.1 — studio della GUI con REA

27 ottobre 2026. Studio offline dei payload originali; nessun accesso alla fotocamera o scrittura su SD. Gli indirizzi usano la mappa candidata dei payload V1.1 e non sono automaticamente validi per V1.0.

## Quadro di funzionamento

```text
tasto logico → evento → dispatcher → handler della schermata
                                    → richiesta di cambio oggetto
                                    → controllo di lista classe 0x15
                                         → record di 28 byte
                                         → ID testo / ID grafica / destinazione
                                    → servizi di testo e grafica → display (non chiuso)
```

Le frecce descrivono collegamenti statici o prove CPU delimitate, non garantiscono la consegna dell'evento né il rendering effettivo.

### Eventi e schermate

Nel percorso di ripresa il dispatcher `0x169F60` riceve un evento e consulta una tabella di coppie evento/callback, con una lista di filtro e un fallback. Nella tabella di `CaptureLiveview`, evento `0x0700` raggiunge `0x65426C`: a seconda di guardie e modalità questa routine può richiedere `CaptureMenu` (oggetto `0x02`) o `ImageMode` (`0x9B`) tramite `0x1453E4`. La prova GNU preesistente copre 24 scenari, ma tasti, guardie e servizio di apertura sono fixture; non identifica il pulsante fisico né dimostra l'apertura di una finestra. [Tasti e schermate](S33_GUI_Ripresa_Tasti_e_Risorse_20261027.md).

La richiesta `0x1453E4` passa attraverso controlli di indice e del gestore `0x145180`: una richiesta può essere condizionata o rifiutata. `CaptureMenu` usa un proprio dispatcher con eventi di ingresso `0x4401`/`0x4405`, uscita `0x4406` e altri eventi. I filtri iniziali letti nel file sono dati iniziali, non stato runtime accertato. [Dispatcher e selezione](S33_GUI_Menu_Dispatch_e_Selezione_20261027.md).

### Liste, selezione e testi

Il controllo di classe `0x15` usa record consecutivi di 28 byte. Nel caso studiato, la tabella dell'evento `0x4409` rimanda a `0x6316BC`: REA mostra il ciclo e la chiamata da `0x63175E` a `0x631F44`. Il passo si ricava da `(indice * 8 - indice) * 4 = indice * 28`. Nell'handler di selezione `0x631878` REA mostra lo stesso calcolo e controlli su bit del campo a `+24`; l'analisi GNU precedente segue le ulteriori guardie e il campo signed `+20`, che può diventare ID di destinazione, e `+16`, che può diventare argomento della richiesta di apertura. [Destinazioni e guardie](S33_GUI_CaptureMenu_Destinazioni_20261027.md), [risoluzione risorse](S33_GUI_CaptureMenu_Risoluzione_Risorse_20261027.md).

Le due liste di `CaptureMenu` hanno rispettivamente 3 e 4 record. I loro ID di testo a `+12`, interpretati attraverso il percorso di lookup e i blocchi di lingua controllati, corrispondono condizionalmente a: «Modo flash/autoscatto», «Flash», «Autoscatto», «Altre opzioni foto», «Scegli stile», «Decora» e «Cambia colore». La lingua effettiva e la visualizzazione non sono osservate. [Byte delle stringhe e origine](S33_GUI_CaptureMenu_Testi_Italiani_20261027.md).

`ImageMode` ha liste distinte per dimensione foto e video; tra i testi candidati verificati ci sono «Grande (13 megapixel)» e «Grande (1080p)». Una lista ha quattro record ma dimensione pagina iniziale tre: numero di record e numero di voci visibili per pagina sono cose diverse. [Liste ImageMode](S33_GUI_ImageMode_Testi_Italiani_20261027.md).

### Grafica e schermo

Nel ramo grafico studiato `0x631F44` sceglie fra ID memorizzati nei primi tre halfword del record; `0x26E3C0` può passare l'ID al lookup `0x23B20C`. Quest'ultimo usa una tabella e un limite nel contesto `0x36A5E0`. Il preparatore `0x23B234` mostra un caso compatibile con RLE byte e un altro con prefisso di dimensioni, secondo analisi statica GNU delimitata. [Descrittori grafici](S33_GUI_Descrittore_Grafico_20261027.md).

Una verifica successiva ha individuato un'inizializzazione **candidata**: `0x23E704` passa al setter grafico `0x23B19C` il puntatore `0xEA0660` e il limite 887. Nella tabella originale, gli 11 ID grafici distinti delle liste `CaptureMenu` puntano a descrittori 72×72 con dati compressi. Una decodifica host, basata sull'interpretazione statica del ciclo originale, produce 5.184 indici per ciascuno. Cinque coppie di ID hanno la stessa maschera di indici non zero, ma valori non zero diversi. Le [maschere](../Risultati/GUI_S33/graphic_table_init_20261027T180014Z/) non sono immagini renderizzate dalla fotocamera. Non sono dimostrati l'inizializzazione e la persistenza della tabella a runtime, la palette, la trasparenza, il rendering o il significato degli stati. [Tabella grafica e prove](S33_GUI_Tabella_Grafica_CaptureMenu_20261027.md).

REA ha successivamente letto le finestre di codice a `0x159110`, `0x23E704`, `0x23B19C`, `0x23B20C`, `0x23B234` e il letterale `0x23E730`, confrontandole con il payload originale: tutte le sei letture coincidono. [Evidenza REA](../Risultati/GUI_S33/rea_graphic_init_20261027T182942Z/evidence.json). Questa prova controlla i byte; la semantica delle istruzioni e il collegamento dei dati derivano dalle verifiche GNU e host citate, non da esecuzione REA.

Una verifica CPU successiva esegue per intero la routine originale `0x23B234` sugli 11 flussi compressi originali: produce gli stessi 5.184 indici per ciascuna risorsa della decodifica host, con stack e guardia dopo il buffer conservati. Usa contesti, descrittori e buffer sintetici e il simulatore GNU DSP v7 **sperimentale**: il prodotto `72 × 72` è gestito dal suo modello provvisorio di `MULDW`, non verificato su hardware. Le 11 chiamate del modello sono state controllate nel log. Non prova il caricamento delle risorse, la palette o il rendering. [Verificatore](../Python_Trace_Scripts/s33_verify_gui_rle_cpu.py), [risultati e log](../Risultati/GUI_S33/rle_original_cpu_20261027T183202Z/verified_evidence.json).

Un ulteriore [studio del disegno indicizzato](S33_GUI_Disegno_Indicizzato_20261027.md) collega staticamente la callback candidata `0x2C8380` al ramo per il campo `+6 = 8`, alla conversione della tabella e alla routine di riga `0x2C9018`. Cinque prove CPU isolate con fixture mostrano che, quando una tabella di conversione è presente, la scrittura viene saltata se il **valore convertito** è zero: l'indice sorgente zero non è necessariamente trasparente. Il collegamento dei chiamanti rimane statico; palette, buffer e pannello reali non sono osservati.

La [ricerca del valore grafico](S33_GUI_Lookup_Colore_20261027.md) è stata verificata separatamente: la routine originale `0x17AF2C` prepara una chiave da quattro byte e ricerca una corrispondenza esatta fra 256 word. Undici casi CPU con tabella sintetica coprono soglie, duplicati, indice 255 e assenza. Il ritorno zero è ambiguo fra prima voce e assenza; la tabella realmente usata non è stata osservata.

Il [banco GNU integrato](S33_GNU_GUI_Pipeline_20261027.md) esegue ora conversione, decompressione e 72 chiamate di riga su ciascuna delle 11 risorse, orchestrate da un chiamante sintetico. Due tabelle di ricerca sintetiche producono risultati distinti e verificati. Il banco amplia le prove riproducibili del simulatore, non dimostra il flusso completo o il display reale.

Esistono inoltre una libreria font/contesto, percorsi di configurazione LCD e comandi diagnostici: la loro presenza non chiude il percorso dall'oggetto al pannello. [Catena display](S33_Schermo_Catena_Uscita_Display.md).

## Nuova prova REA e correzioni

L'ELF storico `tbm-02-analysis.elf` è una rappresentazione relocatable del blocco 2: l'intera sezione `.text` è stata confrontata con il payload V1.1 (`5d7f4e074b585407b660375ab5ba5b30144987c10bdbed98589998cfddb545c6`). L'ELF ha SHA-256 `8534b647979f1298edc78dc77595222638910f78b95d9f18f3e847155b0e3c0c`.

Ghidra inizialmente applicava una base `0x10000` all'ELF relocatable e quindi leggeva indirizzi spostati. La copia locale `rea-arc` ora imposta base zero per gli ELF ARC `ET_REL`; la sezione risulta a `0x5FE800`. Per questo preciso ELF, identificato dall'hash, tre ingressi sono definiti esplicitamente da precedenti verifiche: `0x6316BC`, `0x631F44`, `0x631878`. Non sono funzioni scoperte autonomamente da REA. La prova [s33_verify_rea_gui.py](../Python_Trace_Scripts/s33_verify_rea_gui.py) ha confrontato 64 byte per ciascun ingresso con il payload originale e ottenuto l'assembly; [evidenza completa](../Risultati/GUI_S33/rea_gui_verified_20261027T181543Z/evidence.json). File originale invariato.

L'analisi Ghidra resta sperimentale. Il corpo attribuito a `0x631F44` include istruzioni lontane non dimostrate appartenenti alla funzione. A `0x6318AC` REA/Ghidra mostra `EXT05`, mentre il disassemblaggio GNU riporta `muludw`: non utilizzare questa decodifica o il corpo intero come prova autonoma. Il profilo elenca gli ingressi forzati e i risultati contengono avvertenze; le conclusioni qui usano i byte confrontati e le analisi GNU circoscritte.

Il test separato su `firmware.bin` con Binwalk 3.1.0 ha dato 99 firme candidate, non partizioni convalidate. `block00-analysis.elf` era riconosciuto ma nella prova precedente la ricerca delle procedure aveva superato 330 secondi. La diagnostica ha identificato `Decompiler Switch Analysis` come fase che assorbiva il tempo; nella copia locale è disabilitata per il solo hash di questo ELF. La nuova prova ha ottenuto la mappa con base zero in 86 secondi e letto a `0x23B20C` 64 byte identici al payload originale: [evidenza](../Risultati/GUI_S33/rea_large_elf_20261027T182150Z/evidence.json). La ricostruzione degli switch e la copertura del flusso indiretto rimangono incomplete; il test non dimostra che tutte le procedure siano state trovate. Né questi test né la ricostruzione della GUI dimostrano comportamento del pannello o hardware. Candidati **NON_INSTALLARE**.

Una successiva chiamata `list_procedures` è terminata in 72 secondi con zero procedure: il file non offre ingressi riconosciuti automaticamente. Un esperimento con ingressi grafici inseriti prima dell'analisi ha allungato sensibilmente la fase di propagazione delle costanti ed è stato interrotto; tali ingressi non sono rimasti nella configurazione. La prova sulla sola lettura dei byte resta valida e non va interpretata come disassemblaggio delle funzioni grafiche.
