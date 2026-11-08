# S33 — stato di integrazione della GUI, 31 ottobre 2026

Il risultato richiesto resta aperto: quattro pulsanti fisici per esposizione, colore/Mono RAW Luminance, funzione da decidere e impostazioni. Esiste un modello sperimentale, non una GUI installabile. Gli indirizzi indicati nelle fonti riguardano il dump V1.1, non altre versioni.

Requisito aggiunto dall'utente il 31 ottobre 2026: **ISO, diaframma e tempo devono offrire ciascuno un'opzione Auto indipendente**, combinabile con valori manuali degli altri due. La semantica e l'effettiva applicazione in camera sono ancora da verificare: [analisi Auto e tempo](S33_GUI_Tempo_Auto_Indipendente_Autoscene_CPU_20261031.md).

Nello stesso menu esposizione deve essere disponibile **Flash sì/no**; l'Auto del flash non è prioritario. Nel modello sperimentale la seconda pagina offre tempo e flash, e la schermata flash emette azioni separate sì/no. Sono azioni astratte, non ancora collegate al controllo Nikon. Nel menu originale i record «No flash» e «Flash sempre attivo» hanno valori 1 e 8; una [prova CPU delimitata](S33_GUI_Flash_Scelte_Valori_CPU_20261031.md) segue i valori fino al setter e getter originali in modalità sintetiche, con risultato dipendente dalla modalità. Non prova il comportamento fisico.

Una [prova successiva](S33_GUI_Flash_Applicazione_Oggetto_CPU_20261031.md) esegue anche `0xDE3A4` originale: nei modi sintetici 0x2C e 0x46 i valori raggiungono due byte di un oggetto in RAM sintetica; in 0x08 arriva 26. Nessuna applicazione allo scatto è dimostrata.

Un [consumatore originale](S33_GUI_Flash_Consumatore_Valore_CPU_20261031.md) distingue il valore 1 dagli altri sotto condizioni controllate: otto casi CPU passano, con input e servizi sintetici. Il significato fisico del suo risultato resta da stabilire.

La [prova integrata](S33_GUI_Flash_Menu_Consumatore_CPU_20261031.md) segue lo stesso oggetto dalla scelta del menu al consumatore in 18 casi; la chiamata al consumatore resta imposta dal banco, senza prova della sequenza reale di scatto.

Una [prova del modello](S33_GUI_Flash_Modello_Eventi_Originali_CPU_20261031.md) parte dal menu Akeru e usa un adattamento del banco per le scelte sì/no originali: nei modi sintetici 0x2C e 0x46 arrivano 8 e 1, in 0x08 arriva 26. Il raccordo resta sperimentale e non installabile.

La [prova successiva](S33_GUI_Flash_Dispatcher_Modello_CPU_20261031.md) consegna le pressioni al dispatcher originale attraverso un descrittore sintetico, mantenendo il raccordo verso la scelta flash nel banco.

Un [banco con coda](S33_GUI_Flash_Coda_Modello_CPU_20261031.md) genera anche pressioni e rilasci logici attraverso il codice Nikon e verifica che l'azione rimanga pendente fino al prelievo imposto dal banco. Mappa fisica e concorrenza restano aperte.

La [prova snapshot](S33_GUI_Flash_Snapshot_Modello_CPU_20261031.md) aggiunge lettore e normalizzatore originali con MMIO sintetici per la stessa navigazione, lasciando al banco la chiamata del callback e la consegna degli eventi.

## Tasti e instradamento

| Slot classe 0x15 | Bit snapshot candidato | Tasto logico | Evento attivo / rilascio | Assegnazione desiderata, subordinata alla mappa fisica |
|---:|---:|---:|---|---|
| 0 | 12 | 11 | 0580 / 0581 | Esposizione |
| 1 | 7 | 14 | 0700 / 0701 | Standard / mono |
| 2 | 8 | 67 | 2180 / 2181 | Da decidere |
| 3 | 13 | 78 | 2700 / 2701 | Impostazioni |

Il 31 ottobre il [verificatore statico](../Python_Trace_Scripts/s33_verify_four_button_candidate_mapping.py) ha nuovamente controllato record, tabelle e finestre rispetto al dump: [PASS](../Risultati/GUI_S33/four_slot_mapping_20261031T153550Z/evidence.json). L'assenza di 2700 dalla tabella live view delimitata non esclude fallback. Questa tabella **non identifica l'ordine fisico**: filtri, stato, acquisizione e consegna effettiva restano condizionati. La [prova CPU](S33_GUI_Tasti_Logici_Coda_e_Quattro_Slot_CPU_20261028.md) consegna gli eventi al controllo mediante banco e usa record e servizi sintetici. Il [confronto live view](S33_GUI_Liveview_Confronto_Eventi_700_2180_CPU_20261030.md) mostra destinazioni diverse per 0700 e 2180 nel contesto sintetico: non basta trasferire una mappa di CaptureMenu alla live view.

Il modello [menu.h](../AkeruOS/ui/menu.h) rappresenta schermate e azioni richieste; la sua coda è sequenziale, capienza quattro e overflow esplicito. Il 31 ottobre `make -C AkeruOS menu-model-verify` è passato su host e GNU ARC700, incluse navigazione e azioni flash: [risultati](../Risultati/GUI_S33/akeru_menu_model_20261031T155912Z/). Questo non verifica concorrenza, worker, rendering, tasti fisici o lifecycle reale; la [prova del ciclo](S33_GUI_Coda_Azioni_Modello_CPU_20261030.md) usa callback e completamento simulati.

## Valori fotografici

* **ISO:** selezionando 125 nel banco diagnostico si ottengono indice 6 e valore software 125. Exit conserva il valore iniziale; Auto porta a 0 nel caso senza ripristino. Una sequenza diversa con ripristino imposto può riportare 1600: l'ordine effettivo di AE e scatto resta sconosciuto. [Scelte e calcolo](S33_GUI_ISO_Scelte_Conferma_Calcolo_CPU_20261030.md), [wrapper e ripristino](S33_GUI_ISO_Origine_Record_Wrapper_CPU_20261030.md).
* **Tempo:** la conferma usa un valore diagnostico moltiplicato per 1000; in un percorso con chiamate e dati imposti, 42 diventa 42000 nel buffer finale. Unità fisica, limiti e applicazione allo scatto non sono dimostrati. [Conferme e calcolo](S33_GUI_Conferme_ISO_Tempo_Calcolo_CPU_20261030.md).
* **f/:** il percorso iris software richiede stati 1 e 9 e include acquisizione, occupazione e completamento asincrono; il banco simula servizi e callback. Non associa questi stati ai valori ottici né prova il movimento. Il manuale descrive due passi con filtro ND, non una scala continua: [controlli e specifiche](S33_GUI_Quattro_Tasti_e_Controlli_20261027.md), [completamento](S33_GUI_Iride_Completamento_Richieste_CPU_20261030.md).
  Un [frammento del calcolo](S33_GUI_Iride_Calcolo_Esposizione_CPU_20261031.md) confronta posizione desiderata e corrente, ma non identifica il ritorno all'Auto.
  Una [prova della copia a monte](S33_GUI_Iride_Origine_Copia_Esposizione_CPU_20261031.md) collega il byte sorgente `0x38077F` al valore desiderato `0x38068F` e alla richiesta iride con ordine imposto dal banco; il produttore del byte e la mappatura ottica restano ignoti.
  Un [successivo frammento](S33_GUI_Iride_Produttore_Calcolo_CPU_20261031.md) mostra due possibili byte sorgente, scelti in base a una condizione sintetica, fino alla stessa richiesta; produttori di quei byte e mappatura ottica restano ignoti.
  La [prova delle conversioni](S33_GUI_Iride_Conversione_Ritorno_CPU_20261031.md) mostra che un valore non riconosciuto può essere ricondotto a 1 o 9 secondo la tabella: il risultato non conferma da solo stato o movimento reali.

## Colore e impostazioni

Mono RAW Luminance è una ricostruzione di luminanza dai campioni CFA, non la semplice scelta del menu colore Nikon. Due RAW sono già stati elaborati offline con calibrazione ipotetica, non misurata: [risultati e limiti](S33_Mono_RAW_Frame_Reali_Riferimento_20261029.md). Il 31 ottobre i sei test del riferimento e del codice offline sono passati; coprono input sintetici, fasi Bayer e bordi, non la qualità o l'integrazione in fotocamera. Il [banco colore](S33_GUI_Colore_Mono_Snapshot_Frame_CPU_20261030.md) impone snapshot e chiamata del processore su frame sintetico: cattura, sincronizzazione e JPEG rimangono da collegare.

Il [confronto della lunghezza CFA](S33_RAW_CFA_Lunghezza_Calcolo_e_File_20261031.md) mostra che il frammento diagnostico, con geometria sintetica 4208×3152, richiede lunghezze diverse dal payload CFAi1012 osservato. Non è ancora identificato il percorso che ha prodotto il file né un buffer sicuro per Mono RAW.

Per le impostazioni esistono prove del manager con apertura e ritorno condizionali, ma flag e servizi sono sintetici: [attivazione](S33_GUI_Impostazioni_Attivazione_Contesto_CPU_20261030.md), [ritorno](S33_GUI_Impostazioni_Ritorno_Contestuale_CPU_20261030.md). Non dimostrano schermata fisica o persistenza.

## Priorità residue

1. Stabilire il percorso reale dal campionamento agli eventi e all'oggetto corrente, inclusa l'identità fisica dei pulsanti e le differenze live view/menu.
2. Collegare lifecycle, annullamento e ritorno dei sottomenu; risolvere serializzazione, overflow e azioni pendenti senza assumere il completamento.
3. Seguire ISO, tempo e stati iris fino a cattura e arbitraggio AE; identificare unità e limiti tramite evidenze appropriate.
4. Calibrare e integrare la pipeline mono nel percorso di acquisizione e uscita, dimostrando buffer, tempi e sincronizzazione; verificare le impostazioni e il ritorno reale.

Nessuna interazione con camera o SD è stata eseguita. Candidati **NON_INSTALLARE**.
