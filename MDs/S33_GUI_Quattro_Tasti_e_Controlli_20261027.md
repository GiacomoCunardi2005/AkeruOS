# AkeruOS — quattro tasti e controlli richiesti

27 ottobre 2026. Obiettivo espresso dall'utente: quattro pulsanti sul lato sinistro, dall'alto verso il basso, destinati a (1) ISO / apertura / tempo, (2) colore / Mono RAW Luminance, (3) da decidere, (4) impostazioni. Questo documento è una mappa di ricerca V1.1, non un firmware modificato o una promessa di funzionalità già operative.

## I pulsanti e la GUI

Il [manuale Nikon](../output/pdf/Archivio_AI/pdf/Nikon_S33_Reference_Manual_En05_03cc47d1917e.pdf) chiama i quattro pulsanti laterali **flexible buttons 1–4**, in ordine dall'alto verso il basso (pagina stampata 5, PDF pagina 27). Le loro funzioni dipendono dalla schermata.

Nel firmware originale sono individuabili quattro **slot logici** nella classe GUI `0x15`. Il verificatore confronta le tabelle originali con `MainCode.dmp`:

| Slot classe, indice 0–3 | Bit nella coppia di stato | Indice tasto logico | Evento nonzero | Callback classe `0x15` |
| ---: | ---: | ---: | --- | --- |
| 0 | 12 | 11 | `0x0580` | `0x631878` |
| 1 | 7 | 14 | `0x0700` | `0x63195C` |
| 2 | 8 | 67 | `0x2180` | `0x631A38` |
| 3 | 13 | 78 | `0x2700` | `0x631B14` |

**Questa tabella non identifica ancora i pulsanti fisici 1–4**, né dimostra il loro ordine. L'emissione dipende da stato e filtri; anche altri percorsi software possono inviare eventi. `KeyOK` e `KeyMenu` sono nomi di comandi diagnostici, non un'identificazione elettrica. In `CaptureLiveview` gli eventi `0x0580`, `0x0700` e `0x2180` hanno voci esplicite; `0x2700` non compare esplicitamente nella tabella delimitata e può seguire il fallback. Non si può quindi applicare automaticamente la mappa dei controlli alla live view.

[Verificatore incrociato](../Python_Trace_Scripts/s33_verify_four_button_candidate_mapping.py), [record e limiti](../Risultati/GUI_S33/four_slot_mapping_20261027T213633Z/evidence.json); [paginazione e guardie](S33_GUI_Classe15_Paginazione_20261027.md). La prova è statica, non aziona pulsanti o legge MMIO fisici.

La [catena statica degli ingressi e della coda](S33_GUI_Quattro_Slot_Snapshot_e_Coda_20261027.md) chiarisce come i bit candidati possono raggiungere il dispatch GUI, con filtri e guardie; non identifica ancora i pulsanti fisici.

Il [confronto fra manuale e record del menu](S33_GUI_Confronto_Manuale_Slot_20261027.md) suggerisce una correlazione fra pulsanti fisici 2/3/4 ed eventi `0x700`/`0x2180`/`0x2700` nella specifica lista «More picture options». La correlazione richiede condizioni non ancora verificate e non risolve una differenza rispetto a una prova separata in live view: non è una mappa fisica accertata.

La [prova dei quattro handler con liste originali](S33_GUI_Quattro_Slot_Liste_Originali_CPU_20261027.md) verifica in CPU le destinazioni richieste per `CaptureMenu` e `ChangeColorMenu` in contesti sintetici. Quest'ultimo ha geometria iniziale pagina/prefisso/conteggio **3/1/4**, non 4/0/4; il calcolo usa il DSP sperimentale e l'apertura è una fixture.

Un [banco con destinazioni sintetiche](S33_GUI_Quattro_Slot_Destinazioni_Sintetiche_CPU_20261028.md) prova le richieste verso oggetti originali ISO o tempo, menu colore e impostazioni. ISO e tempo sono alternative nello stesso slot, il terzo è un segnaposto: non è ancora il sottomenu richiesto né un'implementazione Mono RAW.

Un secondo [banco del sottomenu esposizione](S33_GUI_Sottomenu_Esposizione_Instradamento_CPU_20261028.md) inserisce ISO e tempo nella stessa lista sintetica, lasciando gli altri due slot senza destinazione; f/ e ritorno restano da realizzare.

Nella [prova dell'aggiornamento dei record](S33_GUI_CaptureMenu_Aggiornamento_Record_e_Slot_CPU_20261027.md), la routine originale può impostare flag che bloccano due voci prima della loro selezione. Sono prove CPU con stati e servizi sintetici: il controllo va studiato insieme al suo ciclo di vita.

Una [prova della live view](S33_GUI_Liveview_Evento_2180_CPU_20261027.md) immette direttamente l'evento `0x2180`: nelle condizioni sintetiche ammesse viene richiesta l'apertura dell'oggetto interno `ShootingMode`. Il servizio di apertura è una fixture; l'ordine fisico e la transizione completa restano ignoti.

Una [prova del ritorno da CaptureMenu](S33_GUI_CaptureMenu_Ritorno_LiveView_CPU_20261027.md) segue l'evento iniettato `0x480` attraverso i dispatcher originali fino alla richiesta condizionale di `AutoSceneLiveView`, con servizi sostituiti; non verifica la chiusura e apertura effettive.

## 1. ISO, apertura e tempo

Il [manuale Nikon, pagina stampata 117](../output/pdf/Archivio_AI/pdf/Nikon_S33_Reference_Manual_En05_03cc47d1917e.pdf) (PDF pagina 139) dichiara per la S33 originale ISO 125–1600, tempi da 1/2000 a 1 s e 4 s nella scena fuochi artificiali. Descrive l'apertura tramite un **filtro ND elettronico**, con due passi f/3.3 e f/6.6 a grandangolo. Sono specifiche del prodotto originale, non intervalli dimostrati di un futuro comando manuale. Non sono stati misurati valori f/ a ogni zoom né il mapping fra gli indici firmware e questi due numeri.

Una [prova CPU dei valori diagnostici](S33_GUI_Debug_Valori_ISO_Tempo_CPU_20261027.md) ha verificato la conversione di 25 indici ISO in valori software e la scrittura del tempo moltiplicato per 1000 nei casi sintetici. Unità, applicazione allo scatto e rapporto con esposizione automatica restano da ricostruire. I nomi delle priorità AE non provano che siano selezionabili. Il menu diagnostico fotografato mostra voci `Exposure Time` e `ISO`, senza dimostrare cosa cambino nello scatto: [foto storica](../Risultati/Hardware/HiddenMenu_23Foto_20261020T173627Z/11_debug_exposure.jpg). Il percorso software chiamato iris usa stati 1 e 9 e il wrapper `0x149530` scarta il ritorno del setter: non può confermare da solo il risultato fisico. [Analisi successiva dell'attuazione](S33_Iride_Attuazione_GPIO_0FF04024_e_Chiusura_Wrapper.md); [piano storico, con correzione](S33_AkeruOS_Esposizione_Manuale_AvTvM_Piano.md).

Gli [handler diagnostici su/giù](S33_GUI_Debug_Tempo_Tasti_CPU_20261027.md) modificano il valore interno nei sei casi CPU sintetici provati. Per il tempo, [14 prove CPU con chiamate forzate](S33_GUI_Tempo_Sovrascritture_e_Snapshot_20261027.md) mostrano che altri setter possono modificare un campo condiviso e lasciarlo diverso dal valore debug; non dimostrano l'ordine reale né la persistenza. Per ISO, [l'analisi statica](S33_GUI_ISO_Lettori_Priorita_e_Soglie_20261027.md) mostra conversioni e ripristini condizionali, non una sequenza di scatto verificata.

Cinque [sequenze CPU di modifica e conferma del tempo](S33_GUI_Debug_Tempo_Modifica_Conferma_CPU_20261027.md) mostrano che i campi impostazione osservati restano invariati fino alla conferma nei casi sintetici provati; non dimostrano persistenza successiva o tempo fisico.

La [conferma della lista ISO diagnostica](S33_GUI_Debug_ISO_Lista_e_Conferma_CPU_20261027.md) è stata provata in 26 casi CPU con lista originale e controllo sintetico: `Exit`, `Auto` e voci 50–3200. Il convertitore include anche 6400, che non è presente in questa specifica lista; questi valori non dimostrano il guadagno fisico.

Nella [prova CPU di inizializzazione ISO](S33_GUI_Debug_ISO_Inizializzazione_CPU_20261027.md), l'indice 23 non ha voce nella lista e richiede la posizione `Exit`; guardie del controllo possono impedire il cambio di selezione. Contesto, conteggio e servizi GUI sono sintetici.

Nella [sequenza CPU riapertura e conferma ISO](S33_GUI_Debug_ISO_Riapertura_Conferma_CPU_20261027.md), per indice 23 iniettato la selezione sintetica ripiega su `Exit`, ma la successiva conferma lascia invariati indice e valore software: la posizione visualizzabile non basta dunque a dedurre un reset.

Una [catena statica ISO verso un buffer di calcolo](S33_GUI_ISO_Soglia_e_Buffer_20261027.md) collega condizionalmente il campo numerico a un correttivo e a successivi confronti; altre chiamate possono intervenire, e l'effetto sul sensore non è dimostrato.

Il [percorso statico del tempo](S33_GUI_Tempo_Ingresso_Calcolo_20261027.md) mostra che una copia del suo campo può entrare in un calcolo insieme a ISO, con condizioni e trasformazioni; non dimostra applicazione allo scatto. Conferma ISO e conferma/annullamento tempo richiedono il ritorno al menu diagnostico originale: [verifica dell'uscita](S33_GUI_Debug_Esposizione_Uscita_20261027.md). Il futuro sottomenu richiede quindi una gestione del ritorno ancora da verificare.

Nella [prova CPU del ripristino](S33_GUI_Ripristino_ISO_Tempo_CPU_20261028.md), `0xCA654` conserva o aggiorna i campi del record in base ai valori diagnostici sintetici. La [statica del WindowManager](S33_GUI_WindowManager_Ciclo_e_Redirect_20261028.md) descrive possibili redirect soggetti a guardie, senza dimostrare ritorno automatico al nuovo menu.

La [prova CPU del redirect](S33_GUI_WindowManager_Interpretazione_Redirect_CPU_20261028.md) verifica i casi di destinazione precedente e risoluzione ID su descrittori sintetici, senza eseguire una transizione completa. La [prova del formato diagnostico tempo](S33_GUI_Debug_Tempo_Formato_CPU_20261028.md) osserva la richiesta del testo `Auto` per la word zero e del formato numerico per valori nonzero; non prova il significato fisico.

Una [prova CPU delle transizioni WindowManager](S33_GUI_WindowManager_Transizioni_CPU_20261028.md) esegue anche il gestore originale con due descrittori e callback sintetici: sono osservabili deviazione e annullamento in condizioni specifiche. Non sono provati callback reali, ritorno dal debug o schermate fisiche.

I [wrapper diagnostici originali per gli eventi di ingresso](S33_GUI_Debug_Lifecycle_Risposte_CPU_20261028.md), con tabelle e filtri iniziali originali, restituiscono zero nei quattro casi CPU provati; passato separatamente all'interprete con tabella iniziale, zero non richiede il ripristino del precedente. La transizione completa e i filtri runtime rimangono da verificare.

La [prova di ingresso dal WindowManager](S33_GUI_Debug_Ingresso_Manager_CPU_20261028.md) esegue gestore, dispatcher `0x4403` e wrapper diagnostici originali nella stessa sequenza. I successivi eventi `0x4401`/`0x4405` e il disegno sono fixture: non dimostra una schermata inizializzata o visibile.

La [prova successiva dell'inizializzazione](S33_GUI_Debug_Inizializzazione_Manager_CPU_20261028.md) esegue anche `0x4405` e i callback diagnostici originali: l'indice ISO sintetico 6 richiede posizione 7 e il callback del tempo richiede il testo iniziale `AUTO`. Controlli, selezione, testo e disegno restano fixture.

La [prova con `0x4401` originale](S33_GUI_Debug_Apertura_4401_4405_CPU_20261028.md) osserva anche i flag e l'argomento nel descrittore; le chiamate di registrazione, i controlli e il disegno sono simulati.

La [prova successiva delle risorse](S33_GUI_Debug_Risorse_Parent_CPU_20261028.md) esegue l'iteratore originale e il collegamento del descrittore alle risorse: sei per tempo e due per ISO nelle condizioni sintetiche. Gli eventi ai singoli controlli restano simulati.

Una [prova dell'inoltro degli eventi](S33_GUI_Debug_Eventi_Risorse_CPU_20261028.md) esegue anche `0x16A944` e il dispatcher fino a ciascuna risorsa; la risoluzione e gli handler delle classi rimangono fixture.

Nella [prova CPU del setter iris](S33_GUI_Iride_Esiti_Setter_Prova_CPU_20261027.md) il wrapper restituisce 1 anche quando l'acquisizione simulata fallisce e lo stato resta invariato. Il [percorso statico di completamento](S33_Iride_Completamento_Handler_Evento_e_Byte_Stato.md) è stato analizzato separatamente; la mossa ottica non è eseguita nel banco.

## 2. Colore e Mono RAW Luminance

La proposta già registrata è [Mono RAW Luminance](S33_Mono_RAW_Luminance.md): ricostruire una luminanza dai campioni RAW, calibrando il sensore e conservando i contributi dei diversi filtri. È una proposta di elaborazione, non una modalità già disponibile o un sensore fisicamente monocromatico. Il CFA rimane fisico; disposizione, profondità, packing e qualità dei dati effettivi non sono ancora verificati. Un'eventuale uscita JPEG e il salvataggio RAW richiedono una pipeline funzionante, non solo una voce di menu.

La traccia RAW V1.1 identifica flag e una lunghezza richiesta, ma non prova un frame utilizzabile né il salvataggio su fotocamera: [analisi RAW](S33_HiddenMenu_RAW_Massimo_20261027.md). Le voci di `ChangeColorMenu` e un eventuale filtro B/N non costituiscono automaticamente Mono RAW Luminance. L’analisi statica di [EVMenu](S33_GUI_EVMenu_Valori_20261027.md) collega le opzioni di luminosità, vivacità e selezione colore a indici e scritture distinte, senza provarne l’effetto sull’immagine.

Un [marcatore nel percorso RAW](S33_Mono_RAW_Integrita_Buffer_20261027.md) può modificare fino a 32 bit in byte del buffer sotto condizioni specifiche; formato, capacità e raggiungibilità reale rimangono da verificare prima di usare i dati per la luminanza.

La [prova CPU del marcatore](S33_Mono_RAW_Marcatore_Prova_CPU_20261027.md) conferma la trasformazione su buffer sintetici nei quattro casi considerati, usando un modello DSP provvisorio, non validato sulla fotocamera.

L'[inventario locale del 28 ottobre](S33_Mono_RAW_Inventario_Locale_20261028.md) non ha trovato un frame RAW S33 con provenienza verificata nel perimetro censito; esistono esclusioni e non è un'analisi dei file negli archivi.

Una [prova CPU del pool e dei descrittori](S33_Mono_RAW_Pool_Descrittore_Prova_CPU_20261028.md) collega inizializzatore, coda e acquisizione con servizi sintetici. Il puntatore dati risultante non è dereferenziato: non prova un frame RAW né la capacità della RAM fisica.

## 3–4 e prossimi punti di verifica

Il terzo pulsante resta da decidere; il quarto è riservato alle impostazioni. Per procedere senza confondere GUI e controllo fotografico occorre verificare: identità e ordine fisici dei quattro tasti; recapito eventi e lifecycle dei sottomenu; contratto e persistenza dei controlli ISO/tempo e dei due stati ottici; disponibilità e formato dei campioni RAW, nonché un confronto della pipeline monocromatica. Le prove CPU con fixture restano separate da queste verifiche.

La [ricostruzione statica delle impostazioni](S33_GUI_Impostazioni_Suono_Routing_20261027.md) collega `GeneralSetupMenu` a destinazioni come `SetupMenu` e `SoundSettingMenu` e individua scritture condizionali per le scelte di suono. Non dimostra persistenza dopo il riavvio né associazione ai tasti fisici.

Nessuna modifica o installazione firmware, operazione hardware o scrittura SD è stata effettuata per questa mappa. I candidati restano **NON_INSTALLARE**.
