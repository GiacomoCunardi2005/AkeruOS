# GUI S33: collegamenti e prove mancanti — 5 novembre 2026

Questa ricognizione confronta il codice corrente con rapporti e risultati del 4 novembre; non ripete le prove e non verifica la fotocamera. Gli indirizzi indicati nei rapporti sono riferiti al campione firmware V1.1. Il prototipo rimane **NON_INSTALLARE**.

## Dal pulsante al menu

Il [modello corrente](../AkeruOS/ui/menu.c) assegna gli eventi di pressione `580`, `700`, `2180`, `2700` agli slot logici 1–4. In MAIN aprono rispettivamente esposizione, colore, nessuna azione e richiesta impostazioni. I corrispondenti eventi di rilascio non ripetono l'azione. Il terzo slot resta intenzionalmente vuoto.

Nel [banco snapshot](S33_GUI_Snapshot_Modello_Quattro_Tasti_CPU_20261104.md) il lettore e lo scanner originali convertono ingressi MMIO sintetici in quegli eventi, e il dispatcher li inoltra a un callback sintetico verso il modello: bit 12→580, 7→700, 8→2180, 13→2700. L'ordine dei quattro tasti fisici, la polarità e le connessioni elettriche non sono misurati. Il banco impone stato, consegna e callback: non prova un'integrazione registrata nel firmware.

Le [etichette](S33_GUI_Navigazione_Etichette_Testo_CPU_20261104.md) attraversano parte della catena originale solo dopo costruzione di record e invocazione da parte del banco; i glifi sono registrati da uno stub. Non c'è ancora una schermata visibile sulla camera, né sono dimostrate proprietà del buffer, clipping sicuro, lingue o lifecycle.

## Valori e comportamenti

| Funzione | Cosa è stato osservato | Cosa manca per la funzione richiesta |
|---|---|---|
| ISO | [Lista V1.1 e setter](S33_GUI_ISO_Mappa_Lista_Completa_CPU_20261104.md): Auto e 22 voci 50–3200 scrivono parametri software in CPU emulata; Exit conserva lo stato. Il convertitore accetta anche 6400, assente dalla lista. | Navigazione, applicazione effettiva nel percorso di scatto, interazione AE, guadagno e persistenza. Non assumere che ogni valore sia utilizzabile fisicamente. |
| f/ | [Sottomenu modello e setter](S33_GUI_Sottomenu_Iride_Modello_CPU_20261104.md): le scelte producono richieste per gli stati software 1 e 9; sotto fixture il setter può accettarle o rifiutarle. | Associazione degli stati a posizioni fisiche, zoom, valori f/ e movimento. Le specifiche citate nel [rapporto snapshot](S33_GUI_Snapshot_Modello_Quattro_Tasti_CPU_20261104.md) descrivono un filtro ND a due passi equivalenti a grandangolo: non dimostrano un diaframma continuo. |
| Tempo | [Schermata diagnostica](S33_GUI_Menu_Scanner_Tempo_Sequenza_CPU_20261104.md): da valore imposto 120, direzione e conferma scrivono 121000 o 119000 in due campi software. | Unità, corrispondenza con il tempo di scatto, percorso reale AE/otturatore e ritorno dalla schermata. Non etichettare quei numeri come secondi o frazioni di secondo. |
| Colore / mono | [Selettore e righe](S33_GUI_Scanner_Colore_Mono_Righe_CPU_20261104.md): un callback sintetico sceglie la modalità; il banco passa uno snapshot al processore su frame 2×2. Standard lascia l'output invariato, mono lo riempie. | Collegamento automatico a cattura e JPEG, proprietà e durata buffer, sincronizzazione, prestazioni, formato e calibrazione. Il percorso standard richiede che il chiamante continui il percorso colore originale. |
| Impostazioni | [Manager](S33_GUI_Impostazioni_Apertura_Occupato_CPU_20261104.md): il banco traduce la richiesta in apertura di `GeneralSetupMenu`; una guardia occupata la rifiuta. | Integrazione e lifecycle effettivi, indicazione o recupero dal rifiuto, navigazione e ritorno. Il secondo tentativo nel banco è iniettato esplicitamente. |

Il [riferimento monocromatico](S33_Mono_RAW_Frame_Reali_Riferimento_20261029.md) usa tutti i canali del mosaico per una stima lineare della luminanza; «puro» significa sviluppo RAW dedicato, non rimozione del filtro colore fisico. RGGB, livelli e guadagni rimangono assunti sperimentali. Il [processore a righe](S33_Mono_RAW_Righe_Buffer_CPU_20261104.md) richiede comunque un frame completo stabile e lo rivalida a ogni chiamata: non è ancora una soluzione di memoria o prestazioni dimostrata per la camera.

## Ordine delle prossime prove

1. Stabilire un ingresso e un lifecycle reali per il menu: registrazione callback, proprietà della coda, apertura, rifiuto e ritorno, poi rendering completo con limiti del buffer verificati. Non promuovere associazioni logiche a tasti fisici senza misure.
2. Seguire ciascun valore software verso il consumatore effettivo dello scatto, distinguendo le sovrascritture AE e l'esito delle richieste. Per tempo e iride ricavare unità e corrispondenze prima di mostrare valori fotografici.
3. Individuare e verificare per il mono origine, formato, proprietà e durata del frame e ingresso encoder, quindi calibrazione e tempi; lo snapshot di modalità deve essere coerente per tutto lo scatto. Mantenere il percorso colore originale quando selezionato.
4. Integrare il menu impostazioni e verificarne il ritorno; lasciare il terzo slot senza funzione finché non viene deciso.

Questi passi non costituiscono autorizzazione a installare firmware, scrivere su SD o operare sulla fotocamera. Le prove citate sono statiche o CPU con fixture, non risultati hardware.
