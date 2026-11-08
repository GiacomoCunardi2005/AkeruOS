# S33 — GUI a quattro tasti: collegamenti, impostazioni e prossime verifiche

29 ottobre 2026. Obiettivo dell'utente: quattro pulsanti alla sinistra del display, dall'alto: **1 esposizione (ISO, f/ e tempo); 2 colore standard / Mono RAW Luminance; 3 da decidere; 4 impostazioni**. Questo documento è uno studio e un contratto di lavoro, non una modifica firmware installabile. Le analisi di indirizzi riguardano il dump Nikon V1.1, SHA-256 `1d34e990a8f99019ffa53ca5de785399df863e942739a667ceb314ec6ce62a39`; non trasferire indirizzi a versioni diverse senza confronto dei byte.

## Dalla pressione al menu

Il manuale chiama i pulsanti laterali flexible buttons 1–4 in ordine dall'alto. Per la GUI il percorso candidato V1.1, condizionato da registrazioni, filtri e stato, è lettura snapshot `0x2D62D8` → callback `0x1406D0` → normalizzazione `0x16EC38`/`0x16E6E0` → stato tasti `0x16F86C`/`0x16F72C` → evento e coda `0x17BC7C` → estrazione `0x17BD4C` → dispatch `0x169E1C` → oggetto corrente e controllo classe `0x15`. Una lettura sintetica rieseguita oggi esercita gran parte di questa catena con MMIO modellati; il collegamento lettore→callback e consegna evento→controllo sono imposti dal banco. [Dettagli e casi](S33_GUI_MMIO_Snapshot_Quattro_Slot_CPU_20261028.md), [nuova esecuzione](../Risultati/GUI_S33/mmio_snapshot_four_routes_cpu_20261028T232019Z/).

| Slot software | Evento stato logico 1 / 0 | Tasto logico | Callback classe 0x15 | Ruolo desiderato se l'ordine fisico fosse confermato |
|---:|---|---:|---|---|
| 0 | `0x580 / 0x581` | 11 | `0x631878` | esposizione |
| 1 | `0x700 / 0x701` | 14 | `0x63195C` | colore / mono |
| 2 | `0x2180 / 0x2181` | 67 | `0x631A38` | da decidere |
| 3 | `0x2700 / 0x2701` | 78 | `0x631B14` | impostazioni |

Questa ultima colonna è una **proposta**, non una mappatura misurata dei pulsanti fisici. Il confronto con il manuale suggerisce una corrispondenza per gli slot 1–3 in uno specifico `CaptureMenu`, ma la live view ha una tabella propria e una discrepanza non risolta. L'ordine, la polarità, il routing in live view, i filtri e le condizioni reali restano da verificare: [confronto manuale](S33_GUI_Confronto_Manuale_Slot_20261027.md), [snapshot e bit](S33_GUI_Quattro_Slot_Snapshot_e_Coda_20261027.md). Il pulsante fisico non può essere identificato solo dal nome diagnostico `KeyMenu` o dall'evento sintetico.

## Nuova prova: terzo slot senza azione

Uno slot con destinazione zero non è automaticamente inattivo: nel banco precedente `0x2180` raggiunge il controllo, che ritorna 0 e permette al dispatcher di ricadere su `CaptureMenu`, il quale richiede `AutoSceneLiveView` (`0x87`). Per sapere se esiste una guardia riutilizzabile ho esteso quel banco senza toccare i payload originali: stesso record sintetico nello slot 2, destinazione zero, flag a offset +24 pari rispettivamente a 0, 1 e 2. Stesso evento e stessa configurazione del banco; le varianti differiscono per quel flag.

| Flag record sintetico | Selezioni registrate | Aperture richieste | Ritorno dispatcher |
|---:|---:|---|---:|
| 0 | 1 | 1: `0x87`, argomento 0, per ricaduta sul padre | 1 |
| 1 (bit 0) | 0 | 0 | 1 |
| 2 (bit 1) | 0 | 0 | 1 |

Tre casi PASS, 4.964 istruzioni nel modello: il controllo originale, con bit 0 o bit 1, ritorna 1 prima della selezione, e in questo contesto il dispatcher non raggiunge l'apertura del padre. Controllati coda di stato 1 e 0, conteggi servizi, destinazione nel caso base e stack. L'evento stato 0 è estratto ma non inoltrato. [Verificatore](../Python_Trace_Scripts/s33_verify_gui_third_slot_guard_cpu.py), [casi](../Risultati/GUI_S33/third_slot_guard_cpu_20261028T232051Z/cases.json), [evidenza e fixture](../Risultati/GUI_S33/third_slot_guard_cpu_20261028T232051Z/verified_evidence.json). Il simulatore DSP v7 è sperimentale, evento e record sono sintetici e i servizi includono filtro, selezione, apertura e sincronizzazione fixture. Il banco consegna esplicitamente l'evento estratto al dispatcher. Questo **non prova** che i flag persistano, che il menu reale carichi quel record, che l'icona sia nascosta, o che il tasto fisico sia disabilitato. I flag originali possono essere aggiornati durante il ciclo del menu: [aggiornamento record](S33_GUI_CaptureMenu_Aggiornamento_Record_e_Slot_CPU_20261027.md).

## 1. Menu esposizione: valori e limiti

| Scelta | Effetto software osservato | Cosa manca |
|---|---|---|
| ISO | Diagnostica `0x3F`; callback `0x7D25B0` → `0xD03B8` scrive indice a `0x365787` e `0x17C320` lo copia a `0x367BC8` e converte nella halfword `0x37FBF2`. La lista originale contiene Auto e ISO 50–3200; la conversione comprende anche 6400 assente da quella lista. | Non prova range supportato o guadagno fisico. Gli indici e il valore sono software; AE e concorrenza possono intervenire. |
| Tempo | Diagnostica `0x3E`; conferma legge `0x899AD0`, moltiplica per 1000 con aritmetica 32 bit e scrive `0x365788` e `0x37FBF4`. Zero è mostrato come Auto nella prova di formato. | Unità fisiche, intervallo raggiungibile, persistenza fino allo scatto ed effetto sul sensore non sono dimostrati. |
| f/ | Pannello diagnostico iris richiede stato 1 o 9; il setter può rifiutare e la scritta viene richiesta prima dell'esito. Il manuale descrive filtro ND e due passi f/3.3 e f/6.6 in grandangolo. | Mapping degli stati a valori ottici, movimento, completamento e arbitraggio AE non provati; non presumere diaframma continuo o che il solo ritorno del wrapper confermi il movimento. |

La selezione ISO 125 produce nel banco indice 6 e valore 125; Exit preserva i campi. La conferma torna però al menu diagnostico originale `0x36`, non al sottomenu proposto: [prova ISO](S33_GUI_ISO_Tasto_Conferma_Ritorno_CPU_20261028.md), [riesecuzione](../Risultati/GUI_S33/key_iso_confirm_transition_cpu_20261028T232019Z/). In una sequenza sintetica il tempo confermato 121.000 può essere cambiato da un setter e poi ripristinato dalla routine `0xCA654`, nell'ordine imposto dal banco: [dettagli](S33_GUI_Tempo_Conferma_Sovrascrittura_Ripristino_CPU_20261028.md), [riesecuzione](../Risultati/GUI_S33/time_confirm_overwrite_restore_cpu_20261028T232019Z/). Nessuna di queste prove dimostra l'ordine reale durante lo scatto. I valori diagnostici e i limiti del manuale sono dati diversi: [tabella ISO/tempo](S33_GUI_Debug_Valori_ISO_Tempo_CPU_20261027.md), [iride](S33_GUI_Iride_Pannello_Esito_CPU_20261028.md).

Il banco [sottomenu esposizione](S33_GUI_Sottomenu_Esposizione_Instradamento_CPU_20261028.md), [rieseguito](../Risultati/GUI_S33/exposure_submenu_routes_cpu_20261028T232019Z/), prova le richieste verso ISO e tempo nella stessa lista sintetica. Non crea il menu effettivo, non collega f/, e non realizza il ritorno. Per una futura implementazione servono lifecycle del nuovo oggetto, visualizzazione e rientro, verifica di selezione/conferma/annullo e comportamento dei valori durante AE e acquisizione; non basta cambiare una destinazione.

## 2. Colore standard e monocromatico

`ChangeColorMenu` (`0xBB`) contiene scelte originali di luminosità, vivacità e colore; non implementa Mono RAW Luminance. Per esempio EVMenu modo 0 può scrivere 2000, 1000, 0, -1000 o -2000 a `0xC8EC52`; modo 1 converte indici in codici 10, 6, 0, 5, 9 e scrive `0x367C06`; modo 2 scrive un indice a `0xC8EB5A` e, dopo ulteriori chiamate, un valore a `0x3681DC`. Sono percorsi statici condizionali: l'unità EV, l'effetto sull'immagine e la persistenza non sono dimostrati. [Valori EVMenu](S33_GUI_EVMenu_Valori_20261027.md), [voci colore](S33_GUI_ChangeColorMenu_Voci_20261027.md).

L'utente ha riferito che le dieci coppie in `RawsAnalysis/` provengono dall'aggiornamento. DSCo dà un raster completo compatibile con 4208×3152 LE16; il payload CFAi corrisponde solo alla prima metà del rispettivo DSCo. L'header riporta RGGB ma black level, matrice sensore, purezza e interpretazione fisica restano da verificare. [Struttura e verifiche](S33_RawsAnalysis_Struttura_e_Risultati_20261029.md). Rispetto alle note precedenti ora esistono file RAW da studiare: le affermazioni storiche «nessun frame» nelle fonti del 27–28 ottobre precedono questa informazione.

Mono RAW Luminance è la pipeline precedentemente richiesta: ricostruire luminanza dai dati CFA con livelli e risposta colore calibrati prima della resa finale. Il [riferimento Python](S33_Mono_RAW_Riferimento_Sintetico_20261028.md) è testato su mosaici sintetici, non implementato in camera. Il filtro CFA fisico rimane sul sensore: una pipeline software non produce la sensibilità di un sensore fisicamente monocromatico. Il marcatore RAW può alterare bit in condizioni studiate, ma non è stabilita la causa dei campioni non multipli di 4 dei file reali. Servono confronto su RAW reali, calibrazione, scelta della pipeline e dimostrazione su frame/risorse disponibili prima di collegare un selettore GUI alla cattura.

## 3. Da decidere; 4. impostazioni

Il terzo slot resta senza funzione definita; la guardia sopra è una possibilità da studiare, non una scelta irrevocabile o una patch. Per il quarto un banco su lista sintetica richiede `GeneralSetupMenu` (`0xB7`, argomento 1); apertura, ritorno e accessibilità dalla schermata reale non sono provati. La statica del menu impostazioni individua routing verso suono e setup e scritture condizionali, non la persistenza: [routing impostazioni](S33_GUI_Impostazioni_Suono_Routing_20261027.md).

## Prossimi passi per il risultato richiesto

1. Collegare in un banco il controllo classe con gestione del menu e del ritorno, includendo ISO, tempo, una destinazione f/ appropriata e i casi annulla; evitare il ritorno fisso alla diagnostica.
2. Seguire quando e come la scelta confermata arriva alla sequenza originale di acquisizione, incluse sovrascritture, limiti, concorrenza e fallimenti dei setter; distinguere valore scelto, applicato e fisico.
3. Definire e verificare su PC la pipeline mono usando i RAW disponibili e calibrazione esplicita; stabilire poi buffer, costi, integrazione di scatto e JPEG sulla macchina senza presumere RAM libera.
4. Provare lifecycle e fallback dei quattro slot, inclusi flag aggiornati dal menu; verificare infine l'associazione fisica di ciascun pulsante e le transizioni su hardware solo con ambito e recupero adeguati.

Nessuna GUI completa, firmware modificato o installazione risultano da questo studio. Nessuna nuova interazione con fotocamera/SD. **NON_INSTALLARE**.
