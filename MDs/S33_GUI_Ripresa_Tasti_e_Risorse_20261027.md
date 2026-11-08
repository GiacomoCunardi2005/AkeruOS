# S33 — GUI di ripresa: tasti, schermate e risorse

27 ottobre 2026. Studio offline della GUI originale Nikon S33 V1.1 per capire
come cambiare menu e destinazioni dei tasti, mantenendo i servizi Nikon.
Nessuna modifica firmware, operazione su fotocamera o SD.

## Schermate individuate

| ID oggetto | Nome interno | Descrittore | Risorse dichiarate |
| ---: | --- | ---: | ---: |
| `0x01` | `CaptureLiveview` | `0x7833CC` | 90 |
| `0x02` | `CaptureMenu` | `0x9802AC` | 3 |
| `0x9B` | `ImageMode` | `0x9814B8` | 10 |
| `0x9D` | `LiveViewHotKeyMenu` | `0x7846F4` | 3 |

Gli ID sono verificati nella tabella di oggetti `0x3F5900` e nei descrittori;
risorse e dati sono confrontati con MainCode. I nomi interni aiutano a
identificare gli oggetti, ma non identificano da soli l'aspetto visibile o
la funzione esatta di ciascuna icona.

## Dal tasto alla schermata

Il [backend pulsanti](S33_Pulsanti_Hardware_Backend_Ingresso.md) collega le
sorgenti al sottosistema eventi. Per gli ID logici sotto `0x61`, il codice
emette `tasto << 7` per lo stato nonzero e aggiunge bit 0 per l'altro stato.
La corrispondenza fra numero logico e tasto fisico resta da verificare.

Continuazione: i [comandi diagnostici dei tasti](S33_GUI_Tasti_Comandi_Eventi_20261027.md)
associano `KeyMenu` all'evento `0x700` e documentano anche direzioni e OK;
questa associazione tramite script non identifica l'interruttore fisico.

La tabella `CaptureLiveview` a `0x7833EC` contiene queste associazioni:

| Evento | Tasto logico | Callback | Risultato staticamente individuato |
| ---: | ---: | ---: | --- |
| `0x0080` / `0x0081` | 1 | `0x654FE8` / `0x655B68` | Percorso S1 e rilascio; identificazione fisica inferenziale |
| `0x0100` | 2 | `0x654CD4` | Percorso S2 verso `CaptureImage` ID `0x04`; identificazione fisica inferenziale |
| `0x0180` | 3 | `0x655F88` | In un ramo chiede `VideoLiveview` ID `0x7E`; altri rami e guardie presenti |
| `0x0600` | 12 | `0x654330` | In rami distinti chiede `LensCtrlMenu` ID `0x4C` o `ReviewState` ID `0x5E` |
| `0x0700` | 14 | `0x65426C` | In base alla modalità chiede `CaptureMenu` ID `0x02` oppure `ImageMode` ID `0x9B` |
| `0x0480`, `0x0500`, `0x0580`, `0x0880` | 9, 10, 11, 17 | `0x65440C` | Handler condiviso con numerosi rami di modalità; azione non ancora attribuita globalmente |

Questi sono collegamenti del firmware, non prove che un dato pulsante fisico
apra sempre quella schermata. In particolare i percorsi di scatto, video e
revisione hanno guardie e side effect propri.

## Prova CPU del tasto logico 14

`0x65426C`, handler di `0x0700`, controlla gli stati dei tasti logici 7–10,
alcune guardie e la modalità restituita da `0xCAD30`. Dopo le condizioni
preliminari:

- modalità `0x46` o `0x0A` → richiesta `0x1453E4(0x02,0)`;
- altra modalità testata `0x2C` → `0x1453E4(0x9B,0)`;
- modalità `0x38` con stato restituito da `0xCAD28` uguale a 7 o 8 → nessuna
  richiesta di apertura nel percorso testato;
- un tasto 7–10 attivo o le guardie simulate attive possono impedire l'apertura.

Il [verificatore](../Python_Trace_Scripts/s33_verify_gui_liveview_key14.py)
esegue **24 scenari**, metà direttamente nell'handler e metà tramite il
dispatcher originale `0x169F60` sulla tabella originale `0x7833EC`, evento
`0x0700`. **PASS**, 4.227 istruzioni, stack conservato: stesso risultato per
entrambe le vie nei casi verificati. Gli accessor di tasti, modalità, guardie
e apertura sono nove fixture dichiarate; `0x1453E4` registra gli argomenti,
non crea una finestra. Il filtro del wrapper `0x6524F4`, WindowMgr, la coda e
l'hardware non sono eseguiti. Gli stati 7–10 vengono tenuti fissi per scenario,
quindi non si verificano cambi fra il controllo iniziale e le letture successive.

Questo è un punto concreto in cui studiare una possibile rimappatura futura:
la destinazione dipende da modalità e guardie, quindi cambiare una costante
senza capire il contesto non equivalrebbe a rimappare universalmente un tasto.

## Tabelle di risorse per i menu

`CaptureMenu` e `LiveViewHotKeyMenu` usano risorse di classe `0x15` con
puntatore a una sequenza di record consecutivi da **28 byte**. Verificati i
byte dei seguenti esempi:

| Risorsa | Oggetto | Tabella | Record |
| ---: | --- | ---: | ---: |
| `0x9801C0` | CaptureMenu | `0x98016C` | 3 |
| `0x980268` | CaptureMenu | `0x9801F8` | 4 |
| `0x981218` | ImageMode | `0x9811C4` | 3 |
| `0x9812C0` | ImageMode | `0x981250` | 4 |
| `0x784608` | LiveViewHotKeyMenu | `0x784598` | 4 |
| `0x7846B0` | LiveViewHotKeyMenu | `0x784640` | 4 |

Ogni record contiene campi numerici, inclusi tre halfword iniziali e parole a
offset 12, 16, 20 e 24. Il codice `0x7CB1B4` usa record di passo 28 e
confronta il campo a offset 20 per decidere come aggiornare un elemento.
**Il significato completo di questi campi e il collegamento alle etichette
visibili non sono ancora dimostrati.** Non assumere che una parola numerica
sia necessariamente l'ID del menu di destinazione.

I rettangoli delle risorse sono coordinate interne del firmware: non abbiamo
misurato una conversione diretta in pixel del display fisico. Gli elementi
grafici potrebbero usare risorse e tabelle differenti dalle stringhe di testo
dell'HiddenMenu.

## Prove e prossimi passi

- [Risultato CPU e limiti](../Risultati/GUI_S33/liveview_key14_20261027T112823Z/verified_evidence.json),
  [scenari](../Risultati/GUI_S33/liveview_key14_20261027T112823Z/cases.json),
  [disassemblaggio](../Risultati/GUI_S33/liveview_key14_20261027T112823Z/gnu_verified.txt).
- [Inventario delle risorse](../Risultati/GUI_S33/resources_20261027T112847Z/resources.json),
  [script](../Python_Trace_Scripts/s33_inventory_gui_capture_resources.py).
- [Scatto S1/S2](S33_Shutter_Due_Stadi_S1_S2.md),
  [ingresso pulsanti](S33_Pulsanti_Hardware_Backend_Ingresso.md),
  [catena schermo](S33_Schermo_Catena_Uscita_Display.md).

Per proseguire occorre collegare il produttore fisico del tasto logico 14,
seguire il wrapper `CaptureLiveview` e WindowMgr fino all'apertura effettiva,
ricostruire selezione/icone delle risorse classe `0x15`, poi studiare un
singolo cambio di destinazione in un banco offline. La persistenza su hardware
e il recupero non sono stati verificati; candidati esistenti NON_INSTALLARE.
# Seguito: il wrapper e il filtro sono stati successivamente studiati in [S33_GUI_Wrapper_Filtro_Menu_20261027.md](S33_GUI_Wrapper_Filtro_Menu_20261027.md).

