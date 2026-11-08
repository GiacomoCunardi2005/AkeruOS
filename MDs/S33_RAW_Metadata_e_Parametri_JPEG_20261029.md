# S33 — decodifica dei RAW e parametri JPEG

Studio del 29 ottobre 2026 su `RawsAnalysis/`. L'utente riferisce che i RAW sono stati fatti con l'aggiornamento; questa è un'informazione di provenienza fornita dall'utente. I file da soli non identificano con certezza l'hash del firmware installato, la voce di menu, né le condizioni del singolo scatto. Le evidenze sono file locali e analisi offline, senza nuove operazioni sulla fotocamera.

## Struttura e campioni

Dieci coppie 1003–1012: ogni `DSCo` è un raster di 26.527.232 byte interpretabile come 4208×3152 campioni unsigned LE16, all'offset zero. Ogni `CFAi` ha 20.808 byte di intestazione più 13.263.616 byte identici alla prima metà del relativo DSCo; i restanti dati del DSCo non sono nel CFAi. Confronto integrale e hash: [rapporto strutturale](S33_RawsAnalysis_Struttura_e_Risultati_20261029.md). Il dimezzamento è osservato, la causa non è ancora provata.

I valori dei dieci DSCo sono tutti tra 0 e 4092; nessuno supera 4095. I campioni non multipli di quattro, circa 6.000 per file su 13.263.616, impediscono di sostenere che tutti siano semplicemente valori di 10 bit moltiplicati per quattro. Non dimostrano da soli 12 bit utili né che la differenza sia dovuta al marcatore firmware. Le statistiche complete, inclusi percentile, numero di valori 4092 e hash, sono in [misure.csv](../outputs/raws_analysis_20261029/misure.csv); il valore 4092 non è un livello di saturazione calibrato.

## Intestazione CFAi: campi osservati

Offset rispetto all'inizio del file; i numeri sono little-endian dove indicato. Le seguenti geometrie e stringhe sono state verificate in tutte le dieci intestazioni.

| Offset | Dato osservato | Interpretazione e confidenza |
|---|---|---|
| `0x0000` | `iq_debug_str_sunny10` | Nome leggibile applicando `byte & 0x7f` ai caratteri con bit alto impostato. È un'etichetta, non prova una scena o un bilanciamento «sunny». |
| `0x0034`, `0x0099` | `Q12205` | Stringa ottenuta con lo stesso mascheramento; significato non identificato. |
| `0x0050` | `ZTH508001748` | Stringa ASCII comune a tutti gli header; possibile identificativo, ruolo non verificato. |
| `0x007c` | `raw_img_info_sunny9` | Etichetta mascherata come sopra. |
| `0x00b0` | `0x00005148` LE32 = 20808 | Coincide esattamente con l'inizio del payload. |
| `0x00b4`, `0x00b6` | `0x1070`, `0x0c50` LE16 = 4208, 3152 | Dimensioni coerenti con DSCo; non dimostrano l'area effettivamente utile. |
| `0x00b8`, `0x00c8`, `0x00d8` | `RGGB` | Indicazione testuale della disposizione CFA; orientamento fisico e convenzioni di demosaic non verificati con target. |
| `0x00c0`, `0x00d0` | `20 10 10 0c 28 00 20 00` | Record ripetuto, significato delle singole unità non stabilito. |
| `0x00e0–0x02df` | 256 valori LE16, monotoni da 0 a 4092 | Tabella identica nei dieci header; [tabella completa](../outputs/raws_analysis_20261029/tabella_header_00e0.csv). Compatibile con una tabella di trasformazione, ma non è dimostrato cosa indicizzi o se venga usata per questi dati. |
| `0x0305` | `end_str_raw_sunny9` | Etichetta mascherata; non identifica da sola la fine di tutte le informazioni. |
| `0x0ef4` | `awb_debug_info` | Etichetta ASCII di un blocco diagnostico; molti byte dell'area variano tra scatti. |
| `0x0f04` | LE16: 64, 64, 16, 16, 4176, 3120 | Numeri stabili nel blocco AWB; sembrano geometrie ma origine e funzioni non sono dimostrate. |
| `0x0f20` | LE16: 4208, 3152, 0, 0, 2, 2 | Numeri stabili nel blocco AWB; i primi due coincidono con la geometria del raster. |
| `0x3fe8` | `end_str_sunny10` | Etichetta mascherata; ulteriori dati non nulli seguono. |

Il mascheramento `& 0x7f` rende leggibili queste etichette perché i loro byte hanno il bit 7 impostato; non è la decodifica generale dell'intero header. Confrontando tutti i 20.808 byte delle dieci intestazioni, 3.725 posizioni assumono più di un valore. Esiste informazione variabile per scatto, ma senza una struttura o un riscontro non è corretto attribuirla a tempo, ISO, diaframma, guadagni o temperatura colore. ExifTool 13.55 non riconosce il formato CFAi.

## Sidecar XMP e JPEG della fotocamera

`CFAi1003.raw.xmp` è un sidecar darktable riferito a CFAi1003, con `DateTimeOriginal=2026:10:28 16:04:47.000`, valutazione 1 e 11 voci di storia abilitate: rawprepare, demosaic, colorin, colorout, gamma, temperature, highlights, channelmixerrgb, exposure, flip e sigmoid. Le voci sono impostazioni di elaborazione del sidecar, non EXIF estratto con certezza dall'header RAW; origine e attendibilità della data e interpretazione dei parametri binari di versione darktable non sono verificate. Non attribuirle automaticamente ai JPEG Python.

`DSCN1002.JPG` ha EXIF Nikon COOLPIX S33 V1.1, data camera `2026:10:28 16:04:36`, 4160×3120, 1/640 s, f/3.3, ISO 125, focale 4,1 mm, esposizione e bilanciamento automatici, flash non scattato, sRGB e qualità Fine. È un JPEG di numero diverso: questi parametri sono suoi e non dimostrano i valori dei RAW 1003–1012 o la versione dell'aggiornamento che li ha prodotti.

Ulteriori campi di quel JPEG: misurazione multizona, compensazione 0, modalità scena automatica nel MakerNote, contrasto/saturazione/nitidezza normali, riduzione rumore e HDR indicati come disattivati, VR-Auto e punto AF centrale. Il campo ISO EXIF è 125, mentre il campo ISO separato del MakerNote è 0 e la selezione ISO è Auto: non sono valori intercambiabili. Il JPEG è 8 bit, campionamento colore 4:2:2. Queste etichette sono quelle lette da ExifTool, non una verifica indipendente dei valori fisici.

## Ricette JPEG effettivamente usate

Le 20 immagini `S33_JPEG_V9_1/DSCoNNNN_02.jpg` e `_13.jpg` sono generate dalla V8 tramite `s33_raw_batch_v91.py`. Il codice attuale definisce questo procedimento:

1. Lettura LE16, geometria 4208×3152, nero assunto 0 e bianco 4092; divisione per 4092 e clipping, conversione a 16 bit; `cv2.COLOR_BayerRGGB2RGB`. La resa non costituisce una calibrazione dell'orientamento CFA o del profilo sensore.
2. Bilanciamento fisso RGB `(1.75, 1.0, 1.43)`, seguito da clipping a `[0,1]`. La luminanza `0.2126 R + 0.7152 G + 0.0722 B` viene campionata ogni 8 pixel in entrambe le direzioni; limiti tonali ai percentili 0,1 e 99,8, calcolati separatamente per ogni foto e comuni alle due ricette. I limiti ricostruiti sono in `misure.csv`; coincidono con quelli salvati nel report V8 per 1003.
3. Ricetta **02**: matrice identità (Balanced), correzione selettiva cromatica 0,35. Ricetta **13**: matrice Combined `[[0.985,0.025,0],[0.010,0.985,0.015],[0,0.030,0.970]]`, correzione 0,40. Il selettore opera in HSV sui toni scuri e saturi vicini a 325°, ruotando parzialmente la tinta verso 135° e riducendo leggermente la saturazione: è una scelta estetica, non una classificazione scientifica della vegetazione.
4. Normalizzazione coi limiti, clipping, sollevamento ombre `x + 0.16*x*(1-x)^2`, curva sRGB standard, quantizzazione 8 bit; Pillow salva JPEG qualità 98, subsampling 0 (4:4:4). Le tavole comparative sono JPEG separati ridimensionati; 02 e 13 sono le immagini complete.

I parametri sono quelli degli script, non impostazioni recuperate dalla macchina; nero, bianco, WB e matrici non sono calibrati. I limiti tonali calcolati nella verifica attuale sono ricostruzioni dal RAW, non metadati conservati nel JPEG. La cache V9.1 controlla dimensioni/formato senza vincolare il contenuto all'hash o alla ricetta, quindi la verifica di corrispondenza va fatta a parte. [Verifica di ricostruzione](../outputs/raws_analysis_20261029/verifica_jpeg.csv): tutti i 20 JPEG rigenerati in memoria dalle fonti attuali coincidono byte per byte con quelli già presenti (20/20); nessun JPEG originale sostituito. Verifica con NumPy 2.5.4 e OpenCV 5.0.0; altri ambienti potrebbero produrre differenze di codifica o arrotondamento.

ExifTool sul campione `DSCo1003_02.jpg` mostra JFIF, 4208×3152, 8 bit e 4:4:4, senza campi EXIF di scatto riconosciuti; la ricetta sopra proviene dal codice e dalla ricostruzione verificata, non da metadati completi incorporati nel JPEG. L'assenza è verificata su questo campione, non generalizzata a file non controllati.

I risultati non stabiliscono esposizione, ISO e diaframma dei singoli RAW, calibrazione colore o funzionamento del firmware su altri scatti. Non modificare o installare candidati sulla base di questa analisi; stato precedente NON_INSTALLARE invariato.
