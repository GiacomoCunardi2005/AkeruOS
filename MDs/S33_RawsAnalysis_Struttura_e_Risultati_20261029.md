# Nikon S33 — struttura dei file in RawsAnalysis

Analisi offline del 29 ottobre 2026, su `RawsAnalysis/`: dieci coppie numerate 1003–1012, script e risultati storici. I file sono stati letti senza modificarli. L’utente ha successivamente riferito che i RAW sono stati prodotti con l’aggiornamento; i nomi e i byte da soli non identificano hash firmware, impostazioni o condizioni di ogni scatto. Approfondimento: [metadata e parametri JPEG](S33_RAW_Metadata_e_Parametri_JPEG_20261029.md).

## Novità rispetto alle prove precedenti

La [fattibilità RAW/JPEG del 28 ottobre](S33_RAW_Puro_e_JPEG_Fattibilita_20261028.md) aveva soltanto una richiesta di 26.527.232 byte ricavata dal firmware e non aveva verificato un frame reale. Qui ci sono dieci file `DSCo` effettivi di quella dimensione, con dati coerenti con 4208 × 3152 campioni little-endian a 16 bit; è una verifica del contenuto dei file, non della provenienza dal sensore o della purezza della catena. Il precedente [scatto SD](S33_RAW_Scatto_SD_20261028.md) riportava solo JPEG: non va confuso con le condizioni specifiche di acquisizione di questi file.

Il precedente [studio del dispatcher CFA](S33_RAW_CFA_IRP_Dispatch_e_Esiti_20261028.md) derivava il nome `CFAi` staticamente, senza osservare il file risultante su dispositivo. Qui esistono dieci coppie `CFAi`/`DSCo` con lo stesso numero; ogni payload `CFAi` coincide **byte per byte con i primi 13.263.616 byte** del rispettivo `DSCo`, esattamente metà dei suoi byte. Questo è più forte della sola corrispondenza del prefisso riportata in `RawsAnalysis/RAW_ANALISI/report.txt`, ma non identifica il percorso firmware che ha scritto i file né il motivo della lunghezza.

## Layout osservato

| File | Offset e dimensione | Interpretazione supportata |
|---|---|---|
| `DSCoNNNN.raw` | offset 0, 26.527.232 byte | 13.263.616 parole unsigned little-endian, interpretabili come 4208 × 3152; nessuna intestazione necessaria per questa geometria. |
| `CFAiNNNN.raw` | offset 0, 20.808 byte (`0x5148`) | Intestazione/metadata; il contenuto non è ancora decodificato completamente. |
| `CFAiNNNN.raw` | offset `0x5148`, 13.263.616 byte | Uguale all'inizio del `DSCo` omonimo; corrisponde a 6.631.808 parole a 16 bit, cioè 1.576 righe nella geometria proposta. Non basta chiamarlo un'immagine completa a 8 bit solo perché la lunghezza coincide con il numero di pixel. |

In tutti i dieci header, la word LE32 a `0xB0` vale `0x5148`, le due word LE16 a `0xB4` e `0xB6` valgono 4208 e 3152, e la stringa `RGGB` compare a `0xB8`, `0xC8`, `0xD8`. La corrispondenza è un forte indizio della geometria e dell'ordine CFA dichiarati dall'header; la posizione effettiva dei filtri e l'orientamento dell'immagine non sono stati calibrati indipendentemente. `awb_debug_info` e altre informazioni sono visibili nell'header 1003, ma struttura e significato dei campi non sono stati convalidati. Il riconoscimento generico `file` come eseguibile DOS è una falsa identificazione basata sui byte iniziali, non prova codice eseguibile.

Ogni `DSCo`, interpretato LE16, ha minimo 0 e massimo 4092; nessun campione supera 4095. La maggioranza è multipla di 4, ma esistono da 5.978 a 6.314 campioni non multipli di 4 per file. Questo supporta una rappresentazione entro 12 bit, non dimostra 12 bit effettivi indipendenti, linearità o assenza di modifiche.

**Aggiornamento:** il confronto successivo ha trovato la sequenza candidata del marcatore in tutte le 32 posizioni previste, in ciascuno dei dieci `DSCo`. Rimangono non provati il produttore effettivo e i bit precedenti: [metodo e controlli](S33_RAW_Reali_Marcatore_Confronto_20261029.md).

## Inventario e controlli integrali

Confronto completo dei payload, statistiche su tutte le parole e SHA-256 dei file letti. La colonna differenze confronta l'intero payload CFAi con i primi 13.263.616 byte DSCo; zero non significa uguaglianza con il DSCo intero.

| N. | SHA-256 CFAi | SHA-256 DSCo | Differenze | Campioni DSCo non multipli di 4 |
|---|---|---|---:|---:|
| 1003 | `a5cd75d9e0a0cde026a31041b85c9e10c923e874b6d913f384e46e52046bda67` | `538b6257f3c218c4939d97f3606449bbe2a5798277ee836a65468bb9c4c102d1` | 0 | 6222 |
| 1004 | `373ecd7d7ec97fa243d6c3a9c19b26d9493fc415c01a9ab365f1a65fac93ea10` | `34d08819ad385db493c62207149154d6ddc837f3ba4f7c29052139d9451706a9` | 0 | 6215 |
| 1005 | `9c61d0895fb47dac61f93c2f519ca39e1437d3c00efef12081e3c6fae314fb88` | `90585f73c13227f0cf554a25b95a2026964ef5553cc35742dc536309cdb1a406` | 0 | 6255 |
| 1006 | `fdcf93985c0f09166c95ed3067fa49bd37c390ece3b46144ff4766862bc85980` | `c6d3a4618ea07459def7786da16e8a848ba7c520ae8d4684c1cd70a4c564aa26` | 0 | 6179 |
| 1007 | `3f81c78c5237d22710cfb02d32d34680ea241b9322f4618dc3e40e111014553d` | `2609b0e072ecf6e4a1b80d5223a87f2f257db681940eb6f239eedab3473353ea` | 0 | 6079 |
| 1008 | `423cd8214a5186609cf1d310f2c99283db1fd80b516587620633fc8b42d38b93` | `fb32fb35272a1832c5b7729d68b011e5479c5744e1670061babb0da363d97f18` | 0 | 6084 |
| 1009 | `ad1e6a81276ad4dd7e4ea530157f826963e3e96438b6c94a6118d29921fb6867` | `d7d02fdc8bfde62ed843926cbf2eb037b2e9dd5f0c30138877364c82fca1e291` | 0 | 6214 |
| 1010 | `288938eb15d17123541763b4c387eca4df4e89382a3c4641726955c6c2234fb2` | `bf643c35888fac1ca8ee5337373edbf10a75ebfbed55793c23591170cd762820` | 0 | 5978 |
| 1011 | `9f64328f3af6c9ef09523cfd2d23758a9261076e4b783f9fd5969b15c5c3bf92` | `6c205a7abb004f1e10c4cb76cc58920a3f81c3b2d1a6f69504904bf189f4dec7` | 0 | 6314 |
| 1012 | `0c7328612445eaf5803b91023166a19ce53916440233a5d3c3f8943696887a85` | `314cc266a2224b38cfcfb3fcac0cfe5af89c483fa43e3309a8db535fe8e9b97f` | 0 | 6216 |

## Conversioni e limiti

`raw_sensor_forensics.py` e `RAW_ANALISI/` documentano l'analisi iniziale del 1003; le versioni `s33_raw_to_jpeg*.py` sviluppano ricette successive. V7/V8 leggono `DSCo1003.raw` come LE16 4208 × 3152, assumono nero 0 e bianco 4092, usano demosaic OpenCV con RGGB, bilanciamento sperimentale e matrici non calibrate; la correzione selettiva della vegetazione è estetica. Il monocromatico deriva da RGB demosaicizzato, non da un sensore monocromatico. V8 produce 15 varianti e V9.1 applica le ricette 02 Balanced/35% e 13 Combined/40% a tutti e dieci i `DSCo`. `S33_JPEG_V9_1/batch_report.csv` riporta 10 OK; il 29 ottobre tutte le 20 immagini 02/13 sono state decodificate interamente come JPEG 4208 × 3152. Questo verifica i file risultanti, non l'esattezza dei colori né la loro corrispondenza attuale al RAW: la cache V9.1 valida formato/dimensioni ma non confronta hash sorgente o ricetta. Le tavole AB hanno dimensioni differenti dai JPEG completi e la funzione di verifica cache le considera quindi invalide e le rigenera.

`DSCN1002.JPG` è un JPEG Nikon 4160 × 3120 con data EXIF della fotocamera; il nome diverso non dimostra che sia associato a uno dei RAW. `CFAi1003.raw.xmp` è un sidecar, non prova che i valori di sviluppo siano calibrazione del sensore. Nessun test di riproduzione colore con target, dark frame, orientamento fisico, buffer completo, stesso scatto RAW/JPEG, persistenza su camera o hardware è stato svolto in questa analisi. I candidati firmware restano **NON_INSTALLARE**.
