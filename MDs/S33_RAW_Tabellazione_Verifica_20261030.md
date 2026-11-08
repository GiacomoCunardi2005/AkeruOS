# S33 — struttura RAW e verifica della tabella dell'intestazione

Il 30 ottobre 2026 sono state riesaminate offline le dieci coppie 1003–1012 in `RawsAnalysis/`. La provenienza dall'aggiornamento è riferita dall'utente; i file non identificano l'hash del firmware. La struttura già acquisita e i parametri JPEG sono conservati nei rapporti [struttura](S33_RawsAnalysis_Struttura_e_Risultati_20261029.md) e [metadati e JPEG](S33_RAW_Metadata_e_Parametri_JPEG_20261029.md).

## Struttura da conservare

* Ogni `DSCo`: 26.527.232 byte, interpretabili come 4208×3152 parole unsigned little-endian da 16 bit, senza intestazione necessaria per tale interpretazione.
* Ogni `CFAi`: intestazione di 20.808 byte (`0x5148`), seguita da 13.263.616 byte uguali ai primi 13.263.616 byte del DSCo con lo stesso numero: 1.576 righe LE16, metà del raster proposto. Il confronto integrale e gli hash sono nel precedente rapporto, non si tratta di un frame completo equivalente a 8 bit. La causa della differenza di lunghezza rimane ignota.
* L'intestazione dichiara 4208×3152 e `RGGB`; l'orientamento fisico non è stato calibrato. Nell'header compaiono anche `awb_debug_info`, identificativo ASCII comune ed etichette con bit alto impostato. Sono state individuate 3.725 posizioni dell'header variabili fra le dieci foto, senza prova che codifichino specifici parametri di esposizione o bilanciamento.
* Tutti i DSCo hanno minimo 0 e massimo 4092; presentano fra 5.978 e 6.314 campioni non multipli di quattro. Né la risoluzione effettiva del sensore né un livello di saturazione calibrato si deducono da questi numeri. Una sequenza compatibile con un marcatore è presente nella seconda metà dei DSCo, come documentato in [confronto marcatore](S33_RAW_Reali_Marcatore_Confronto_20261029.md); questo non dimostra il percorso che ha scritto i file né consente di ricostruire i bit precedenti.

## Nuova verifica della tabella a 0x00e0

Tutte le intestazioni contengono esattamente la stessa tabella di 256 valori LE16 a `0x00e0..0x02df`: strettamente crescenti da 0 a 4092, con salti non uniformi multipli di quattro da 4 a 60. [Valori e differenze](../outputs/raws_header_lut_20261030/lut.csv).

Per ciascun DSCo abbiamo contato tutte le 13.263.616 parole che coincidono con uno dei 256 valori della tabella. Le percentuali variano dal **32,3953%** (1007) al **90,1181%** (1004); per il 1003 sono **60,8232%**. I restanti valori, quindi dal 9,8819% al 67,6047% dei campioni, **non** appartengono alla tabella. Ogni file presenta da 1.193 a 1.995 valori distinti, più dei 256 della tabella. Questo esclude che l'intero DSCo sia semplicemente una sequenza di valori scelti da quella tabella senza ulteriori trasformazioni. Non esclude interpolazioni, elaborazioni successive o un ruolo diverso per la tabella: origine, indice e impiego effettivo rimangono ignoti. Le percentuali dipendono dalla distribuzione dei pixel e non misurano qualità o accuratezza dell'immagine.

[Misure complete e SHA-256 di tutti gli input](../outputs/raws_header_lut_20261030/verification.csv); confronto della tabella e conteggi integrali eseguiti con NumPy, senza modificare i RAW.

## Parametri dei JPEG

L'unico JPEG Nikon presente, `DSCN1002.JPG`, registra 1/640 s, f/3.3, ISO EXIF 125, focale 4,1 mm, WB e esposizione automatici, flash non scattato, JPEG Fine sRGB 4160×3120. Ha numero diverso dalle coppie RAW: questi valori non si possono trasferire ai singoli scatti RAW. Il MakerNote contiene un campo ISO separato uguale a 0 e ISO Selection Auto, da non confondere con ISO EXIF 125.

I 20 JPEG 02/13 sono sviluppi locali V8/V9.1: nero assunto 0, bianco 4092, demosaic OpenCV RGGB, WB sperimentale RGB 1,75/1/1,43, soglie tonali adattate allo scatto, curva sRGB, qualità JPEG 98 e 4:4:4. La ricetta 02 usa matrice identità e correzione selettiva 0,35; la 13 una matrice Combined e correzione 0,40. La ricostruzione precedente ha verificato 20/20 file byte per byte; dettagli, matrice e limiti in [metadati e JPEG](S33_RAW_Metadata_e_Parametri_JPEG_20261029.md). Queste sono ricette del computer, non parametri JPEG della fotocamera; non sono calibrate.

ISO, tempo, diaframma e parametri JPEG dei singoli RAW restano non decifrati. Nessuna nuova prova su hardware; candidati **NON_INSTALLARE**.
