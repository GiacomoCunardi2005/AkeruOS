# Mono RAW Luminance — prime prove offline su frame S33

29 ottobre 2026. I file `RawsAnalysis/DSCo1003.raw` e `DSCo1012.raw` sono due raster 4208×3152 LE16. L'utente riferisce che i RAW sono stati prodotti con l'aggiornamento; hash firmware e condizioni degli scatti non sono ricavati dai file. Qui si applica per la prima volta il riferimento Mono RAW Luminance preesistente a due frame interi, offline su PC.

## Procedura

[`s33_mono_raw_offline.py`](../Python_Trace_Scripts/s33_mono_raw_offline.py) implementa con NumPy e OpenCV la stessa ricostruzione a vicini bilineari del [riferimento scalare](S33_Mono_RAW_Riferimento_Sintetico_20261028.md): ricostruzione di R/G/B a partire dai campioni della matrice CFA, matrice RGB lineare, poi luminanza con pesi `0.2126, 0.7152, 0.0722`. Si usano tutti i canali, non una desaturazione di un JPEG. Per un canale presente nel fotosito si usa il campione stesso; per quelli mancanti si mediano i vicini disponibili di quel colore, trattando i bordi senza campioni fittizi. L'output lineare non è sottoposto a clipping.

**Assunzioni provvisorie**, non calibrazioni misurate: RGGB come da intestazioni CFAi, nero 0 e bianco 4092 per ogni canale, matrice diagonale `diag(1.75, 1, 1.43)` derivata dai guadagni sperimentali usati in precedenza. Questa matrice non è una trasformazione misurata sensore→sRGB: il risultato è un proxy di luminanza, non luminanza colorimetrica calibrata. Non c'è correzione difetti o rumore. La presenza dei filtri CFA fisici non cambia: «puro» indica qui sviluppo RAW dedicato, non un sensore fisicamente monocromatico.

Il TIFF esporta la luminanza lineare come float32 per pixel; il JPEG è un'anteprima B/N 8 bit con limiti calcolati per immagine ai percentili 0,1 e 99,8 (campione ogni 8 pixel), ombre `x+0.16*x*(1-x)^2`, curva sRGB e qualità 98. Il TIFF lineare può contenere valori superiori a 1 e non è un JPEG né un'uscita calibrata. Gli script non modificano il RAW e richiedono una cartella di output nuova.

## Risultati e controlli

| RAW | Anteprima | TIFF lineare | Intervallo float32 |
|---|---|---|---|
| 1003 | [JPEG](../outputs/mono_raw_20261029/DSCo1003/mono_sperimentale.jpg) | [TIFF](../outputs/mono_raw_20261029/DSCo1003/luminanza_lineare_float32.tiff) | 0,01358–1,17520 |
| 1012 | [JPEG](../outputs/mono_raw_20261029/DSCo1012/mono_sperimentale.jpg) | [TIFF](../outputs/mono_raw_20261029/DSCo1012/luminanza_lineare_float32.tiff) | 0,01106–1,19050 |

Per ogni scatto sono stati verificati hash del RAW, dimensioni 4208×3152, decodifica TIFF float e JPEG monocromatico. Tre porzioni reali per scatto (angolo alto sinistro, interno, angolo basso destro), con confronto esclusi i bordi artificiali del ritaglio, concordano con il riferimento scalare con errore massimo inferiore a `1,49e-8`, compreso l'arrotondamento a float32. Le misure e gli hash degli output sono in [verifica.json](../outputs/mono_raw_20261029/verifica.json); [parametri 1003](../outputs/mono_raw_20261029/DSCo1003/report.json), [parametri 1012](../outputs/mono_raw_20261029/DSCo1012/report.json).

Sei test PASS: quattro del riferimento esistente e due del nuovo codice; il confronto usa dati sintetici non uniformi, bordi, quattro fasi Bayer e una matrice 3×3 non diagonale con elemento negativo, oltre a input invalidi. Comando: `python3 -m unittest discover -s tests -p 'test_s33_mono*' -v`. Il JPEG 1003 è stato anche ispezionato visivamente; non è un confronto quantitativo di qualità con il JPEG Nikon.

Questa prova dimostra solo elaborazione offline riproducibile e coerenza con il riferimento sui casi indicati. Non prova qualità relativa, calibrazione, tempo/memoria su ARC700, buffering, integrazione nello scatto, scrittura SD o il selettore della GUI. Per il dispositivo occorrono calibratura, verifica delle risorse e un'implementazione idonea alla pipeline originale. Nessun firmware, RAW originale o hardware modificato; **NON_INSTALLARE**.
