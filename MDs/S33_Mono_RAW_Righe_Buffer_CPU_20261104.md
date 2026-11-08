# Mono RAW: produzione per righe e limite del buffer — 2026-11-04

Il possibile buffer fotografico merita cautela: per il lavoro immagini tipo 1, `P+0x10` è usato nel percorso diagnostico CFA e in una preparazione che può precedere JPEG; non sono provati formato Bayer, durata, capacità o identità dei byte consumati dall'encoder. Un ramo CaptureImage separato collega staticamente il campo `descrittore+4` a un writer e alla successiva ricerca del descrittore: [CFA/JPEG](S33_RAW_CFA_IRP_e_JPEG_Catena_20261028.md), [buffer CaptureImage](S33_RAW_JPEG_Collegamento_Buffer_Statico_20261028.md). Non è identificato un punto sicuro per inserire il processore.

Per ridurre il fabbisogno di **uscita** del prototipo offline, `akeru_mono_raw_rows` in `AkeruOS/camera/mono_raw.c` elabora un intervallo di righe a partire dal frame sorgente completo. Usa le coordinate assolute per CFA e vicini, anche su righe dispari e confini delle strisce. L'output è compatto e non deve sovrapporsi a nessuna parte dell'input. Intervalli invalidi, overflow, campioni fuori range e puntatori invalidi vengono respinti prima delle scritture nei casi verificati. `akeru_mono_raw` conserva la precedente API e ora richiama la funzione per tutte le righe; il selettore colore continua a usare il percorso a frame intero.

Con geometria ipotetica 4208×3152, un frame LE16 occupa 26.527.232 byte: l'uscita di una riga ne occupa 8.416 anziché altri 26.527.232. **Il frame sorgente completo deve però restare accessibile e stabile**; la funzione attuale valida tutti i campioni a ogni chiamata, quindi molte chiamate comportano molte riletture e non costituiscono una soluzione prestazionale per la fotocamera. Non è verificata la disponibilità di memoria, la durata del frame o il collegamento a JPEG.

Verifiche:

- [Test host UBSan e GNU ARC700](../Risultati/GUI_S33/akeru_mono_raw_20261104T154936Z/verified_evidence.json): frame 5×5, partizione 1+2+2 con inizi dispari, risultato identico al frame intero; righe invalide, overflow e sovrapposizione rifiutati. La scansione integrale rifiuta anche un campione invalido fuori dalle righe richieste.
- [Tre ritagli reali del DSCo1012](../Risultati/Mono_RAW/rows_real_20261104T154937149792Z/evidence.json): confronto host 16×16, righe 1+3+5+7 contro elaborazione intera e riferimento floating point, input verificato invariato tramite SHA-256. Origine CFA RGGB, livelli e guadagni rimangono assunzioni; i bordi sono quelli del ritaglio, non necessariamente del frame intero.
- Equivalenza host/GNU col nucleo precedente e regressione pipeline colore host/GNU PASS; [scanner → colore/mono 8/8](../Risultati/GUI_S33/key_scanner_menu_color_cpu_20261104T154936465522Z/verified_evidence.json).

Nessuna modifica a RAW originali, firmware, GNU o hardware. Non sono dimostrati calibrazione, CFA fisico, prestazioni, buffer sul dispositivo, sincronizzazione o uscita JPEG. **NON_INSTALLARE**.

Riproduzione: `python3 Python_Trace_Scripts/s33_verify_akeru_mono_raw.py`; `python3 Python_Trace_Scripts/s33_verify_mono_rows_real.py`; `python3 Python_Trace_Scripts/s33_verify_key_scanner_color_pipeline_cpu.py`.
