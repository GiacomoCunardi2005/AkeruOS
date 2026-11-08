# S33 V1.1 — byte iniziali e valore iride zero (2026-10-31)

## Immagine di caricamento

Nel blocco 1 estratto, confrontato byte per byte con `DUMPS/MainCode.dmp`, i quattro byte a `0x3663A4` e i 1184 byte a `0x37FBD0` sono zero; tra questi ultimi rientrano `0x38003D` e `0x38003E`. Sono byte dell'immagine, non un'osservazione dello stato dopo l'avvio. Non dimostrano che questi siano i valori effettivi durante lo scatto, né che zero significhi Auto o RAM disponibile. Non è stato individuato un inizializzatore completo dei due byte; la sola ricerca dei riferimenti diretti non esclude alias o copie indirette.

## Prova CPU con fixture

`python3 Python_Trace_Scripts/s33_verify_iris_claim_async_cpu.py --exposure-zero` verifica i byte contro il dump e ripete cinque scenari. Nel primo il test imposta stato precedente 9, valore desiderato 0, puntatore globale nullo, risorse disponibili e assenza di busy; entra nel frammento originale `0xFDC9E`, richiama `0xF7568`, poi entra in `0xF78BE`. La sequenza è imposta dal test, con servizi e MMIO simulati, e non prova che venga eseguita così dal firmware in condizioni naturali.

Risultato: il valore 0 viene copiato fino alla richiesta, lo stato osservato diventa 0 e viene registrato un post verso `0x235AE4`; il frammento restituisce 1. Questo dimostra il comportamento del percorso provato con queste fixture, non l'accettazione fisica dell'iride né il completamento della richiesta. Non usare 0 come codice Auto senza prova ulteriore.

Evidenze: `Risultati/GUI_S33/iris_exposure_zero_cpu_20261031T205759781835Z/` (5 casi PASS, trace, snapshot e fixture); regressione della tabella sintetica `Risultati/GUI_S33/iris_exposure_table_cpu_20261031T205753557055Z/` (5 casi PASS). Il dump è controllato tramite hash dal verificatore. Nessuna operazione su fotocamera o firmware originale.

Aggiornamento 2026-10-31: [ordine originale condizionato](S33_GUI_Iride_Ordine_Originale_Statico_20261031.md): un percorso originale è compatibile con calcolo → copia → successiva applicazione, mentre una chiamata intermedia con selettore 1 salta il ramo iride. La prova zero resta con fixture e sequenza imposta.
