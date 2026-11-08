# S33 V1.1 — distanza fra buffer e writer RAW

28 ottobre 2026. Analisi statica e quattro casi CPU sintetici, senza accesso a fotocamera o SD. **NON_INSTALLARE**.

Nel ramo del pool interno inizializzato con selettore `word[0x366E34]` diverso da 1 e 2, la distanza fra gli inizi dei nodi è **13.263.872 byte**, mentre il writer diagnostico con selettore RAW `word[0x366F90] == 3` richiede **26.527.232 byte**. Questi sono selettori distinti: la voce 12 bit imposta il secondo a 3, non è stata trovata qui una prova che imposti anche il primo o quale valore questo abbia durante lo scatto. Non è quindi dimostrato che i due rami coesistano realmente sulla fotocamera.

Se coesistono, se il pool interno è stato effettivamente inizializzato con tale distanza e sono presenti due nodi consecutivi, la lettura richiesta dal writer del primo nodo si estende per **13.263.360 byte oltre l'inizio del secondo**. Il marcatore, nelle condizioni già verificate e con `r16=0`, opera su 32 posizioni: la prima è 256 byte prima del secondo nodo e le altre 31 sono fra **8.160 e 260.640 byte dopo** il suo inizio. Può modificarne i bit bassi; non è dimostrato che la regione sia RAM valida, che il secondo nodo sia attivo o che il servizio di scrittura legga realmente tutti i byte. Non è una prova di corruzione hardware né di capacità del buffer. Con un solo nodo l'intervallo oltre il primo stride può appartenere ad altra parte della regione o superarla; qui non viene determinato.

## Origine della distanza e selettori

Per il ramo interno, `0x18ED60` con primo argomento zero chiama `0x141CE8`, che legge il selettore del pool tramite `0x141CE0`. Nel caso diverso da 1 e 2, `0x141D3E..0x141D66` calcola `align_up(4208 × 3152, 1024) = 0xCA6400`; passa il risultato come `r1` a `0x18E4B4`. L'inizializzatore usa quel valore per calcolare sia il numero di nodi sia la distanza fra indirizzi `elemento+8` successivi. Se il pool è già attivo il ramo iniziale salta l'inizializzazione: non si può dedurre la distanza effettiva dal selettore attuale senza conoscere il momento dell'inizializzazione.

Il selettore pool è letto da `0x366E34`; `0x141CC4` lo scrive. Il corpo `0xCBAF0` lo azzera a `0xCBB0E`, poi sotto altre guardie può impostarlo a 1 o 2 a `0xCBB5E`. Non è stata verificata la raggiungibilità di queste guardie per una particolare fotografia. I valori 1 e 2 scelgono rispettivamente 0x6400000 e 0x5200000 byte: entrambi sono superiori a 2N, ma questo non prova capacità, allocazione o accessibilità reali.

Il rapporto [RAW massimo](S33_HiddenMenu_RAW_Massimo_20261027.md) documenta il diverso selettore `0x366F90` e il writer; [integrità](S33_Mono_RAW_Integrita_Buffer_20261027.md) documenta condizioni e posizioni del marcatore. `0x1B8F24` trasmette un argomento del chiamante a `0x18ED60`: la prova di questo banco forza direttamente il ramo a primo argomento zero e non dimostra il valore durante lo scatto normale. La modalità con memoria esterna e i servizi fisici non sono coperti.

## Verifica riproducibile

`python3 Python_Trace_Scripts/s33_verify_raw_pool_stride_cpu.py` — quattro casi **PASS**, selettore pool 0, 1, 2 e 3; verifica gli indirizzi di due nodi e l'associazione del primo al descrittore. [Casi](../Risultati/Mono_RAW/pool_stride_cpu_20261028T143452Z/cases.json), [finestre GNU](../Risultati/Mono_RAW/pool_stride_cpu_20261028T143452Z/gnu_windows.txt), [fixture](../Risultati/Mono_RAW/pool_stride_cpu_20261028T143452Z/fixture_patches.json).

Le routine originali `0x18ED60 → 0x141CE8 → 0x18E4B4` e gli helper selezionati girano nel simulatore GNU con modello DSP sperimentale; pool inattivo iniziale, selettori, regione, dimensione 256 MiB, riserve, due descrittori, servizi, code e metadati sono sintetici. Solo l'inizio della regione è mappato; nessun dato pixel viene letto. Il caso iniziale fallito per globale sintetico non mappato resta conservato, seguito dal PASS. La prova non esegue il writer, lo scatto, il JPEG o l'hardware e non convalida una mappa fisica. Nessun firmware originale o GNU modificato.
