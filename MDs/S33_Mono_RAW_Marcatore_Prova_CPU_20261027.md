# S33 V1.1 — Marcatore del buffer RAW candidato: prova CPU

27 ottobre 2026. La routine originale `0x28D5BC` è stata chiamata direttamente
in quattro scenari con memoria sintetica esplicitamente mappata; non è stato
eseguito il percorso di scatto. La [precedente analisi statica](S33_Mono_RAW_Integrita_Buffer_20261027.md)
identifica una chiamata condizionale con selettore 2 e dimensioni 4208 × 3152,
ma non dimostra che sia raggiunta né che il puntatore indichi dati RAW validi
sulla fotocamera.

Sono originali anche il codice del servizio di copia `0x128C20`, il prologo e
l'epilogo chiamati dalla routine e i 32 byte della tabella `0x35231C`, verificati
contro il dump storico. La copia non è stata sostituita con un servizio fittizio.
La memoria del buffer, gli argomenti, lo stack e il chiamante sono sintetici;
per `MULUDW` si usa il modello GNU DSP v7 sperimentale già presente, con
semantica provvisoria non validata sull'hardware. Il modello accetta qui il
prodotto 3152 × 4208 e registra il risultato `0x00CA6300`.

Il buffer mappato contiene 13.524.592 byte e l'offset sintetico del secondo
argomento è 16. È stato confrontato **ogni byte del buffer** con il risultato
atteso; i 32 byte potenzialmente interessati hanno passo 8416. I risultati:

| Selettore | Dati sintetici nelle posizioni | Byte cambiati | Ritorno |
|---|---|---:|---:|
| 2 | bit meno significativo opposto alla tabella | 32 | 0 |
| 2 | bit già uguale alla tabella | 0 | 0 |
| 2 | byte zero | 16 | 0 |
| 3 | bit già uguale alla tabella | 0 | 1 |

Nei tre casi con selettore 2 l'output coincide con la sostituzione del bit
meno significativo in ciascuna posizione con il valore corrispondente della
tabella originale. Lo stack è ripristinato in tutti i casi; il codice originale
mappato non risulta modificato. La prova confronta le scritture sull'intero
buffer, comprese tutte le posizioni diverse dalle 32 bersaglio: esse sono
rimaste uguali al termine della chiamata. Il confronto finale non rileva
eventuali scritture temporanee poi ripristinate, né prova l’assenza di altre
scritture fuori dal buffer o di letture fuori limite. Stack e area di stato
del chiamante sono distinti dal buffer e vengono usati dalla prova.

La prima esecuzione `marker_cpu_20261027T214620Z` è conservata come FAIL:
controllava erroneamente il prodotto atteso `0x00CA6400`; corretto l'assert
host in `0x00CA6300`, la prova completa è PASS. Non è stato modificato il
firmware per aggirare il simulatore.

Riproduzione: `python3 Python_Trace_Scripts/s33_verify_raw_marker_cpu.py`.
Risultati, log DSP, trace, hash, snapshot e casi:
`Risultati/HiddenMenu_RAW/marker_cpu_20261027T214622Z/`.

Questi risultati rafforzano la necessità di controllare l'integrità di un
futuro frame utilizzabile per Mono RAW Luminance, senza dimostrare che il
marcatore venga eseguito su un frame reale, quali campioni interessi o se il
buffer reale sia sufficiente. CFA, packing, durata, concorrenza, ordine di
esecuzione e salvataggio rimangono non verificati. **NON_INSTALLARE**.
