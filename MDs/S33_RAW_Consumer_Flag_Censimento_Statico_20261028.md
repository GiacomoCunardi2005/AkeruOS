# S33 V1.1 — consumer diretti candidati del flag RAW

28 ottobre 2026. La lista esplorativa preesistente, ottenuta da disassemblaggio lineare dei blocchi 0–10, contiene 14 chiamate dirette candidate al getter `0x28D48C`. Le 14 finestre sono state riancorate ai byte del MainCode storico e le condizioni riportate sotto verificate con GNU. È un censimento delimitato delle chiamate **presenti nella lista**, non della totalità delle chiamate possibili o dei percorsi eseguiti.

Il valore `2` **non è equivalente a `1`**: alcuni consumer controllano il valore esatto, altri lo zero. Le conseguenze seguenti sono condizionali all'esecuzione dei rispettivi frammenti e ai loro ulteriori controlli.

| Chiamata getter | Controllo e conseguenza statica per flag 2 |
| --- | --- |
| `1B91EC` | `==1`: salta il ramo che può chiamare il marcatore `28D5BC`. |
| `1B9292`, `1B933A` | `!=0`: non blocca i due rispettivi writer; servono i puntatori e altri requisiti. |
| `1B990A` | `!=0`: non blocca il writer a `1B994A`, soggetto a puntatore e calcoli del ramo. |
| `1BAA28`, `1BC09C`, `1BC7CC` | `==1` e selettore `==3`: con 2 si sceglie `17D458` anziché `17D62C`; natura e conseguenze dei due helper non sono state caratterizzate qui. |
| `1BC51E`, `1BCC70` | `==1`: con 2 si salta il loop che può chiamare il writer rispettivamente a `1BC55A` e `1BCCAE`. |
| `7CF134`, `7CF1FA` | `==1`: con 2 vengono scelte rispettivamente le stringhe `SaveCFAonTake:Off` e `Take12BitCCDRaw:Off`, identiche alla scelta per 0. L'etichetta non prova lo stato delle altre funzioni. |
| `7CF4F8`, `7CF7F0` | confronto con zero e inversione normalizzata: con 2 la callback passa 0 al setter. La seconda aggiorna anche il selettore dopo un'ulteriore lettura. |
| `7CF810` | `!=0`: la callback prepara selettore 3; il valore effettivo dipende dalla lettura dopo setter e servizi, non è assunto invariato. |

La [prova CPU separata](S33_RAW_Flag_Marcatore_Writer_Sequenza_CPU_20261028.md) verifica un percorso delimitato con flag e servizi sintetici, non sostituisce l'analisi degli altri consumer. L'asimmetria qui individuata rende **infondata una raccomandazione di impostare 2**: può cambiare selezione del percorso e indicazione nel menu e non prova che il buffer risultante sia RAW puro o che sia salvato con il JPEG dello stesso scatto.

Riproduzione: `python3 Python_Trace_Scripts/s33_verify_raw_flag_consumers_static.py`. [Evidenza](../Risultati/HiddenMenu_RAW/flag_consumers_static_20261028T143651Z/evidence.json), [finestre GNU](../Risultati/HiddenMenu_RAW/flag_consumers_static_20261028T143651Z/gnu_windows.txt). La lista usata è [branch_candidates.json](../Risultati/HiddenMenu_RAW/20261027_static/branch_candidates.json); il verificatore confronta le finestre con il dump storico e controlla 42 istruzioni, oltre a pool e stringhe. Non esclude chiamate indirette, altri payload o accessi diretti/alias RAM; non prova raggiungibilità, effetti delle funzioni chiamate o comportamento hardware. Nessun firmware modificato, fotocamera o SD; **NON_INSTALLARE**.
