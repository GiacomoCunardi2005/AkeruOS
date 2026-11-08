# Profilo di emulazione dal dump hardware e primo disegno con il percorso grafico Nikon originale

6 novembre 2026. Fase 3 (completata nella parte raggiungibile), fase 4 (primo profilo) e primo assaggio della fase 5 del piano GUI (`goal.txt`). Collegato da [catena grafica](S33_GUI_Catena_Grafica_Testo_da_Dump_20261106.md), [coda messaggi](S33_GUI_Coda_Messaggi_WindowMgr_da_Dump_20261106.md) e [stato GUI](S33_GUI_Stato_Reale_da_Dump_Hardware_20261106.md). Nessun firmware creato, dump originale intatto (hash controllato prima e dopo), nessun accesso alla fotocamera. Certezza: **A** osservato ed eseguito, **B** dedotto, **C** ipotesi.

## Il profilo (fase 4, primo passo)

`Python_Trace_Scripts/s33_verify_dump_profile_gui.py`: costruisce un ELF con la **RAM reale del dump** (`[0x100, 0x0104074C)`, SHA-256 `c91888b2…6107`, copia di lavoro) e un piccolo probe ARC700, e lo esegue nel simulatore GNU in container (come gli altri probe del progetto). Il simulatore richiede flag ARC700 e un segmento RW di stack; senza di essi si ferma con «size zero».

- **Prova di base (PASS):** il codice originale Nikon su RAM reale restituisce la finestra attiva `0x783AE8`, il contesto di disegno `0x3E8950` e lo schermo **640×480**: gli stessi valori ricavati a mano dal dump. Nessuna fixture. **A**. Evidenza: `Risultati/Runtime_Kernel/Dump_Profile_GUI/20261106T175113013063Z/`.
- Classificazione dei dati, come da piano: stato reale verificato (puntatori kernel, TCB, tabelle: usato), stato momentaneo (coda messaggi, task corrente: usato con cautela), hardware non emulato (MMIO, interrupt, controller display: non mappato, il simulatore si ferma se lo tocca).

## Il disegno originale (`--draw X Y`)

Si chiama `0x186D08` con rettangolo `(X,Y,300,60)`, stringa "AKERU", colore `0x00FFFFFF`, flags 0. Con il simulatore di base si ferma a `0x3342B4` (istruzione DSP `muludw`, segnale 4, 473.725 istruzioni). Con il **motore sperimentale con DSP** del progetto (hash verificato come negli altri probe GUI) il disegno **arriva in fondo** (uscita 0, ritorno 1). Il motore segnala `provisional=1` per `muludw`: la semantica DSP è provvisoria, quindi le coordinate dei glifi dipendono da quell'ipotesi (**B**).

Albero di chiamate osservato nella traccia reale: `0x186D08` → contesto `0x20E320`, schermo `0x20DBC8`, clip `0x20D7BC`/`0x20D860` → pre-disegno `0x23EA4C` (`0x23E854`, `0x23E8D4`, `0x23E784` → setter `0x23ABB8`, `0x23ABCC`, `0x23AD04`, `0x23AD10`) → colore `0x23E7D8` (`0x23EA28`, `0x23ABA4`) → `0x186C40` → `0x186780` → `0x14C768` → `0x16C624` → **motore font** `0x1EB3B8` (bind del font, già noto) → … → copia dei glifi. **A**.

## Dove finiscono i pixel (risposta alla fase 3)

- **Copia dei glifi:** ciclo a `0x2C9050–0x2C9060`: per ogni byte sorgente non nullo `stb` nel buffer, destinazione incrementata di 1. Il pixel è quindi **1 byte (indice di palette)** e **0 = trasparente**. **A**.
- **Piano di destinazione:** in **RAM alta, fuori dal dump**: primo pixel a `0x0F68B39E`, ultimo a `0x0F68DC05` per il disegno in `(20,30)`. Spostando X di +80 l'indirizzo cresce di 80; spostando Y di +100 cresce di **32000**: **passo di riga 320 byte**. **A**.
- **Valori scritti:** `1`, `2`, `35`, `161` (indici di palette; il significato dei colori non è decodificato). **A**/**C**.
- **Aspetto:** il testo appare sulle righe **alternate** (una riga sì e una no) e a destra del piano (colonne 212–319, con la «U» che esce dal bordo e rientra a sinistra). Il motivo non è chiarito: potrebbe essere un'organizzazione per campi (interlacciata), una scala 2× della riga, oppure l'effetto della semantica provvisoria di `muludw` sulla posizione. **C**. Immagine: `Risultati/Runtime_Kernel/Dump_Profile_GUI/20261106T175219121807Z//draw_AKERU.png`, mappa ASCII: `Risultati/Runtime_Kernel/Dump_Profile_GUI/20261106T175219121807Z//ascii.txt`.
- **Base del piano e aggiornamento del display:** non ancora identificati; il piano è in una regione che il dump non copre.

## Limiti

- RAM alta (piano pixel) non catturata: il profilo parte da zeri lì; per una schermata completa serve un secondo dump che includa quella regione (decisione della fase 6, ora motivata: **sì, serve un puntatore verificato a quella zona**, in particolare la base del piano e la palette).
- `muludw` provvisorio; MMIO, interrupt, scheduler e controller display non emulati; istante unico non atomico.
- Fase 5 completa (schermata AkeruOS con apertura, selezione e ritorno) non eseguita: l'integrazione con il sistema finestre Nikon non è stata fatta.

**Prossimo:** (1) capire l'interlacciamento e la posizione orizzontale (leggere `0x186780`/`0x16C624` e il motore font); (2) trovare la base del piano OSD e la palette (potrebbe richiedere un dump della regione `0x0F600000–0x0F700000`, con consenso esplicito); (3) agganciare una finestra AkeruOS al dispatcher `0x169E1C` in questo profilo. Nessuna modifica al firmware della S33.


**Correzione (stessa data):** il «passo di riga 320» di questo rapporto è sbagliato. Il piano ha **640 byte per riga** e `y` conta mezze righe; le «righe alternate» erano un effetto di quel passo. Vedi [prima schermata AkeruOS](S33_GUI_Prima_Schermata_AkeruOS_e_Decisione_Dump_20261106.md).

Prima schermata AkeruOS e decisione sul dump: [dettaglio](S33_GUI_Prima_Schermata_AkeruOS_e_Decisione_Dump_20261106.md).
