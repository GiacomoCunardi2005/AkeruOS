# S33 V1.1 — percorso di ritorno da CaptureMenu, prova CPU

Il 27 ottobre 2026 una prova offline in GNU ARC700 ha eseguito il wrapper originale `CaptureMenu` `0x7CAFE8`, entrambi i dispatcher originali `0x169F60`, gli handler `0x7CB0F8`, `0x20E814` e `0x20E940`. L'evento logico `0x480` è stato **iniettato direttamente** nel wrapper, con contesto e filtro sintetici. Il firmware originale e `MainCode.dmp` sono stati confrontati nelle finestre e tabelle usate.

Nel caso non filtrato con guardie sintetiche permissive il percorso traduce `0x480` nell'evento `0x2180`. Prima della richiesta di apertura chiama quattro volte il servizio `0x17C074`, con argomenti `(0, evento, 0)` ed eventi `0x81`, `0x80`, `0x101`, `0x100` in tale ordine. Quindi chiede `0x1453E4(0x87, 0)`; la tabella oggetti associa l'ID `0x87` al nome interno **AutoSceneLiveView**. Il servizio di apertura e quello dei quattro eventi sono registratori del banco: le loro azioni reali e l'effettivo ritorno alla visualizzazione non sono osservati.

| Caso sintetico | Risultato nel banco |
| --- | --- |
| Filtro senza `0x480`, guardie permissive | Quattro chiamate di evento e una richiesta `(0x87, 0)` |
| Filtro con `0x480` | Nessuna chiamata ai due servizi |
| `0xCB4A8` = 2, oppure `0xCAD5C` = 3 | Nessuna richiesta |
| `0x17BE18` = 1, oppure `0x16F920` = 42 | Nessuna richiesta |
| Prima chiamata `0x1453FC` = 1, oppure seconda = `0x7E` | Nessuna richiesta, dopo una chiamata alla fixture `0x1564C0` |

Sono **8 scenari PASS** e lo stack è conservato. Le guardie sono nominate per indirizzo, non se ne inferisce il significato operativo. Le due letture di `0x1453FC` sono controllabili separatamente; nelle altre fixture le letture ripetute restituiscono lo stesso valore. Il ramo in cui la seconda lettura di `0xCAD5C` vale 2 non è stato eseguito. La descrizione statica della rotta e delle sue guardie è nel [rapporto precedente](S33_GUI_CaptureMenu_Left_20261027.md).

Per progettare un sottomenu, questa è una rotta originale di **richiesta condizionale**, con servizi preliminari e filtri, non la prova di una semplice funzione di chiusura che possa essere riutilizzata indipendentemente. Non dimostra che il tasto fisico generi `0x480`, che l'evento venga consegnato, né che il WindowMgr chiuda o apra effettivamente una finestra; non esegue grafica, coda, scheduler o fotocamera. Otto servizi sono sostituiti soltanto nelle copie laboratorio; fixture e patch sono elencate nell'evidenza. Nessuna modifica a firmware o hardware; **NON_INSTALLARE**.

- [Verificatore riproducibile](../Python_Trace_Scripts/s33_verify_gui_capturemenu_left_cpu.py)
- [Casi](../Risultati/GUI_S33/capturemenu_left_cpu_20261027T214629Z/cases.json), [risultato con hash e limiti](../Risultati/GUI_S33/capturemenu_left_cpu_20261027T214629Z/verified_evidence.json), [servizi fixture](../Risultati/GUI_S33/capturemenu_left_cpu_20261027T214629Z/fixture_patches.json), [finestre GNU](../Risultati/GUI_S33/capturemenu_left_cpu_20261027T214629Z/gnu_windows.txt) e [traccia](../Risultati/GUI_S33/capturemenu_left_cpu_20261027T214629Z/cases.trace).
