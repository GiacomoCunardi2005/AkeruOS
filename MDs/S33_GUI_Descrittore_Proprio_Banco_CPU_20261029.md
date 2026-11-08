# S33 V1.1 — modello C tramite descrittore sintetico

Il 29 ottobre 2026 ho ripetuto la prova dispatcher→modello usando un descrittore sintetico in RAM di laboratorio, anziché sostituire le istruzioni del callback originale `CaptureMenu` `0x7CAFE8`. Il descrittore copia i 28 byte originali `0x9802AC` e sostituisce il solo puntatore callback a offset `+12` con il ponte verso il modello C. Il banco predispone quel descrittore come corrente e pone a zero il controllo attivo. L'ID nel descrittore copiato resta 2: non è stata registrata una nuova identità di finestra e non è una collocazione RAM fisica.

Generatore tasto logico e coda originali → record estratto e consegnato **dal banco** a `0x169E1C` → dispatcher originale `0x169D78` → callback del descrittore sintetico → `akeru_menu_event` compilato ARC700. **12 casi PASS**, uno per ogni schermata modello/tasto logico, con controparti stato 0, 24 ingressi al ponte e al modello, controllo di record, azioni, schermate e stack; 14.490 istruzioni. Il test controlla anche che i primi 8 byte del callback originale nella copia siano invariati. [Casi](../Risultati/GUI_S33/synthetic_descriptor_menu_cpu_20261028T233512Z/cases.json), [differenza del descrittore](../Risultati/GUI_S33/synthetic_descriptor_menu_cpu_20261028T233512Z/descriptor_change.json), [manifest e traccia](../Risultati/GUI_S33/synthetic_descriptor_menu_cpu_20261028T233512Z/verified_evidence.json), [fixture](../Risultati/GUI_S33/synthetic_descriptor_menu_cpu_20261028T233512Z/fixture_patches.json). Ripetizione: `make -C AkeruOS menu-descriptor-model-verify`.

## Tentativo di apertura del descrittore

Ho anche provato a far aprire il descrittore da `0x145180` anziché predisporlo come corrente. Entrambi i tentativi sono **FAIL** e sono conservati:

- [233455Z](../Risultati/GUI_S33/synthetic_open_menu_cpu_20261028T233455Z/): con i riferimenti alle risorse originali ancora presenti, il lifecycle della lista legge una cella non mappata `0xC8EC7D`.
- [233502Z](../Risultati/GUI_S33/synthetic_open_menu_cpu_20261028T233502Z/): con conteggio e puntatore delle risorse azzerati nella copia sintetica, il percorso prosegue ma si ferma sulla lettura non modellata `0x0FEB4070` a `0x20C12C`.

[Script del tentativo](../Python_Trace_Scripts/s33_verify_gui_synthetic_open_menu_cpu.py). Non è dimostrato che i valori reali di quelle celle o l'assenza di risorse siano validi; i fallimenti non sono prova di guasto sulla fotocamera. Non è stata forzata una riuscita con valori arbitrari.

La prova PASS stabilisce il solo recapito tramite descrittore già corrente nelle condizioni sintetiche: non registra una nuova finestra, non prova apertura, lifecycle, risorse, rendering, scheduler o controllo attivo reale. Tasti, RAM e filtri sono sintetici o fixture, e le azioni del modello non applicano impostazioni. Restano da verificare identità e posizione del nuovo oggetto, allocazione, backend e mapping fisico. Nessun firmware originale, camera o SD modificati; **NON_INSTALLARE**.
