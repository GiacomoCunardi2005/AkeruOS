# Etichette del modello GUI AkeruOS

Il 4 novembre 2026 è stata aggiunta `akeru_menu_label`: per ogni schermata e slot logico 1–4 restituisce un'etichetta statica, oppure NULL per uno slot vuoto o un ingresso non valido. Le etichette accompagnano il [modello di navigazione](../AkeruOS/ui/menu.c); non disegnano sul display.

| Schermata | Slot 1 | Slot 2 | Slot 3 | Slot 4 |
|---|---|---|---|---|
| Principale | Esposizione | Colore / Mono | — | Impostazioni |
| Esposizione | Indietro | ISO | Apertura | Altro |
| Colore | Indietro | Colore | Mono RAW | — |
| Altro | Indietro | Tempo | Flash | — |
| Flash | Indietro | Acceso | Spento | — |
| Apertura | Indietro | Posizione A | Posizione B | — |

Le posizioni A e B corrispondono alle azioni software degli stati 1 e 9, rispettivamente; **non** assegnano valori f/ né attestano il movimento del filtro. Le stringhe sono separate dal modello di navigazione, per non cambiare la disposizione delle sezioni nei banchi che usano soltanto la navigazione.

Il test controlla tutte le 24 etichette, slot vuoti e ingressi invalidi, oltre alle azioni di navigazione: [host e GNU ARC700 PASS](../Risultati/GUI_S33/akeru_menu_model_20261104T161358Z/verified_evidence.json). Regressioni separate: [snapshot → menu → iride 14/14](../Risultati/GUI_S33/key_snapshot_menu_iris_cpu_20261104T161323216865Z/verified_evidence.json), [scanner → colore 8/8](../Risultati/GUI_S33/key_scanner_menu_color_cpu_20261104T161331680826Z/verified_evidence.json). Queste regressioni usano il modello di navigazione, non visualizzano le nuove etichette.

Mancano il collegamento ai record e al rendering Nikon, verifica di lingua/font e disposizione sullo schermo, lifecycle, tasti fisici e applicazione completa delle impostazioni. La posizione del terzo tasto principale resta vuota. Nessuna prova sulla fotocamera; **NON_INSTALLARE**.
