# S33 — immagini JPEG incorporate nel firmware

Il suggerimento di esaminare le immagini è utile: nel firmware originale V1.1 sono state individuate **116 sequenze JPEG decodificabili** mediante una ricerca semplice dei marcatori. Tra queste ci sono **18 immagini da 160×96** che raffigurano scene illustrate: ritratto, spiaggia, fiore, cibo, paesaggio, fuochi d'artificio e altre.

La [tavola delle 18 immagini](../Risultati/GUI_S33/embedded_jpeg_20261027T113806Z/160x96_contact.png) riporta sotto ogni figura l'offset nel file firmware. Sembrano candidate interessanti per illustrare scene o opzioni fotografiche: è un'interpretazione visiva, non una conferma del loro uso in uno specifico menu.

## Dove cercare il caricamento

**Seguito:** è stata identificata una tabella di offset e lunghezze e una routine che la consulta; vedi [indice JPEG delle scene](S33_GUI_Indice_JPEG_Scene_20261027.md).

La prima immagine della tavola si trova all'offset `0x3A49D0` nel contenitore e appartiene al payload 2, con indirizzo di caricamento candidato `0x62CBD0`. Per le prime quattro immagini non sono stati trovati riferimenti letterali little-endian diretti a questi indirizzi nei payload verificati. Questa ricerca non esclude offset relativi, tabelle indicizzate, puntatori calcolati o caricamenti tramite altri formati.

È già nota, separatamente, la struttura del menu `CaptureMenu`, che contiene liste di risorse numeriche: non è ancora dimostrata una corrispondenza tra i loro identificatori e queste immagini JPEG. Il prossimo passo è individuare l'indice delle immagini e il codice che seleziona e decodifica le risorse, quindi risalire al menu che le richiede.

## Riproduzione e limiti

[Script di inventario](../Python_Trace_Scripts/s33_inventory_embedded_jpeg.py) e [risultati con offset, dimensioni e hash](../Risultati/GUI_S33/embedded_jpeg_20261027T113806Z/inventory.json). Il programma verifica l'hash del firmware, cerca i marcatori JPEG e prova a decodificare fino al primo EOI successivo. Non è una scansione esaustiva: altre immagini possono usare formati diversi o una struttura che questa ricerca non riconosce. Le immagini originali non sono state alterate. Nessuna riproduzione del menu o verifica sulla fotocamera.
