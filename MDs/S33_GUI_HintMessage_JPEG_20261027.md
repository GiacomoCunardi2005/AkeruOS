# S33 — percorso HintMessage verso le immagini JPEG

L'oggetto GUI interno **`HintMessage`**, ID `0x9E`, ha il gestore `0x7C976C` e una tabella eventi a `0x9819C8`. L'evento `0x4405` porta all'handler `0x7C97A4`. Se i controlli iniziali lo consentono e il valore restituito dalla chiamata `0x14504C` con parametro `0x12` è 7, un ramo raggiunge la seguente catena originale:

```text
HintMessage, evento 0x4405
  → handler 0x7C97A4, controlli e valore 7
  → 0x7C9BBC → 0x7C9BF0 (indice 14)
  → 0x7C9C54 → 0x7C9CFC → 0x7C9E38
  → record 14 della tabella offset/lunghezza → lettore 0x159558
```

Il chiamante `0x7C9CFC` tenta la lettura una seconda volta se la prima fallisce, quindi passa il buffer a una routine che riconosce marcatori JPEG e legge campi di dimensione. Nel blocco di 18 JPEG identificato in precedenza, l'indice 14 corrisponde all'illustrazione di una donna con maglia viola, visibile nella [tavola](../Risultati/GUI_S33/embedded_jpeg_20261027T113806Z/160x96_contact.png).

La corrispondenza con **quell'immagine effettivamente letta** dipende dalla base runtime configurata per `0x159558`, ancora non dimostrata. Il nome interno suggerisce una schermata di suggerimento, ma non prova il testo visibile, il significato preciso dell'evento `0x4405`, né quando la schermata sia presentata. Il codice è collegato staticamente: non abbiamo osservato il display o eseguito insieme i servizi di lettura e disegno.

## Riproduzione

Il [verificatore](../Python_Trace_Scripts/s33_verify_jpeg_hint_path.py) confronta con `MainCode.dmp` descrittore, tabella eventi e finestre di codice originali, e verifica la catena e l'indice costante. [Esito](../Risultati/GUI_S33/jpeg_hint_path_20261027T114229Z/evidence.json) e [finestre GNU](../Risultati/GUI_S33/jpeg_hint_path_20261027T114229Z/gnu_windows.txt). L'[indice delle immagini](S33_GUI_Indice_JPEG_Scene_20261027.md) verifica separatamente tutti i record.

Prossimo: verificare la configurazione della base di lettura e seguire gli altri ingressi della schermata per comprendere selezione e visualizzazione. Nessuna modifica firmware o operazione sulla fotocamera.
