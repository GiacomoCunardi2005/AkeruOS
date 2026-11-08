# USB: rilevamento con fotocamera nel menu normale

20 ottobre 2026, campionamento iniziato alle 20:07:55 ora italiana. L'utente riferisce fotocamera collegata e accesa nel menu normale. Richiesta: rilevarla sul PC.

**Esito: nessuna Nikon rilevata durante questa verifica.** `lsusb` iniziale e finale non contengono dispositivi Nikon; `gphoto2 --auto-detect` iniziale e finale non elencano fotocamere. Campionamento sysfs: 23 letture distanziate di due secondi, nessun cambiamento nell'inventario dei 21 dispositivi USB, nessun vendor `04b0`. L'albero USB mostra le altre periferiche; nessun disco USB compare in `lsblk`.

La lettura separata del campo `authorized` dei dispositivi presenti restituisce sempre 1. Questo non prova lo stato di una periferica assente. Il registro kernel accessibile, controllato prima e dopo il campionamento, non riporta collegamenti USB nel periodo osservato. Nessun errore di autorizzazione è comparso nei comandi di rilevamento.

È stato chiesto all'utente di ricollegare il cavo, preferibilmente a una porta diretta del portatile, durante il controllo. Non è arrivata conferma dell'esecuzione: **il campionamento non va presentato come prova di un ricollegamento fisico effettivamente avvenuto**.

## Evidenze e limiti

- [Manifest con campioni sysfs e hash dei log](../Risultati/Hardware/USB_Rilevamento_20261020T180755Z/verified_evidence.json).
- [Inventario USB finale](../Risultati/Hardware/USB_Rilevamento_20261020T180755Z/lsusb_final.txt).
- [Rilevamento gphoto2 finale](../Risultati/Hardware/USB_Rilevamento_20261020T180755Z/gphoto_final.txt).
- [Registro kernel finale](../Risultati/Hardware/USB_Rilevamento_20261020T180755Z/kernel_after.txt).
- [Indice ultima verifica](../Risultati/Hardware/latest_usb_detection.json).
- [Precedente riconoscimento Nikon PTP e relativi limiti](S33_USB_MSDC_e_Accelerazione_Analisi_OS.md#osservazione-usb-reale--20-ottobre-2026).

Nessuna sessione PTP o comando vendor, nessun reset, montaggio, lettura file della fotocamera o scrittura hardware. Nessuna modifica GNU. L'assenza di enumerazione non distingue cavo, porta, connettore e stato firmware; non dimostra guasto e non smentisce il precedente riconoscimento PTP. Prossimo: ricollegamento fisico confermato, confronto porta diretta e cavo dati, ripetendo solo il rilevamento. Nessun incremento dell'avanzamento AkeruOS.
