# GUI S33 V1.1 — tutte le scelte ISO e ripristino

Il 29 ottobre 2026 il [banco GNU ARC700](../Python_Trace_Scripts/s33_verify_gui_iso_all_restore_records_cpu.py) esegue la conferma ISO originale `0x7D25B0`, la conferma tempo `0x7D2394` e il ripristino `0xCA654`, in quest'ordine imposto dal banco. Copre tutti i 24 record della lista ISO originale, ciascuno con tre indici iniziali del record di ripristino (0, 6, 19): **72 casi PASS**. L'indice diagnostico iniziale è sempre 19, corrispondente al valore software 1600; il tempo sintetico viene confermato a 42 e produce 42000, senza attribuire unità fisiche.

| Scelta ISO | Dopo conferma | Dopo ripristino con record iniziale 0 / 6 / 19 |
|---|---|---|
| Exit | Conserva indice diagnostico 19 e valore 1600 | Indice record diventa 19 in tutti e tre i casi; valore software 1600. |
| Auto | Indice e valore diagnostici diventano 0 | Indice record resta rispettivamente 0 / 6 / 19; valore software diventa 0 / 125 / 1600. |
| Una delle 22 scelte numeriche, da 50 a 3200 | Scrive l'indice e il corrispondente valore | L'indice diagnostico nonzero sovrascrive il record e viene riconvertito nello stesso valore in tutti e tre i casi. |

Questa prova amplia quella precedente, nella quale il record partiva soltanto da indice 19. Il caso Exit mostra che **non cambiare l'indice diagnostico** durante la conferma non implica preservare il record successivo: qui il vecchio indice diagnostico nonzero ha precedenza. Nel caso Auto, il valore diagnostico rimane 0, ma il valore software dopo il ripristino dipende dal record. Per la GUI futura è necessario mantenere distinti selezione, stato diagnostico e valore dopo ripristino; la sequenza osservata non prova che ciò avvenga nello stesso ordine in uno scatto reale.

I 24 valori originali sono confrontati col dump V1.1; ogni caso verifica campi, richieste simulate di apertura e stack. [Casi](../Risultati/GUI_S33/iso_all_restore_records_cpu_20261029T224658Z/cases.json), [manifest e traccia](../Risultati/GUI_S33/iso_all_restore_records_cpu_20261029T224658Z/verified_evidence.json), [fixture](../Risultati/GUI_S33/iso_all_restore_records_cpu_20261029T224658Z/fixture_patches.json). La prima esecuzione PASS `224648Z` precede l'aggiunta del controllo integrale dei valori lista; non è la fonte della prova finale.

Controllo, record e ordine sono sintetici; 14 altri setter, recupero controllo e apertura sono fixture. Non sono dimostrati tasti fisici, lifecycle, concorrenza, AE, guadagno sensore, persistenza o effetto fotografico. Nessun firmware o dispositivo modificato; **NON_INSTALLARE**.
