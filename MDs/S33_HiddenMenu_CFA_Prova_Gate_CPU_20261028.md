# S33 V1.1 — effetto del flag HiddenMenu CFA nel gate originale

28 ottobre 2026. Prova offline su CPU GNU ARC700 con modello DSP sperimentale. **NON_INSTALLARE**; nessun accesso alla fotocamera o alla SD.

La voce IQDEBUG `SaveCFARawOnIRP` è collegata staticamente alla callback `0x7CF51C`, che legge `0x13AF18`, inverte il valore booleano e chiama il setter `0x13AF20` per il byte `0x366C20`. Nel nuovo banco il setter originale viene chiamato direttamente: **non sono eseguiti menu, tasti o callback GUI**.

Il frammento originale `0x1E6A54` legge poi quel flag. In cinque casi con contesto, struttura e servizi sintetici:

| Flag scritto | Campo formato | Risultato osservato |
|---:|---:|---|
| 0 | 2 | Nessuna chiamata al dispatcher diagnostico. |
| 1 | 2 | Tre chiamate, modalità 0/1/2; scrittura richiede 2.048 byte. |
| 1 | 1 | Tre chiamate; scrittura richiede 1.536 byte. |
| 1 | 2 | Anche con errore 77 restituito dalla fixture a ogni chiamata, tutte e tre vengono invocate. |
| 2 | 2 | Tre chiamate, perché il gate verifica solo che il valore sia diverso da zero. |

Le dimensioni del banco sono 17 × 19, allineate a 32 × 32: il valore 2 del campo produce 2 byte per posizione, l'altro caso 1,5. I numeri, puntatore `0x2040000` e chiave `0x12345678` sono input del test, non misure della S33. Il caso flag 2 verifica il consumer, **non** suggerisce di impostare tale valore: la callback del menu normalizza a 0 o 1 e altri consumer possono avere comportamenti diversi.

Il dispatcher è una **fixture che registra argomenti e restituisce un valore**, senza eseguire open/write/close né leggere il buffer. L'errore 77 è iniettato in ogni invocazione, non un errore reale. L'esecuzione si ferma a `0x1E6ACC`, prima del resto della routine: non prova l'esito finale o la propagazione di errori altrove. La prova sostiene l'effetto locale del flag e la mancata interruzione immediata dei tre tentativi, non la creazione, la correttezza o la persistenza di un file. La relazione condizionale con JPEG è nel [rapporto CFA/JPEG](S33_RAW_CFA_IRP_e_JPEG_Catena_20261028.md).

Riproduzione: `python3 Python_Trace_Scripts/s33_verify_hidden_cfa_gate_cpu.py`. [Casi](../Risultati/HiddenMenu_RAW/hidden_cfa_gate_cpu_20261028T144436Z/cases.json), [fixture](../Risultati/HiddenMenu_RAW/hidden_cfa_gate_cpu_20261028T144436Z/fixture_patches.json), [script e snapshot](../Python_Trace_Scripts/s33_verify_hidden_cfa_gate_cpu.py). Byte delle due finestre confrontati col dump e hash firmware controllato. Il primo tentativo fallito per un immediato assembly fuori intervallo rimane conservato; corretto solo il banco. Nessun frame, sensore, salvataggio reale o JPEG sono stati verificati.
