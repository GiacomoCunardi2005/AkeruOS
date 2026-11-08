# GUI esposizione — bit 0 di FEB0000 nel percorso di ritorno, 28 ottobre 2026

Due continuazioni del [banco FEB](S33_GUI_Esposizione_Ritorno_FEB_Audit_20261028.md), ancora **FAIL**, eseguono il primo caso con una cella sintetica a `0x0FEB0000` inizializzata rispettivamente a `0xA5A0` e `0xA5A1`. La scelta controlla il bit 0 e mantiene gli altri bit uguali; non rappresenta un valore misurato sulla Nikon. Nel firmware V1.1, `0x20C70C` legge una halfword dalla cella, imposta il bit 0 e la riscrive. Il chiamante osservato `0x133650` proviene dal percorso sintetico della GUI; le finestre `0x133614`, `0x20C70C` e `0x20A2CC` della copia eseguita corrispondono ai byte originali del dump.

| Iniziale sintetico | Lettura osservata | Risultato nel backing ordinario | Arresto successivo |
|---|---|---|---|
| `A5A0` | `A5A0` | `A5A1` | lettura 16 bit `0x0FEE03C0` a `0x20A2DC` |
| `A5A1` | `A5A1` | `A5A1` | stessa lettura |

Entrambe le esecuzioni si fermano dopo 13.571 istruzioni. Le tracce hanno 13.924 righe e differiscono solo nella lettura a `0x20C718`; il record della scrittura mostra l'operando esteso `0xFFFFA5A1`, mentre il file di backing conserva i due byte `A1 A5`. Dopo la scrittura la CPU ritorna al chiamante e successivamente raggiunge `0x20A2CC`, che legge `0x0FEE03C0` e testa il bit 0. Il fault è sulla prima lettura: nessun ramo successivo di questa routine è stato eseguito.

[Banco](../Python_Trace_Scripts/s33_verify_gui_exposure_return_feb0000_cpu.py), [manifest A5A0](../Risultati/GUI_S33/exposure_return_feb0000_a5a0_20261028T144025Z/verified_evidence.json), [manifest A5A1](../Risultati/GUI_S33/exposure_return_feb0000_a5a1_20261028T144025Z/verified_evidence.json). Ogni run conserva lo snapshot dello script e il seed; hash di traccia, snapshot, seed e backing finali coincidono con i rispettivi manifest. I 76 file binari finali e snapshot sono identici tra run: ciò non prova da solo l'identità degli input iniziali, perché i mapfile possono essere mutati; il seed è invece dichiarato separatamente e la lettura iniziale è nella traccia.

Il test verifica il comportamento di queste istruzioni nel modello, non semantica, temporizzazione, persistenza o effetti fisici dei registri. Sincronizzazione, risorse, MMIO, contesti e input restano fixture, DSP v7 e AUX 69 modelli sperimentali; la sequenza non ha completato il primo dei quattro casi, né il ritorno al sottomenu. `0x0FEE03C0` richiede analisi e un modello motivato prima di continuare. Nessuna operazione sulla fotocamera; **NON_INSTALLARE**.
