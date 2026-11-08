# Tempo del menu e copia nel consumatore di acquisizione — 6 novembre 2026

**5/5 CPU emulata PASS; NON_INSTALLARE.** L'analisi statica V1.1 individua nella callback candidata di acquisizione `0x1BA9C4` una chiamata a `0xDBBC0` a `0x1BA9F8`. In `0xDBBC0`, il frammento `0xDBCBC` chiama il getter originale `0xF6F14`, aggiunge 720 e copia 240 byte da `0x380844` in un buffer locale. Tale area contiene il risultato del calcolo testato dopo la scelta del tempo.

Il banco integrato percorre menu, conferma e calcolo come nella [prova precedente](S33_GUI_Tempo_Ritorno_Task_Chiamante_CPU_20261106.md), poi **chiama esplicitamente il frammento `0xDBCBC`**, con frame sintetico. Il banco confronta tutti i 240 byte copiati con la sorgente, controlla i due canarini e verifica tempo, ISO e flag agli offset +52, +64 e +80. La routine byte di copia `0x128C20` è una fixture; il banco interrompe il frammento a `0xDBCD2`.

| Tempo confermato | Limite sintetico | Campo tempo nella copia | Caso | Cartella `Risultati/GUI_S33/…` |
|---:|---:|---:|---|---|
| 121 | 1000000 | 121000 | normale | `snapshot_capture_focus_original_cpu_20261106T091517229623Z_276832` |
| 119 | 1000000 | 119000 | discesa | `snapshot_capture_focus_original_cpu_20261106T091517236351Z_276835` |
| 121 | 20000 | 20000 | limite | `snapshot_capture_focus_original_cpu_20261106T091517195352Z_276833` |
| 119 | 20000 | 20000 | discesa e limite | `snapshot_capture_focus_original_cpu_20261106T091517191938Z_276830` |
| 121 | 1000000 | 121000 | notifica soppressa dal modello | `snapshot_capture_focus_original_cpu_20261106T091517226698Z_276831` |

In ogni caso ISO è 125 e flag 1, con ingressi sintetici. Nell'ultimo caso il banco chiama comunque il frammento dopo il ritorno di errore modellato: ciò **non implica** che una fotocamera faccia altrettanto. Regressione senza la nuova copia: `snapshot_capture_focus_original_cpu_20261106T091517236349Z_276834` PASS. [Verificatore](../Python_Trace_Scripts/s33_verify_snapshot_capture_focus_original_cpu.py), [relazione statica della callback](S33_Ingresso_Acquisizione.md).

Il banco verifica i byte originali dei siti `0x1BA9F8`, `0xDBCBC` e del getter. Non esegue né l'inizio di `0x1BA9C4`/`0xDBBC0` né la continuazione dopo la copia; i rami precedenti potrebbero cambiare l'area sorgente. L'ordine fra chiusura LiveView, calcolo e acquisizione è imposto, non stabilito dal test. Restano fixture, contesti e schedulazione sintetici e DSP sperimentale: non sono dimostrati S2, esposizione fisica, AE o sensore. Nessuna operazione su fotocamera o supporti.

Primo tentativo rifiutato da un errore del verificatore: un nome locale sovrascriveva il percorso sorgente usato dal controllo hash finale. Rinominato il dato, la matrice è stata ripetuta; la cartella fallita è conservata.
