# AutoScene: inizializzazione anticipata e rollback — CPU emulata

Il 5 novembre 2026 il banco [di rientro con inizializzazione nel callback](S33_GUI_Autoscene_Inizializzazione_Coda_CPU_20261105.md) è stato esteso con `--fail-entry`. Per entrambi gli eventi logici `0x700` e `0x2180`, il callback del descrittore sintetico riceve prima `0x4401`, completa e azzera la coda del modello come nella prova precedente; il banco gli fa poi restituire **−1 su `0x4405`**. È un errore iniettato intenzionalmente, non un errore riscontrato sulla fotocamera.

| Condizione | Descrittore corrente osservato | Stato della coda AkeruOS |
|---|---|---|
| Guardia manager attiva, prima del tentativo | live view `0x783AE8` | schermata esposizione, sospesa; nessuna inizializzazione |
| Guardia rimossa, callback `0x4405` restituisce −1 | live view `0x783AE8` dopo rollback | schermata principale, attiva=0; inizializzazione già eseguita |
| Guardia rimossa, senza errore iniettato | descrittore sintetico `0x2050000` | inizializzata; successivo evento `0x700` porta il modello a colore |

**2/2 riproduzioni del rollback atteso**: [evento `0x700`, argomento 4](../Risultati/GUI_S33/autoscene_lifecycle_failure_cpu_20261105T103636172359Z/verified_evidence.json) e [evento `0x2180`, argomento 5](../Risultati/GUI_S33/autoscene_lifecycle_failure_cpu_20261105T103637464868Z/verified_evidence.json). Per ciascuno il banco controlla descrittore, stato e contatori prima del ripristino artificiale successivo: una inizializzazione e un errore `0x4405`, zero inizializzazioni quando la guardia blocca. Il dispatcher restituisce 1 anche nel caso di rollback: non basta a confermare l'apertura. Le regressioni senza errore passano per [0x700](../Risultati/GUI_S33/autoscene_lifecycle_entry_cpu_20261105T103638685700Z/verified_evidence.json) e [0x2180](../Risultati/GUI_S33/autoscene_lifecycle_entry_cpu_20261105T103639856959Z/verified_evidence.json).

Il risultato indica una **incoerenza nel protocollo sperimentale**: `0x4401` da solo è troppo anticipato per considerare confermato il rientro, perché in questo caso la transizione viene successivamente annullata. La coda aveva già perso lo stato sospeso. Non implementare tale regola come se garantisse il successo; il passo successivo è verificare un completamento condizionato a esito e descrittore finale, oppure un ripristino completo dello stato su rollback. Non è stabilito quale soluzione sia integrabile in camera.

Riproduzione: `python3 Python_Trace_Scripts/s33_verify_gui_autoscene_key_reenter_cpu.py --lifecycle-entry --fail-entry`, aggiungendo `--event-2180` per il secondo evento. Le altre sequenze ereditate vengono eseguite ma non validate da questa variante. I file indicati come PASS confermano che il banco ha riprodotto l'esito avverso previsto, **non** che la gestione sia sicura.

Il descrittore, il callback, il flag di abilitazione, il valore −1, il contesto e la consegna degli eventi sono sintetici; l'ID 2 è reindirizzato solo nella copia laboratorio. Lo scheduler reale, altri errori, concorrenza, risorse, rendering, tasti fisici e comportamento su hardware non sono provati. Nessuna modifica a firmware originale, dispositivo o supporti. **NON_INSTALLARE**.
