# Tempo: azione opposta dopo ritorno rifiutato

Il 29 ottobre 2026 ho verificato un'altra sequenza rispetto alla [ripetizione dello stesso evento](S33_GUI_Tempo_Ritorno_Riprova_CPU_20261029.md): dopo il primo ritorno rifiutato dalla guardia del manager, il banco rimuove la guardia e inietta l'evento opposto senza riaprire la schermata tempo. Il valore modificato nel controllo è 121; i due campi software partono dalla sentinella `0x12345678`.

| Sequenza iniettata | Dopo la prima azione, ritorno rifiutato | Dopo la seconda azione, ritorno riuscito |
|---|---|---|
| Conferma, poi annulla | Campi 121.000 / 121.000; schermata tempo; flag 1 | Campi 121.000 / 121.000; descrittore sintetico; flag 0 |
| Annulla, poi conferma | Entrambi i campi conservano la sentinella; schermata tempo; flag 1 | Campi 121.000 / 121.000; descrittore sintetico; flag 0 |

In questa configurazione **annullare dopo una conferma già eseguita non ripristina i valori precedenti**, anche se il primo tentativo di uscita è stato rifiutato. Viceversa, confermare dopo un annullamento rifiutato scrive il valore. La transizione della finestra e l'applicazione dei campi sono quindi osservabili come operazioni distinte; il nuovo menu non può assumere che annulla annulli una conferma già avvenuta. Questi risultati non giustificano da soli un ripristino automatico, la cui interazione con altri aggiornamenti non è stata verificata.

[Due casi PASS](../Risultati/GUI_S33/model_time_return_switch_cpu_20261029T054258Z/verified_evidence.json), 23.091 istruzioni GNU ARC700: [valori](../Risultati/GUI_S33/model_time_return_switch_cpu_20261029T054258Z/cases.json), [traccia](../Risultati/GUI_S33/model_time_return_switch_cpu_20261029T054258Z/cases.trace), [banco ripetibile](../Python_Trace_Scripts/s33_verify_gui_model_time_return_switch_cpu.py). Il banco controlla i due campi, flag, descrittori, stack e conteggio complessivo degli ingressi a conferma, annullo e setter.

Guardia e secondo evento sono forzati dal banco; flag, contesto e descrittore senza risorse sono sintetici. I trampoline sono applicati soltanto a copie di laboratorio e vari servizi sono fixture. Non dimostra che la sequenza sia disponibile sulla fotocamera, né unità fisiche del valore, effetti AE, scatto, persistenza, concorrenza o resa grafica. **NON_INSTALLARE**.
