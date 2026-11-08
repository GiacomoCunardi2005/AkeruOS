# Tempo: ripetizione dopo ritorno rifiutato

Il 29 ottobre 2026 ho esteso la [prova del ritorno contestuale](S33_GUI_Tempo_Ritorno_Contestuale_CPU_20261029.md): dopo un primo ritorno rifiutato dalla guardia del manager, il banco rimuove la guardia e invia una seconda volta lo stesso evento, senza riaprire la schermata tempo.

| Evento ripetuto | Dopo primo tentativo rifiutato | Dopo secondo evento |
|---|---|---|
| Conferma | schermata tempo, flag 1, campi 121.000 / 121.000 | descrittore sintetico, flag 0, campi 121.000 / 121.000 |
| Annulla | schermata tempo, flag 1, campi sentinella invariati | descrittore sintetico, flag 0, campi sentinella invariati |

La traccia verifica **due ingressi al setter originale del tempo** nel caso di conferma: la seconda conferma ripete la scrittura dello stesso valore, non è soltanto una nuova richiesta di navigazione. Il risultato uguale nei due campi non prova l'assenza di altri effetti o la sicurezza di un retry generale.

[Due casi PASS](../Risultati/GUI_S33/model_time_return_retry_cpu_20261029T054224Z/verified_evidence.json), 23.091 istruzioni: verificati flag, descrittori, campi, stack e conteggio delle chiamate a conferma, annullo e setter. [Casi](../Risultati/GUI_S33/model_time_return_retry_cpu_20261029T054224Z/cases.json), [traccia](../Risultati/GUI_S33/model_time_return_retry_cpu_20261029T054224Z/cases.trace), [banco](../Python_Trace_Scripts/s33_verify_gui_model_time_return_retry_cpu.py).

Il secondo evento e la rimozione della guardia sono imposti dal banco; non sappiamo se o quando accadano sulla fotocamera. Il flag e il descrittore sono sintetici, quest'ultimo senza risorse; i trampoline modificano soltanto copie di laboratorio. Non sono provati effetti concorrenti, AE, unità fisiche, scatto o persistenza. **NON_INSTALLARE**.
