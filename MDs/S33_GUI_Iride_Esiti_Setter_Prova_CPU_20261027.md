# S33 V1.1 — esiti del setter iris e suo wrapper

Il 27 ottobre 2026, in sette casi GNU ARC700, ho eseguito il setter originale `0x18B85C` e il wrapper originale `0x149530`, con stato RAM sintetico e cinque servizi sostituiti da fixture esplicite. Le finestre del codice originale sono confrontate con `DUMPS/MainCode.dmp`. Le fixture controllano acquisizione, guardia, richiesta, rilascio e pulizia: nessuna mossa ottica viene eseguita.

| Stato iniziale → richiesto | Esito fixture | Setter diretto: ritorno / stato | Wrapper: ritorno / stato |
| --- | --- | --- | --- |
| 9 → 9 | Già selezionato | 9 / 9, senza acquisizione | — |
| 9 → 1 | Acquisizione rifiutata | 9 / 9 | **1 / 9** |
| 9 → 1 | Guardia rifiutata | 9 / 9, rilascio richiesto | — |
| 9 → 1 | Richiesta rifiutata | 9 / 9, pulizia richiesta | — |
| 9 → 1 | Richiesta accettata dalla fixture | 1 / 1 | — |
| 1 → 9 | Richiesta accettata dalla fixture | — | **1 / 9** |

Nelle richieste simulate, il setter passa alla fixture handle `0x1234`, indice desiderato, `wait=1` e `0x3A98`; preserva lo stack nei casi provati. Il wrapper restituisce 1 sia nell'esempio in cui la richiesta non arriva al servizio, sia nell'esempio di stato cambiato: **il suo ritorno da solo non conferma la selezione**. Anche la lettura dello stato è una cella software, non una misura fisica dell'apertura.

Il rapporto successivo alla prima analisi statica descrive il [completamento differito](S33_Iride_Completamento_Handler_Evento_e_Byte_Stato.md) e corregge la descrizione della guardia di generazione; non prova esecuzione del timer, evento, GPIO o movimento su questa fotocamera. I nomi Big/Small per gli indici 1/9 non stabiliscono quale valore f/ sia ottenuto in condizioni fisiche reali o alle varie posizioni zoom.

[Verificatore](../Python_Trace_Scripts/s33_verify_iris_setter_outcomes_cpu.py), [sette casi](../Risultati/GUI_S33/iris_setter_outcomes_cpu_20261027T214355Z/cases.json), [fixture sostituite](../Risultati/GUI_S33/iris_setter_outcomes_cpu_20261027T214355Z/fixture_patches.json), [finestre GNU](../Risultati/GUI_S33/iris_setter_outcomes_cpu_20261027T214355Z/gnu_windows.txt), [risultato e hash](../Risultati/GUI_S33/iris_setter_outcomes_cpu_20261027T214355Z/verified_evidence.json). Nessun firmware o dispositivo modificato; **NON_INSTALLARE**.
