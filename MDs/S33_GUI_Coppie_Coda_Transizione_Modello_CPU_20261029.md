# GUI: eventi accodati e cambio di schermata nel modello

Il 29 ottobre 2026 ho collegato il [banco delle coppie snapshot](S33_GUI_Snapshot_Coppie_Simultanee_CPU_20261029.md) al modello C `akeru_menu_event`, compilato per ARC700. Partendo dalla schermata principale, il banco predispone insieme i bit delle quattro coppie ammesse nel test precedente; il lettore, callback, normalizzatore e coda originali producono due record. Il banco li estrae e li consegna entrambi al modello, nell'ordine della coda, prima di ripristinare gli ingressi.

| Slot logici sintetici | Prima azione del modello | Seconda azione del modello |
|---|---|---|
| 1 + 2 | passa a esposizione | richiede ISO |
| 1 + 3 | passa a esposizione | richiede diaframma |
| 2 + 4 | passa a colore | nessuna azione |
| 3 + 4 | nessuna azione | richiede impostazioni |

Per le prime due coppie, due eventi prodotti dallo stesso snapshot sono interpretati su schermate diverse: il secondo provoca una richiesta del sottomenu appena aperto. La prova rende concreto un rischio del modello, non dimostra che un utente lo sperimenterà sulla fotocamera. Prima di scegliere una mitigazione occorre definire come il collegamento riconoscerà una stessa acquisizione e gestirà transizioni e rilasci: scartare eventi semplicemente per ordine o tempo potrebbe eliminare pressioni valide.

[Quattro casi PASS](../Risultati/GUI_S33/mmio_pairs_to_menu_cpu_20261029T054746Z/verified_evidence.json), 12.102 istruzioni GNU; verificati i due record iniziali, le due controparti successive estratte, azioni e schermate dopo ogni chiamata, esito e stack. [Casi](../Risultati/GUI_S33/mmio_pairs_to_menu_cpu_20261029T054746Z/cases.json), [traccia](../Risultati/GUI_S33/mmio_pairs_to_menu_cpu_20261029T054746Z/cases.trace), [banco](../Python_Trace_Scripts/s33_verify_gui_mmio_pairs_to_menu_cpu.py). I record di rilascio vengono estratti ma non consegnati al modello in questo test.

La consegna al modello è esplicita nel banco; callback e stato precedenti sono predisposti, MMIO è memoria ordinaria, lock e filtro sono fixture. Non sono eseguiti scheduler, dispatcher reale, rendering, apertura effettiva dei controlli, esposizione o tasti fisici. Le azioni sono richieste del modello, non modifiche applicate alla fotocamera. **NON_INSTALLARE**.
