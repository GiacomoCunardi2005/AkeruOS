# S33 — tempo Auto e valori operativi nel ramo AutoScene

Il requisito espresso il 31 ottobre 2026 è avere **Auto separato per ISO, diaframma e tempo**, ciascuno selezionabile indipendentemente dagli altri due. Una configurazione come ISO manuale, diaframma Auto e tempo manuale deve quindi essere rappresentabile. È un requisito del progetto, non una funzione già verificata sulla fotocamera.

Nel codice diagnostico esistono una scelta ISO Auto e una visualizzazione `AUTO` per tempo zero; non è ancora provato che questi valori assicurino la corretta gestione automatica durante lo scatto. Per l'iride sono stati provati richieste e completamento software degli stati 1/9, ma non è stato identificato un comando verificato per restituire ad AE il controllo automatico del diaframma. Non si deve inventare un terzo stato o chiamare Auto il semplice rilascio di una handle.

## Confronto dei percorsi per il tempo

Il [banco](../Python_Trace_Scripts/s33_probe_gui_iso_autoscene_to_calc_cpu.py) ora copre la conferma tempo diagnostica 0, 42 e 84, con ISO 125 sintetico. Dopo la conferma il banco può imporre un aggiornamento operativo a 90.000 mediante `0xDE7B4` e poi entra direttamente nel frammento `0x659C08`: modo `0x2C` chiama il wrapper `0x65BC60(4)`, modo `0x2B` lo salta. Infine il banco chiama esplicitamente `0xD8CA4` e controlla il buffer finale.

| Scelta diagnostica | Aggiornamento operativo | Dopo ramo `0x2C` / buffer finale | Dopo ramo `0x2B` / buffer finale |
|---|---|---:|---:|
| 0, visualizzato come Auto nella diagnostica | assente | 0 | 0 |
| 0 | 90.000 imposto | 0 | 90.000 |
| 42 | assente | 42.000 | 42.000 |
| 42 | 90.000 imposto | 42.000 | 90.000 |
| 84 | assente | 84.000 | 84.000 |
| 84 | 90.000 imposto | 84.000 | 90.000 |

Sono valori software: le unità fisiche non sono stabilite. I **12 casi PASS** controllano conferma, campo dopo il ramo, record, calcolo, copia finale e stack. Lo [script riunito](../Python_Trace_Scripts/s33_check_iso_autoscene_matrix.py) si invoca con `--time`; [riepilogo e manifest](../Risultati/GUI_S33/time_autoscene_matrix_20261031T155515968865Z/summary.json). La regressione ISO esistente è stata rieseguita: [20/20 PASS](../Risultati/GUI_S33/iso_autoscene_matrix_20261031T155515993982Z/summary.json).

## Perché il risultato Auto differisce da una prova precedente

Nel [banco precedente](S33_GUI_Ripristino_ISO_Tempo_CPU_20261028.md), che chiamava `0xCA654` direttamente con un record iniziale predisposto a 90.000, il diagnostico zero lasciava il record a 90.000. Qui la traccia mostra che `0xCA5DC` riceve effettivamente **90.000 dalla fixture** e lo scrive nel record, ma il wrapper `0x65BC60` lo azzera a `0x65BCFE` prima di `0xCA654`. Se la word diagnostica è zero, `0xCA654` non la sostituisce: nel ramo `0x2C` il setter riceve dunque zero. I primi due tentativi `gui_iso_autoscene_calc_probe_2_time0_20261031T155348Z` e `..._time0_update0_20261031T155424Z` sono conservati come FAIL: il primo aveva un oracolo errato di 90.000; il secondo non prevedeva la seconda chiamata al calcolo quando il tempo è zero. Il banco finale verifica entrambe le condizioni nella traccia.

Il confronto distingue chiamata diretta e chiamata attraverso questo wrapper; non dimostra quale percorso o ordine avvenga in camera. La fixture del getter tempo restituisce 90.000, input/modalità/aggiornamento sono imposti, e servizi GUI, copia, callback e parte del calcolo sono sostituiti nel banco. L'handler AutoScene non è eseguito dall'ingresso, e AE, ottica, sensore, scatto, persistenza e indipendenza effettiva delle tre modalità restano da dimostrare. Firmware, camera e SD invariati; **NON_INSTALLARE**.
