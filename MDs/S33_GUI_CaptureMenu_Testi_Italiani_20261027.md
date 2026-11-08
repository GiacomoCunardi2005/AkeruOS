# S33 — testi candidati delle voci CaptureMenu

Il 27 ottobre 2026 ho individuato nel TBM originale V1.1 i blocchi da cui il firmware può caricare le risorse testuali usate da `CaptureMenu`. Il risultato collega sette ID dei record alla forma italiana e inglese dei byte, senza ancora dimostrare che una determinata lingua o lista sia attiva sulla fotocamera.

| Lista | Indice | ID testo `+12` | Blocco 5: byte ASCII italiani | Blocco 1: byte ASCII inglesi |
| --- | ---: | ---: | --- | --- |
| `0x4800` | 0 | 59 | Modo flash/autoscatto | Flash mode/self-timer |
| `0x4800` | 1 | 91 | Flash | Flash |
| `0x4800` | 2 | 92 | Autoscatto | Self-timer |
| `0x4801` | 0 | 60 | Altre opzioni foto | More picture options |
| `0x4801` | 1 | 61 | Scegli stile | Choose a style |
| `0x4801` | 2 | 1 | Decora | Decorate |
| `0x4801` | 3 | 26 | Cambia colore | Change colors |

## Collegamento ai file

L'inizializzatore `0x128574` ottiene dal getter `0x1EB1A4` il puntatore `0x3BB118` e lo salva nel contesto `0x366864`. La tabella originale contiene 37 coppie di offset e dimensioni; il verificatore ha confrontato i 37 blocchi consecutivi con `MainCode.dmp` e controllato il loro identificatore `0x18E209FE`. Il blocco 1 inizia al TBM offset `0xC7BE00`; il blocco 5 a `0xC84000`.

Nel percorso condizionale `0x128620`, il lettore `0x159550` riceve base `0xC7A000`; `0x159558` riceve l'offset e la dimensione della coppia selezionata e destinazione `0x43E170`. Dopo una lettura dichiarata riuscita e il confronto dell'identificatore, il codice abilita il lookup. La routine `0x1286C4`, già collegata ai campi `+12` di CaptureMenu, usa la tabella `0x43E174` e la base `0x43E768`: le posizioni relative nel blocco caricato sono rispettivamente `+4` e `+0x5F8`. Applicando questa geometria ai blocchi 1 e 5, tutti e sette gli ID portano alle sequenze ASCII riportate sopra, terminate da zero.

La prova confronta integralmente i blocchi di origine tra TBM e dump e controlla i singoli offset e caratteri. Il percorso della risorsa `+12` verso il lookup è documentato nella [precedente analisi](S33_GUI_CaptureMenu_Risoluzione_Risorse_20261027.md). Il backend può usare una sorgente diversa e la lingua è scelta a runtime: non sono state osservate la lettura effettiva, la consegna dei dati a `0x186D08` o la visualizzazione. Non viene attribuita una codifica completa agli altri blocchi; solo le sette stringhe mostrate nei blocchi 1 e 5 sono state verificate come ASCII.

[Verificatore e dati](../Python_Trace_Scripts/s33_verify_gui_capture_text_source.py), [37 blocchi, hash e stringhe](../Risultati/GUI_S33/capture_text_source_20261027T175650Z/evidence.json), [finestre GNU del caricatore e lookup](../Risultati/GUI_S33/capture_text_source_20261027T175650Z/gnu_windows.txt), [inizializzazione del puntatore](../Risultati/GUI_S33/capture_text_init_20261027T175700Z/gnu_window.txt). Nessuna modifica firmware, SD o fotocamera; **NON_INSTALLARE**.
