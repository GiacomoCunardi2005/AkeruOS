# S33 — confronto condizionale tra manuale e slot del menu

27 ottobre 2026. Il [manuale Nikon S33](../output/pdf/Archivio_AI/pdf/Nikon_S33_Reference_Manual_En05_03cc47d1917e.pdf) (SHA-256 `03cc47d1917e7ecf8d051e7b578273ce248fc434e54b600f2105517a0d69b29c`) definisce i pulsanti flessibili 1–4 dall'alto verso il basso, pagina stampata 5 (PDF 27). Alle pagine stampate 26, 32 e 33 (PDF 48, 54 e 55) descrive tre scelte dal menu «More picture options», dopo il pulsante 3 della schermata di ripresa.

Confrontando quelle indicazioni con l'[estrazione dei testi V1.1](S33_GUI_CaptureMenu_Testi_Italiani_20261027.md), le [destinazioni dei record](S33_GUI_CaptureMenu_Destinazioni_20261027.md) e la [selezione degli slot di classe 0x15](S33_GUI_Classe15_Paginazione_20261027.md) si ottiene la seguente **ipotesi**, limitata alla lista `0x4801` quando i record e gli eventi siano effettivamente quelli studiati:

| Voce riportata dal manuale | Pulsante fisico indicato dal manuale | Indice record V1.1, testo e oggetto candidato | Evento associato staticamente allo slot |
| --- | ---: | --- | --- |
| Choose a style | 2 | 1, ID testo 61, `ShootingMode` | `0x700` |
| Decorate | 3 | 2, ID testo 1, `FrameSelect` | `0x2180` |
| Change colors | 4 | 3, ID testo 26, `ChangeColorMenu` | `0x2700` |

Per la prima riga del menu, il manuale indica in generale il pulsante 1 per tornare indietro quando compare l'icona Q. Il record 0 ha ID testo 60 («More picture options»), flag iniziale `0x08` e destinazione `AutoSceneLiveView`; lo slot 0 usa evento `0x580`. Questa somiglianza è meno specifica delle altre tre: il testo del record è il titolo del menu e non prova il rendering dell'icona di ritorno.

La correlazione richiede che la schermata del manuale usi effettivamente la risorsa V1.1 `0x4801`, che la geometria e la pagina siano quelle iniziali, che il gestore riceva gli eventi della classe e che altri filtri o instradamenti non cambino la selezione. Il manuale non identifica gli eventi interni, il firmware non dimostra che tali eventi provengano dagli interruttori fisici, e la corrispondenza di nomi e destinazioni non è una misura elettrica. Non è quindi una mappa fisica verificata né autorizza a trasferire questi indirizzi alla V1.0.

Un confronto aggiuntivo impone cautela anche sulla live view: il manuale descrive il pulsante 3 in ripresa come accesso a «More picture options», mentre in una [prova separata](S33_GUI_Liveview_Evento_2180_CPU_20261027.md) l'evento `0x2180` **iniettato** direttamente nella live view richiede `ShootingMode` in alcuni stati sintetici. L'eventuale differenza di percorso o di stato non è risolta; non si deduce che la prova rappresenti la pressione fisica del pulsante 3 o che il manuale sia errato.

Le fonti sono indipendenti per funzione: il manuale documenta l'interfaccia prevista senza dichiarare qui la versione del firmware, mentre il codice e gli indirizzi sono V1.1; le fotografie storiche del menu diagnostico non mostrano la sequenza di questi tre menu e non verificano la mappa. Nessuna osservazione V1.0 della stessa sequenza, né prova di visualizzazione, coda o pulsanti su hardware è stata effettuata. Nessun firmware o dato sulla fotocamera è stato modificato. Candidati **NON_INSTALLARE**.
