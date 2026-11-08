# Menu tempo, ritorno al task e chiamante della richiesta — 6 novembre 2026

Il [banco precedente](S33_GUI_Tempo_Ritorno_DB138_CPU_20261106.md) terminava artificialmente CapMgrTask subito dopo la notifica. Il banco ora lascia eseguire il salto originale `0x14A59A → 0x14A4FA`: il task raggiunge una seconda attesa dell'evento `0x1`. Quando il bit non è presente, la fixture cooperativa registra il punto e smonta il frame del task per restituire il controllo al chiamante. Questo **modella una sospensione**, non conserva né riprende un task concorrente reale.

Il banco può inoltre invocare `0x14A1FC`, il cui codice originale chiama la richiesta `0x14A968` a `0x14A20A` e ne restituisce il valore dopo due servizi modellati. La sequenza testata è: menu tempo → registrazione → chiamata esplicita `14A1FC → 14A968` → task cooperativo → `DB138` originale fino al ritorno → notifica → seconda attesa → ritorno della richiesta e del chiamante.

**4/4 CPU emulata PASS** con chiamante `14A1FC`:

| Tempo | Limite sintetico | Risultato software | Ritorno del chiamante | Cartella `Risultati/GUI_S33/…` |
|---:|---:|---:|---:|---|
| 121 | 1000000 | 121000 | 0 | `snapshot_capture_focus_original_cpu_20261106T091028052009Z_269770` |
| 119 | 1000000 | 119000 | 0 | `snapshot_capture_focus_original_cpu_20261106T091028007147Z_269771` |
| 121 | 20000 | 20000 | 0 | `snapshot_capture_focus_original_cpu_20261106T091028054305Z_269772` |
| 121 | 1000000 | 121000 | 1, notifica soppressa dalla fixture | `snapshot_capture_focus_original_cpu_20261106T091028062265Z_269775` |

Le prove controllano due chiamate al calcolo, risultati e copia finale, due attese del task, salto di ritorno originale e stack conservato. ISO 125 e flag 1 sono sintetici. Regressioni PASS con chiamata diretta alla richiesta e ciclo del task `snapshot_capture_focus_original_cpu_20261106T091028053837Z_269773`, e con precedente arresto dopo notifica `snapshot_capture_focus_original_cpu_20261106T091028013525Z_269774`. Una matrice aggiuntiva di 7/7 casi PASS esercita il ciclo senza il chiamante `14A1FC`, includendo ritorno menu libero e retry: cartelle `snapshot_capture_focus_original_cpu_20261106T090921*`. [Verificatore](../Python_Trace_Scripts/s33_verify_snapshot_capture_focus_original_cpu.py).

`0x1B9E30` e `0xD014C` sono fixture che ritornano zero; la richiesta iniziale è ancora invocata dal banco e registrazione, eventi, sincronizzazione, RAM e altri servizi sono modellati. `0xDB138` arriva al proprio epilogo originale solo nei rami selezionati dalle fixture. Non sono dimostrati collegamento al tasto fisico, schedulazione reale, persistenza, AE, unità o sensore; DSP GNU sperimentale. Nessuna operazione su camera o supporti; **NON_INSTALLARE**.

**Contestualizzazione successiva, 6 novembre 2026:** `0x14A1FC` è chiamata anche dal ramo di chiusura AutoSceneLiveView `0x659B40`; ciò non prova un'attivazione durante lo scatto. [Analisi e limiti](S33_GUI_Tempo_Chiamante_Chiusura_LiveView_20261106.md).
