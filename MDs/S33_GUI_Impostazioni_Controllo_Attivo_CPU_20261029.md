# Impostazioni: effetto del controllo attivo sul dispatch

Il 29 ottobre 2026 ho esteso la [prova di apertura impostazioni](S33_GUI_Modello_Impostazioni_Apertura_CPU_20261029.md) inviando direttamente al dispatcher originale l'evento logico `0x700` dopo l'apertura sintetica di `GeneralSetupMenu`. Nelle due sequenze il contesto impostazioni osservato è 1, ma il puntatore al controllo attivo dopo l'apertura è ancora quello della lista sintetica precedente, costruita dal banco.

| Condizione del banco prima di `0x700` | Destinazione osservata |
|---|---|
| Controllo sintetico precedente conservato | `ChangeColorMenu`, descrittore `0x982064` |
| Controllo azzerato esplicitamente dal banco | `SoundSettingMenu`, descrittore `0x9A0A44` |

Entrambe le aperture iniziali restituiscono 1 con descrittore impostazioni `0x99242C`; l'evento successivo restituisce 1 e lo stack torna al valore precedente. Il banco controlla le destinazioni rispetto alla tabella originale e la traccia raggiunge gli handler `0x63195C` e `0x7EAB18`. I due casi sono sequenziali e condividono backing sintetico: non sono due avvii indipendenti. L'azzeramento è un intervento del banco, **non una correzione proposta per la fotocamera**; non è noto quale controllo debba essere attivo nel ciclo reale.

[Due casi PASS](../Risultati/GUI_S33/settings_navigation_cpu_20261029T053351Z/verified_evidence.json), [casi](../Risultati/GUI_S33/settings_navigation_cpu_20261029T053351Z/cases.json), [traccia](../Risultati/GUI_S33/settings_navigation_cpu_20261029T053351Z/cases.trace), [verificatore](../Python_Trace_Scripts/s33_verify_gui_settings_navigation_cpu.py). La prova esplorativa [053313Z](../Risultati/GUI_S33/settings_navigation_cpu_20261029T053313Z/verified_evidence.json) riportava PASS senza verificare la destinazione successiva: quel PASS copre solo le vecchie asserzioni di apertura e non va interpretato come navigazione impostazioni riuscita. Il tentativo [053333Z](../Risultati/GUI_S33/settings_navigation_cpu_20261029T053333Z/verified_evidence.json) è FAIL per una modifica del banco applicata al punto errato; è stato corretto prima della prova finale.

Il modello e la consegna dell'evento sono espliciti nel banco, il controllo iniziale, RAM, MMIO e vari servizi sono fixture. Non sono dimostrati tasti fisici, stato reale dei controlli, visualizzazione, ritorno al nuovo menu, modifica o persistenza delle impostazioni. Nessuna modifica a firmware originale o dispositivo; **NON_INSTALLARE**.
