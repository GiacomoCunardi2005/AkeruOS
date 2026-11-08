# GUI V1.1 — conferma tempo e scrittori successivi, 28 ottobre 2026

Quattro sequenze GNU ARC700 collegano il tasto logico sintetico, coda, apertura della schermata diagnostica tempo, modifica da 120 a 121 e conferma originali a una successiva chiamata **esplicita del banco** a un altro setter originale. La conferma scrive 121.000 sia nella word diagnostica `0x365788` sia nel campo `0x37FBF4`; al termine la schermata diagnostica ritorna al descrittore `DEBUG MODE MENU` `0x987AF8`.

| Setter chiamato dal banco dopo la conferma | Ritorno | Word diagnostica | Campo `0x37FBF4` |
|---|---:|---:|---:|
| `0x1E1DC4(0)` | 0 | 121.000 | 0 |
| `0x1E1DC4(1.000.000)` | 0 | 121.000 | 1.000.000 |
| `0x1E1DC4(1.000.001)` | 1 | 121.000 | 121.000 |
| `0x17C49C(1)` | 0 | 121.000 | 500.000 |

Gli assert controllano i due campi prima e dopo conferma, esito del setter, campi successivi, ritorno del manager e stack. Il risultato unisce nella stessa esecuzione le precedenti prove separate di [conferma](S33_GUI_Tempo_Tasto_Modifica_Ritorno_CPU_20261028.md) e [setter concorrenti](S33_GUI_Tempo_Sovrascritture_e_Snapshot_20261027.md). Dimostra una possibile divergenza software sotto quell'ordine imposto, non che il display mostri il valore né che il setter venga chiamato dopo la conferma nella macchina reale.

PASS: quattro sequenze, 67.522 istruzioni nel modello. [Verificatore](../Python_Trace_Scripts/s33_verify_gui_time_confirm_overwrite_cpu.py), [casi](../Risultati/GUI_S33/time_confirm_overwrite_cpu_20261028T142606Z/cases.json), [manifest e traccia](../Risultati/GUI_S33/time_confirm_overwrite_cpu_20261028T142606Z/verified_evidence.json), [fixture](../Risultati/GUI_S33/time_confirm_overwrite_cpu_20261028T142606Z/fixture_patches.json). Finestre e dati considerati sono confrontati con il dump V1.1; DSP GNU v7 sperimentale.

Il tasto logico, gli eventi di modifica e conferma, i contesti e l'ordine dei setter sono sintetici; servizi di sincronizzazione, filtro, selezione, testo e disegno sono fixture. Non sono provati unità fisiche del tempo, scheduling, concorrenza, applicazione allo scatto, persistenza o comportamento hardware. Il sottomenù esposizione richiesto non è ancora implementato. **NON_INSTALLARE**.
