# Iride — transizioni degli stati letti dal pannello, 28 ottobre 2026

Il pannello iride legge le richieste logiche tramite il getter originale `0x16F920`. Il banco esegue in sequenza il callback `0x1406D0`, il normalizzatore e il commit originali, la ricerca delle transizioni nei 16 record a `0x392F04`, lo scrittore `0x16F72C` e il getter reale. Gli snapshot sono passati direttamente al callback, non acquisiti dal lettore hardware.

| Indice letto dal pannello | Bit del record | Getter dopo attivazione / rilascio sintetici |
|---:|---:|---:|
| 7 | 20 | 1 / 0 |
| 8 | 16 | 1 / 0 |
| 9 | 21 | 1 / 0 |
| 10 | 15 | 1 / 0 |

Per ciascun caso il banco parte con coppia precedente zero e gate predisposti, inietta un solo bit attivo nel valore complementato dal callback e poi inietta lo stato zero. Il byte dell'indice 4 è inizializzato a `0x5A` come controllo e resta tale. L'indice 4 **non compare nei 16 record originali esaminati**: questo non esclude altri scrittori o percorsi, ma significa che la prova dei quattro record non spiega il produttore dell'uscita del pannello. Le associazioni ai pulsanti fisici non sono dimostrate.

Quattro casi PASS, 8.255 istruzioni, nessun fault, stack conservato. [Verificatore](../Python_Trace_Scripts/s33_verify_iris_shadow_transitions_cpu.py), [casi e manifest](../Risultati/GUI_S33/iris_shadow_transitions_cpu_20261028T145037Z/verified_evidence.json), [trace](../Risultati/GUI_S33/iris_shadow_transitions_cpu_20261028T145037Z/cases.trace), [fixture](../Risultati/GUI_S33/iris_shadow_transitions_cpu_20261028T145037Z/fixture_patches.json). Finestre e tabella sono confrontate col dump V1.1; hash di trace, casi, fixture e snapshot coincidono col manifest.

La [catena statica precedente](S33_Iride_Consumatori_Registrazioni_Evento_3200002.md) collega il monitor al task `MCUCTRL_Task` e al callback; questo banco non esegue quel task, il monitor o la lettura MMIO, né dimostra che operino contemporaneamente al pannello. I suoi snapshot iniettati direttamente non sono una dimostrazione della loro raggiungibilità dalle due halfword fisiche. Lock, filtro e servizi sono fixture, RAM e DSP sono modelli. Restano da verificare produttore dell'indice 4, scheduler, ingressi fisici, display e mossa ottica. **NON_INSTALLARE**.
