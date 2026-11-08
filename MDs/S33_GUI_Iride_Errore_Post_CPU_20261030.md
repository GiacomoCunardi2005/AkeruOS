# Iride — fallimento della programmazione del completamento

Per il futuro menu f/, la prova GNU ARC700 `--post-fail` del [verificatore](../Python_Trace_Scripts/s33_verify_iris_claim_async_cpu.py) inietta il ritorno 7 nel servizio di post `0x145F28`. Acquisizione, richiesta asincrona e cleanup `0x18B9D4` eseguono codice Nikon V1.1; la memoria MMIO e i servizi esterni sono fixture. Il post non programma alcun callback reale. [Risultati dei due casi](../Risultati/GUI_S33/iris_post_failure_cpu_20261030T154503Z/cases.json), [manifest](../Risultati/GUI_S33/iris_post_failure_cpu_20261030T154503Z/verified_evidence.json), [fixture](../Risultati/GUI_S33/iris_post_failure_cpu_20261030T154503Z/fixture_patches.json).

| Iniziale → richiesto | Ritorno helper | Stato finale software | Generazione | Proprietà finale | GPIO sintetico finale |
|---|---:|---:|---:|---:|---:|
| 9 → 1 | 0 | 9 | `0x1235` | 0 | `0xA5A0` |
| 1 → 9 | 0 | 1 | `0x1235` | 0 | `0xA5A0` |

In entrambi i casi il codice passa prima per il ramo di richiesta, incrementa la generazione, tenta il post e poi entra nel cleanup originale; il callback differito `0x235AE4` non viene eseguito. Il cleanup comprende il corpo originale che interviene sul GPIO sintetico e cancella lo stato di movimento; la halfword di proprietà viene ripulita nel percorso esercitato. I rilasci di livello inferiore, i lock e il delay sono simulati. Stack conservato; nessun ingresso alla wait `0x158D04`.

Con queste condizioni un errore del post non conferma il nuovo stato, ma **non equivale a nessun effetto**: generazione e MMIO sintetico sono cambiati prima o durante il cleanup. L'interfaccia non deve trattare il ritorno 0 come completamento riuscito né riutilizzare la vecchia handle come se la generazione fosse invariata. Questo risultato non prova un errore del post sulla camera o l'efficacia fisica del cleanup; lo scheduler, l'ottica, il tempo reale e l'interazione con AE restano da verificare. Nessuna modifica alla fotocamera, SD o firmware originale; **NON_INSTALLARE**.

Regressione: `--post-fail` 2 casi, `--completion` 2 casi e modalità precedente 7 casi PASS; rispettive evidenze nelle directory con suffisso `20261030T154503Z`.
