# S33 V1.1 — setter ISO e confronto con soglia, CPU emulata

Data 2026-11-04. Otto casi eseguono in sequenza il setter diagnostico originale `0xD03B8`, il convertitore originale `0x17C320`, il setter del parametro `0xDE78C` e il **frammento** originale `0xD8D0A..0xD8D38` di un consumatore identificato staticamente in `0xD8CA4`. Il banco chiama esplicitamente il frammento dopo il setter: non prova che la fotocamera esegua questi passaggi in questa sequenza. Le finestre e il pool originali sono verificati byte per byte dopo il link.

La tabella è sintetica: flag `+0=1`, soglia halfword `+2=125`, correttivo signed halfword `+4=-7`; il contesto restituito dal secondo servizio ha flag `+4=0`. Risultato del solo confronto:

| Indice setter | Valore software | Correttivo osservato |
|---:|---:|---:|
| 0 | 0 (Auto nel menu) | 0 |
| 1 | 50 | 0 |
| 6 | 125 | 0 |
| 7 | 140 | −7 |
| 19 | 1600 | −7 |
| 22 | 3200 | −7 |

In due ulteriori casi con valore 1600, disabilitare il flag della tabella oppure impostare a 1 il flag del secondo contesto produce correttivo 0. Il confronto usa `>` stretto, non `>=`; il valore della soglia 125 è una scelta del banco e **non** è un limite osservato nel firmware in camera. Il correttivo è letto con segno ed è acquisito in `r25` al termine del frammento. Il seguito originale a `0xD8D66` lo somma a un'espressione, come verificato staticamente nel [rapporto precedente](S33_GUI_ISO_Lettori_Priorita_e_Soglie_20261027.md); il seguito non viene eseguito in questa prova.

I due servizi che forniscono tabella e contesto sono stub; RAM, valori e ordine sono fixture. L'ingresso diretto salta il prologo della funzione intera e un'uscita sintetica cattura il registro prima del seguito. Nessuna conclusione sul valore reale della soglia, sulle unità del correttivo, sull'esposizione, sul guadagno analogico/digitale o sull'ISO nativo. Lo zero software non prova il comportamento dell'AE; 50 e 3200 non sono così dimostrati su sensore. Nessuna operazione su hardware o supporti. **NON_INSTALLARE**.

Riproduzione: `python3 Python_Trace_Scripts/s33_verify_iso_threshold_slice_cpu.py`. [Evidenze 8/8](../Risultati/GUI_S33/iso_threshold_slice_cpu_20261104T112659828444Z/verified_evidence.json). Regressione scanner handler 0x2180 [10/10](../Risultati/GUI_S33/key_scanner_handler2180_cpu_20261104T112659846656Z/verified_evidence.json).
