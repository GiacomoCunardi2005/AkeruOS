# S33 V1.1 — origine del byte che sceglie il marcatore RAW

28 ottobre 2026. Tre casi offline GNU ARC700 eseguono il frammento originale `0x1B8F82` e il prefisso di `0xDF304`, con snapshot e frame sintetici. **NON_INSTALLARE**.

`0xF6F14` restituisce il puntatore `0x380574`. `0xDF304` copia 240 byte dalla posizione `0x380574 + 720` e copia il byte della posizione 208 della copia nel byte 0 dell'output. Il chiamante `0x1B8FA6` trasferisce tale byte in `0x368790 + 0x0C` (`0x36879C`), che il marcatore confronta poi con `0x0B`. Quindi, se puntatore e copia sono quelli esaminati e non intervengono modifiche concorrenti, la sorgente è `0x380914`.

Nel banco i valori sorgente 0, 11 e 202 arrivano al byte del contesto, con byte vicini differenziati. `0x128C20` e la lettura originale sono eseguite, ma un trampolino termina anticipatamente `0xDF304` dopo il primo byte e un servizio intermedio è fixture. Il banco invoca direttamente il frammento, non lo scatto completo: non prova il produttore del valore dello snapshot, la stabilità durante l'acquisizione o il valore reale in una modalità fotografica. Stato dello scatto e byte del marcatore sono campi distinti; non si deve assumere che siano uguali.

Riproduzione: `python3 Python_Trace_Scripts/s33_verify_raw_marker_context_source_cpu.py`. [Casi](../Risultati/Mono_RAW/raw_marker_context_source_cpu_20261028T150028Z/cases.json), [fixture](../Risultati/Mono_RAW/raw_marker_context_source_cpu_20261028T150028Z/fixture_patches.json), [script](../Python_Trace_Scripts/s33_verify_raw_marker_context_source_cpu.py). Nessuna fotocamera, SD o immagine reale è coinvolta nella prova CPU.
