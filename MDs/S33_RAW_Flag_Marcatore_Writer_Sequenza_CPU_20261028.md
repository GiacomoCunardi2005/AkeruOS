# S33 V1.1 — controlli RAW in sequenza CPU

28 ottobre 2026. Nove casi eseguono su GNU ARC700 le istruzioni originali da `0x1B91EC` fino all'epilogo, compresi i controlli del marcatore, le due letture successive del flag e i rami del writer. Codice originale confrontato con MainCode storico; contesto, stack, descrittori, selettore e servizi sono sintetici. **NON_INSTALLARE**.

| Flag iniziale e cambiamento imposto | Chiamate registrate al marcatore | Chiamate registrate al writer |
| --- | ---: | ---: |
| 0 invariato | 0 | 0 |
| 1 invariato | 1 | 1 |
| 2 invariato | 0 | 1 |
| 255 invariato | 0 | 1 |
| 1 → 2 tra i controlli | 1 | 1 |
| 2 → 0 tra i controlli | 0 | 0 |
| 2 → 1 tra i controlli | 0 | 1 |
| 2 invariato, secondo puntatore non nullo | 0 | 2 |
| 2 → 0 nel primo writer simulato, secondo puntatore non nullo | 0 | 1 |

Quando chiamato, il marcatore riceve puntatore sintetico, offset `0x1234`, dimensioni 4208 e 3152 e selettore 2. Ogni writer registrato riceve 26.527.232 byte richiesti, con selettore di modalità 3. I puntatori `0x2040000` e `0x2041000` sono identificatori sintetici non dereferenziati: non indicano RAM libera né fotogrammi. L'ultimo caso mostra che la lettura a `0x1B933A` influenza separatamente il secondo writer; il cambiamento del flag è **imposto dalla fixture**, non osservato nel servizio originale.

La fixture di `0x141ED8` restituisce 0 o 1; se restituisce 1, la fixture `0x159BF0` cambia intenzionalmente il byte e `0x141EBC` è una stub. Il campo locale `fp-204` è 16, quindi il ramo con valore 4 e il suo callback indiretto non vengono eseguiti. Il byte contesto `+0x0C` è posto a 0. Marcatore e writer sono registratori di chiamate, non eseguono i corpi originali e non accedono ai dati immagine; servizi di uscita sono stub. Si usa il modello DSP GNU v7 sperimentale. Non è dimostrato che i servizi originali mantengano o cambino il flag nel dispositivo, né che questo percorso sia raggiunto durante uno scatto. I casi di cambiamento misurano la dipendenza dai valori, non ne provano l'origine reale.

Riproduzione: `python3 Python_Trace_Scripts/s33_verify_raw_flag_gate_sequence_cpu.py`. [Risultato e limiti](../Risultati/HiddenMenu_RAW/flag_gate_sequence_cpu_20261028T143544Z/verified_evidence.json), [casi](../Risultati/HiddenMenu_RAW/flag_gate_sequence_cpu_20261028T143544Z/cases.json), [sostituzioni di laboratorio](../Risultati/HiddenMenu_RAW/flag_gate_sequence_cpu_20261028T143544Z/fixture_patches.json), [trace](../Risultati/HiddenMenu_RAW/flag_gate_sequence_cpu_20261028T143544Z/cases.trace). I precedenti tentativi `143520Z` e `143522Z` sono conservati come FAIL: errore host di hashing e allineamento dell'assembly del banco; non è stato modificato il firmware per aggirare il simulatore.

Non sono stati verificati buffer reale, purezza o formato RAW, conteggio effettivamente scritto, persistenza, JPEG o stesso scatto. Nessun accesso hardware o SD.
