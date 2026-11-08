# S33 V1.1 — scrittura CFA parziale e geometria, 31 ottobre 2026

La [prova precedente](S33_RAW_CFA_Lunghezza_Calcolo_e_File_20261031.md) confrontava la richiesta diagnostica con il payload del file. Il confronto diretto con un'ipotetica singola scrittura deve considerare anche la **dimensione totale** di `CFAi1012.raw`, 13.284.424 byte: non è dimostrato che l'header di 20.808 byte sia scritto separatamente dal backend reale.

Il [banco GNU](../Python_Trace_Scripts/s33_verify_cfa_menu_dispatcher_cpu.py), opzione `--geometry`, ha eseguito sei casi con 4208 × 3152 e flag diagnostico attivo. Per ciascuno dei due valori del contesto `+8`, la fixture di scrittura ritorna successo e riferisce alternativamente tutta la richiesta, 13.284.424 byte o 13.263.616 byte. [Sei casi PASS](../Risultati/HiddenMenu_RAW/cfa_geometry_cpu_20261031T204328443420Z/verified_evidence.json):

| Contesto `+8` | Richiesta | Conteggio riferito dalla fixture | Ramo di conteggio breve |
|---:|---:|---:|---|
| 2 | 26.527.232 | 26.527.232 | no |
| 2 | 26.527.232 | 13.284.424 o 13.263.616 | sì |
| 1 | 19.895.424 | 19.895.424 | no |
| 1 | 19.895.424 | 13.284.424 o 13.263.616 | sì |

Nei quattro casi brevi la traccia mostra il dispatcher caricare `0x700103` a `0x28D80A` e ritornare al chiamante; quest'ultimo prosegue fino alla chiamata di chiusura. Le fixture di apertura, scrittura e chiusura sono chiamate una volta ciascuna; la chiusura ritorna zero nel banco. La prova si arresta a `0x1E6ACC` e non verifica la continuazione successiva. Anche i [sei casi precedenti](../Risultati/HiddenMenu_RAW/cfa_menu_dispatcher_cpu_20261031T204328444940Z/verified_evidence.json) sono PASS.

Il ramo originale di apertura costruisce il nome e chiama `0x12BC20`; il dispatcher esegue poi una chiamata di scrittura a `0x12BCC4`. Nel banco questi servizi sono fixture: non si osserva se il backend reale crei un header, aggiunga altri dati, tronchi o persista un file. I conteggi brevi sono **imposti**, non rilevati nella fotocamera; il file reale non prova che questo percorso o errore si sia verificato. La capacità e la natura del buffer restano ignote. Modello DSP sperimentale, nessun accesso alla fotocamera: **NON_INSTALLARE**.

Una [prova successiva](S33_RAW_CFA_Backend_Selettore_CPU_20261031.md) esegue anche i due wrapper originali sotto `0x12BCC4` e mostra che il servizio inferiore riceve selettore 1; il servizio stesso rimane fixture.
