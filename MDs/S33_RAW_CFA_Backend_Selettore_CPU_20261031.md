# S33 V1.1 — percorso CFA e selettore del backend, 31 ottobre 2026

Nel banco CFA la fixture di scrittura è stata spostata da `0x12BCC4` al servizio inferiore `0x12DE3C`. Rimangono quindi originali il dispatcher, `0x12BCC4` e `0x18B0BC`. Con geometria sintetica 4208 × 3152, i [sei casi GNU DSP sperimentale](../Risultati/HiddenMenu_RAW/cfa_backend_cpu_20261031T204449293802Z/verified_evidence.json) passano: per ciascun caso la fixture inferiore riceve handle `0x1234`, puntatore `0x2040000`, lunghezza attesa, puntatore al conteggio e **selettore 1**. Il banco verifica anche i due conteggi brevi e la successiva chiamata di chiusura fixture.

Questo selettore differisce da `0` osservato nel [banco distinto del writer RAW](S33_RAW_Writer_Conteggio_e_Backend_20261028.md). Le istruzioni mostrano che il ramo CFA imposta `r3=1` prima di `0x12BCC4`; `0x18B0BC` conserva 1 e lo passa al servizio inferiore. Non bisogna attribuire ai due percorsi comportamento equivalente soltanto perché condividono le routine di scrittura.

Lettura statica aggiuntiva di `0x12DE3C`: nel ramo che supera le guardie e l'acquisizione del contesto, il selettore viene limitato a 0..2, salvato nel campo `+0x5C` di un record indicizzato, e quel campo viene azzerato dopo la chiamata `0x1FA090`. La finestra `0x12DE3C..0x12DEFF` è stata confrontata byte per byte al dump (`SHA-256 4c17b3584316e39be72a43635e20aa32ad38c4344188b814814e586810fa385f`). Questo tratto è **statico**: il banco sostituisce l'ingresso `0x12DE3C`, non dimostra il significato del selettore né se `0x1FA090` aggiunga un header.

Una [prova successiva](S33_RAW_CFA_Selettore_Contesto_CPU_20261031.md) esegue anche `0x12DE3C` con servizi e volume sintetici e osserva 1 durante la chiamata inferiore e 0 dopo il ritorno.

Il primo tentativo `cfa_backend_cpu_20261031T204442000264Z` è FAIL: l'assert del banco assumeva erroneamente 0 dal writer RAW diverso; è stato corretto a 1 dopo aver controllato le istruzioni. Firmware invariato. Le regressioni [geometria](../Risultati/HiddenMenu_RAW/cfa_geometry_cpu_20261031T204458068341Z/verified_evidence.json) e [sei casi preesistenti](../Risultati/HiddenMenu_RAW/cfa_menu_dispatcher_cpu_20261031T204458067932Z/verified_evidence.json) sono PASS.

Nome, apertura, servizio inferiore, chiusura, contesto e conteggi sono fixture. Nessuna creazione di file, provenienza dell'header, capacità del buffer o scatto reale è verificata; **NON_INSTALLARE**. Riproduzione: `python3 Python_Trace_Scripts/s33_verify_cfa_menu_dispatcher_cpu.py --backend`.
