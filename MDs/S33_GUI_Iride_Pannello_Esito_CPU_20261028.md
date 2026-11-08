# Pannello diagnostico iride: tasti logici e stato — 28 ottobre 2026

Il ciclo diagnostico originale V1.1 `0x2C5074` interroga i tasti logici 9 e 10: quando il 9 risulta attivo, invia la stringa `Iris status: Big` al servizio testo e chiama il setter originale `0x18B85C(1)`; quando è attivo il 10, invia `Iris status: Small` e chiama `0x18B85C(9)`. Il pannello presenta anche il testo `Iris: Left/Right`, ma questo da solo non identifica elettricamente i due interruttori né prova l'assegnazione 9/10 alle direzioni fisiche.

Quattro sequenze CPU passano con getter dei tasti e servizi di attuazione simulati:

| Stato iniziale | Tasto logico | Etichetta richiesta | Richiesta | Risultato fixture | Stato software finale |
|---:|---:|---|---:|---|---:|
| 9 | 9 | Big | 1 | accettata | 1 |
| 1 | 10 | Small | 9 | accettata | 9 |
| 9 | 9 | Big | 1 | rifiutata | 9 |
| 1 | 10 | Small | 9 | rifiutata | 1 |

**La stringa è inviata prima della chiamata al setter**: nei due casi di rifiuto il testo richiesto non corrisponde allo stato software finale. Un'interfaccia futura non deve trattare quella scritta come conferma della commutazione. Anche la cella software non è una misura del movimento ottico; completamento, concorrenza AE e stato fisico restano da verificare.

Il [manuale S33](../output/pdf/Archivio_AI/pdf/Nikon_S33_Reference_Manual_En05_03cc47d1917e.pdf), pagina stampata 117 (PDF 139), descrive un filtro ND a controllo elettronico con due passi f/3.3 e f/6.6 in grandangolo. Questa è una specifica del prodotto, non una dimostrazione che gli indici 1/9 corrispondano rispettivamente a quei numeri, né che esista un diaframma continuo o che il comando manuale prevalga sull'AE. Non attribuire f/ numerici agli indici senza altre prove.

[Verificatore](../Python_Trace_Scripts/s33_verify_iris_panel_key_cpu.py), [risultati, trace e fixture](../Risultati/GUI_S33/iris_panel_key_cpu_20261028T093015Z/). Le finestre e stringhe nel test sono confrontate con `MainCode.dmp`; il getter tasti riproduce una sequenza sintetica e testo, acquisizione, richiesta e pulizia sono fixture. Nessun pulsante, display, GPIO, lente o foto verificato su hardware. **NON_INSTALLARE**.
