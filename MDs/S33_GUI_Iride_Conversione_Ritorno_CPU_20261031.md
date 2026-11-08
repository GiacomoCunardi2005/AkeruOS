# S33 V1.1 — conversione degli stati iride, 31 ottobre 2026

In alcuni percorsi il firmware usa `0xFF720(1,3,valore)` per convertire un valore iride; un altro frammento usa `0xFF720(3,1,valore)` per ricavarne quello da richiedere. Il [banco](../Python_Trace_Scripts/s33_verify_iris_conversion_cpu.py) chiama in sequenza getter originale `0x18B8D4`, le due conversioni originali e controlla il risultato. La sequenza di andata e ritorno è **imposta dal banco**: non dimostra che quelle chiamate consecutive avvengano durante uno scatto.

| Contesto del banco | Ingresso getter | Conversione 1→3 | Ritorno 3→1 |
|---|---:|---:|---:|
| Puntatore tabella nullo | 1 | 0 | 1 |
| Puntatore tabella nullo | 0, 9 o 255 | 1 | 9 |
| Tabella sintetica | 1 | 10 | 1 |
| Tabella sintetica | 9 | 20 | 9 |
| Tabella sintetica | 0 o 255 | 10 | 1 |

Gli [otto casi GNU ARC700](../Risultati/GUI_S33/iris_conversion_cpu_20261031T205627047631Z/verified_evidence.json) passano senza patch del codice originale; byte iniziale e puntatore sono sintetici. La tabella del banco contiene riga `+4 = [1,9,9,32]` e riga `+12 = [10,20,30,40]`: per il 9 duplicato viene scelto il primo riscontro. Il ritorno di un valore sconosciuto può quindi coincidere con 1 o 9 a seconda del contesto di conversione: da questo risultato non si può dedurre che il valore originale fosse valido o che l'ottica si sia mossa.

Il ramo `0xFDC9E` studiato nella [prova precedente](S33_GUI_Iride_Tabella_Calcolo_CPU_20261031.md) chiama `0xFF720(3,1,...)` solo con puntatore non nullo: la seconda chiamata con puntatore nullo di questa prova è una chiamata diretta del banco, utile a descrivere la funzione ma non a ricostruire quel ramo. La tabella effettiva, il suo produttore, l'interazione con AE e la corrispondenza con i valori f/ fisici sono ignoti. Nessun sensore o attuatore è stato eseguito; **NON_INSTALLARE**.

Riproduzione: `python3 Python_Trace_Scripts/s33_verify_iris_conversion_cpu.py`.
