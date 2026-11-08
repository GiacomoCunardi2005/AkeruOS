# S33 V1.1 — campo tempo: scritture e snapshot

27 ottobre 2026. Analisi statica dei payload originali V1.1, confrontati nelle finestre considerate con `DUMPS/MainCode.dmp`, e 14 scenari GNU ARC700 su RAM sintetica. Gli indirizzi e le conclusioni riguardano questa versione. Il nome «tempo» deriva dalla schermata diagnostica: l'unità fisica, l'effetto sul sensore e l'ordine reale delle attività non sono dimostrati.

## Più scrittori dello stesso campo

`0xD03E0(v)` scrive `v` nella word `0x365788` e passa `v` a `0xDE7B4`, che scrive `[0x37FBD0+0x24] = v` (`0x37FBF4`). Il getter `0xD0400` legge la prima word; `0xDE7D0` legge la seconda. Altri percorsi originali possono scrivere la seconda senza passare da `0xD03E0`:

- `0x17C49C` salva l'indice in `0x367BC7` e lo inoltra anche a `0xDE548`; per indici 0–8 seleziona una word e chiama `0xDE7B4`. Per indice superiore a 8 restituisce 1 senza quella chiamata. I risultati sono nella tabella seguente.
- `0x1E1DC4(v)` confronta `v` come unsigned con 1.000.000: se non è superiore chiama `0xDE7B4(v)`; altrimenti restituisce 1 senza scriverlo. Anche zero è accettato. Il chiamante `0x1E1CDE` lo usa, con guardie e azioni diverse, per un valore di struttura o per 1000.
- `0xC9F0E` chiama `0xDE7B4(0)` nel percorso che lo contiene. `0xCA6EC` lo chiama con il campo `+0x18` di un record, eventualmente aggiornato dal debug come descritto sotto. `0x323E72` lo chiama solo in un ramo con condizioni e valore da una struttura: non si assume che quel ramo sia raggiunto durante uno scatto ordinario.
- `0xDE730(a,b,c)` scrive il terzo argomento `c` nello stesso `+0x24`, oltre a un byte e una halfword vicini. Non è stata stabilita una sequenza runtime che lo invochi dopo la scelta nel menu.

| Indice `0x17C49C` | Word scritta |
| --- | ---: |
| 0 | 0 |
| 1 | 500.000 |
| 2 | 1.000.000 |
| 3 | 1.500.000 |
| 4 | 2.000.000 |
| 5 | 3.000.000 |
| 6 | 4.000.000 |
| 7 | 6.000.000 |
| 8 | 8.000.000 |

Nel banco si imposta prima `0xD03E0(42000)` e si chiama uno di questi setter su ogni caso: tutti i nove indici validi della tabella e i valori ammessi 0 e 1.000.000 cambiano `0x37FBF4`, lasciando `0x365788=42000`. Indice 9, 1.000.001 e `0xFFFFFFFF` restituiscono errore e lasciano entrambi i campi a 42000. **14/14 PASS**. Le chiamate sono ordinate artificialmente dal banco; provano la possibilità di divergenza, non che si verifichi sulla fotocamera.

## Salvataggio e ripristino condizionale

Per un record non nullo, il percorso `0xCA5DC` salva a `record+0x18` il risultato di `0x17C480`. Il percorso `0xCA654`, sempre per record non nullo, chiama prima `0x17C49C(record byte +0x0C)`. Dopo altre chiamate, legge `0xD0400`: se la word debug è non zero la rilegge e la copia in `record+0x18`; infine passa quel campo a `0xDE7B4`. Se la word debug è zero, usa il valore già presente nel record. Nell'ordine statico di questo percorso, l'ultima chiamata può quindi prevalere sulla precedente; non si conoscono ordine delle altre attività, eventuali accessi concorrenti o permanenza finale.

La lettura `0x17C480` non equivale a leggere direttamente `0x37FBF4`: chiama `0xDF47C` con un buffer locale e ritorna la word all'offset `+0x20` del buffer. `0xDF47C` copia 240 byte da `0x380574+960` in RAM locale e ricava la word restituita dall'offset 52 della copia, dunque dall'indirizzo sorgente candidato `0x380968`; la sorgente appartiene a un'altra area. Il codice a `0xDBE06` copia 240 byte da un buffer di stack verso l'area `0x380574+960`, dopo chiamate che possono alterare quel buffer. Non è stato dimostrato quando la copia avviene, né una relazione deterministica tra campo richiesto e valore dello snapshot. Il percorso `0xD5AA4` inizializza/aggiorna ulteriormente l'area chiamando `0xDB7B0`.

## Prove e limiti

[Verificatore](../Python_Trace_Scripts/s33_verify_gui_time_overwrites_cpu.py), [14 casi](../Risultati/GUI_S33/time_overwrites_cpu_20261027T214115Z/cases.json), [traccia](../Risultati/GUI_S33/time_overwrites_cpu_20261027T214115Z/cases.trace), [finestre disassemblate](../Risultati/GUI_S33/time_overwrites_cpu_20261027T214115Z/gnu_windows.txt) e [metadati](../Risultati/GUI_S33/time_overwrites_cpu_20261027T214115Z/verified_evidence.json). Le finestre supplementari sono confrontate con il dump nello script; la lettura statica non dimostra un'esecuzione completa dei percorsi. Il banco richiama direttamente le routine originali con RAM e valori sintetici e non emula interfaccia, scheduling, AE o hardware. Le grandezze numeriche non sono valori fisici verificati. Nessun firmware è stato alterato né alcuna operazione sulla fotocamera o SD effettuata. Candidati **NON_INSTALLARE**.
