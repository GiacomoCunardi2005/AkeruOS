# GUI — conferme diagnostiche e calcolo esposizione

Il 30 ottobre 2026 ho collegato nel simulatore GNU ARC700 DSP sperimentale le conferme originali delle schermate diagnostiche ISO (`0x7D25B0`, evento `0x4801`) e tempo (`0x7D2394`, evento `0x580`) al chiamante del calcolo `0xD8CA4`. Il banco inietta gli eventi, sceglie la voce ISO 125 attraverso un controllo sintetico e imposta il valore di lavoro del tempo; **dopo** le due conferme chiama esplicitamente `0xD8CA4`. Non è una sequenza attivata autonomamente sulla fotocamera.

Le due conferme chiamano i setter originali e richiedono ciascuna l'apertura GUI a `0x1453E4`, qui sostituita con registratore; il banco verifica due richieste e ultima destinazione `0x36`. Il chiamante crea la copia del contesto, chiama il calcolo, copia il buffer e ritorna. Sei casi PASS:

| Valore tempo immesso | Altra variazione sintetica | Tempo buffer finale `+52` | ISO software `+64` | Byte confronto `+80` |
|---:|---|---:|---:|---:|
| 42 | base | 42.000 | 125 | 1 |
| 84 | base | 84.000 | 125 | 1 |
| 42 | limite 20.000 | 20.000 | 125 | 1 |
| 42 | campo signed `+0x0E` = 100 | 44.941 | 125 | 1 |
| 42 | seconda word confronto = 42.000 | 42.000 | 125 | 0 |
| 42 | seconda word confronto = 50.000 | 42.000 | 125 | 0 |

I valori immessi sono moltiplicati per 1000 dal callback Nikon: non è stabilita l'unità fisica. Il numero 125 è l'output software della voce scelta, non una misurazione del sensore. Il test verifica una sola voce ISO, non tutte le impostazioni.

Oltre alla fixture GUI e al controllo sintetico, il banco usa una copia byte per `0x128C20`, una callback indiretta e `0x18C634` con ritorno zero. A `0xD8E22` un registratore nella copia laboratorio salva il primo risultato e riproduce il ramo sintetico `r16=0`; i registri temporanei usati sono preservati. RAM, tabella, limite e argomenti sono sintetici. Tracce verificano entrambi i callback, il setter tempo e ISO, `D8CA4 → F6F54 → FDA28`, copia finale e ritorno; una sola chiamata a `FDA28` in questi casi.

[Verificatore](../Python_Trace_Scripts/s33_probe_gui_iso_time_confirm_to_calc_cpu.py), [manifest caso 0](../Risultati/GUI_S33/gui_iso_time_confirm_to_calc_probe_0_20261030T102258Z/verified_evidence.json), stessa cartella con numeri 1–5 per gli altri casi. Il primo tentativo `102235Z` è stato interrotto: il banco riutilizzava lo stesso nome file per il codice della fixture e per i dati del controllo, provocando un ciclo sintetico; il banco finale usa nomi distinti.

Non sono provati tasti fisici, apertura reale delle schermate, attivazione naturale di `D8CA4`, concorrenza, AE, uso del buffer nello scatto o unità fisiche. Firmware e dispositivo non modificati; **NON_INSTALLARE**.
