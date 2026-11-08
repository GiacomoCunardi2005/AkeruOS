# Scanner 0x700 → transizione e inizializzazione ISO — CPU emulata

Data 2026-11-04, firmware campione 1.1. [Verificatore](../Python_Trace_Scripts/s33_verify_key_scanner_iso_lifecycle_cpu.py), [evidenze 4/4 PASS](../Risultati/GUI_S33/key_scanner_lifecycle_real700_cpu_20261104T110806082943Z/verified_evidence.json), [regressione gate manager 8/8 PASS](../Risultati/GUI_S33/key_scanner_manager700_cpu_20261104T110811707185Z/verified_evidence.json). **NON_INSTALLARE**.

## Percorso e condizioni

Il banco estende [scanner → CaptureMenu → handler 0x700 → manager](S33_GUI_Scanner_Handler700_Manager_Gate_CPU_20261104.md) caricando byte originali per il callback ISO 0x7D252C, i servizi lifecycle 0x16A05C/0x16A188/0x16A1FC, l'handler ISO 0x7D2564, il getter 0x17C3F0, la ricerca 0x641128, i 24 record ISO e le relative tabelle. I byte caricati sono confrontati con i payload verificati dopo il link. Nei casi positivi le tracce attestano 0x4403, 0x4401 e 0x4405, e l'esecuzione di 0x7D252C, 0x16A05C, 0x16A188, 0x7D2564 e 0x641128; non si afferma che 0x16A1FC sia stato eseguito in questi casi.

Finestra iniziale CaptureMenu 0x9802AC, controllo attivo zero, tabella finestre, due ordini delle callback, snapshot di input, latch e guardie sono fissati dal banco. CAD5C=2 e CD9C8=0x3F sono stub; l'indice ISO software iniziale è **6**, imposto in RAM. Il controllo lista è sintetico, con count 24 e puntatore ai record originali. Estrazione e dispatch degli eventi sono chiamati esplicitamente dal banco. Servizi di enumerazione risorse, focus, recupero controllo, selezione, filtro post speciale 0x17BE80, lock e segnale sono stub: la selezione viene registrata, non applicata a un controllo reale.

## Risultato

Due ordini × busy del manager 0/1 = quattro casi:

| Busy | Osservazione verificata |
|---:|---|
| 0 | La pressione logica 0x700 porta il manager a impostare corrente 0x989FCC (descrittore ISO); il percorso lifecycle originale raggiunge 0x7D2564, che cerca l'indice software 6 nei record originali e chiede allo stub di selezione la posizione **7** del controllo sintetico. |
| 1 | Il manager rifiuta la transizione; corrente rimane 0x9802AC e lo stub di selezione non viene chiamato. |

Nel caso busy=0 il manager genera un'ulteriore notifica 0x4409: il banco verifica il terzo record in coda `(0x989FCC, 0x4409, 0)` e gli indici aggiornati. La notifica rimane in coda: non è estratta o consegnata in questa prova. Il rilascio 0x701 è stato generato ed estratto prima del dispatch della pressione, ma non consegnato alla nuova finestra. Posizione 7 e indice software 6 **non sono una misura ISO fisica**.

## Sviluppo e limiti

Il caso positivo è stato raggiunto dopo aver caricato le funzioni mancanti documentate nella [diagnosi timeout](S33_GUI_Manager700_Diagnosi_Timeout_20261104.md). Una corsa intermedia raggiungeva già la scrittura della corrente ISO ma si fermava nel servizio 0x17BE80 non caricato; nel banco finale questo servizio è uno stub che ritorna zero. L'aspettativa iniziale di due record è stata corretta a tre dopo aver osservato la notifica 0x4409; questa correzione è verificata nel record e negli indici, non semplicemente ignorata.

Non si dimostrano la creazione effettiva dei controlli, la consegna di 0x4409, il rendering, il valore o l'applicazione dell'ISO al sensore, la persistenza, l'ordine reale delle callback, i tasti fisici o l'hardware. Il passo successivo è consegnare rilascio e 0x4409 alla finestra ISO, poi collegare una selezione dell'utente ai setter e verificarne valori e stato senza assumere le fixture come realtà.
