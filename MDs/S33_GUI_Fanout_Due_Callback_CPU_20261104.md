# Fan-out tasti con due callback originali — CPU emulata

Data: 2026-11-04. Firmware campione 1.1. Banco: [verificatore](../Python_Trace_Scripts/s33_verify_key_fanout_callbacks_cpu.py), [evidenze](../Risultati/GUI_S33/key_fanout_callbacks_cpu_20261104T104147470937Z/verified_evidence.json). Esito **38/38 PASS**; non installabile, nessuna prova hardware.

## Ambito

Il banco esegue su GNU ARC700 i byte originali, controllati contro i payload verificati anche dopo il link, di fan-out 0x16F6B0, callback 0x16E588 e 0x323A00, query tasti, getter modo e millicode. In ciascun caso impone un ordine diverso delle due callback nella tabella a dieci slot; altre celle zero. Passa pressioni e rilasci logici direttamente al fan-out, senza scanner né tasti fisici.

RAM, latch e modo sono sintetici; modo 0x2C, latch8/latch9/cella trigger 0. Il test impone flag globale anello, argomento fan-out e bit della classe a 1; 0x16BC90 e 0xD0CA4 restituiscono 0, 0xCB618 restituisce 1. I servizi 0xC9BF8, 0x16BC90, 0xD0CA4, 0xC68F0, 0xCB618, 0x169EB4, 0x16ED40 e 0x16F070 sono stub. Anche 0x17BC7C è uno stub che registra i quattro argomenti: la prova osserva una **chiamata all'anello**, non la sua consegna o persistenza. Il banco verifica conteggi, argomenti post/anello e contesto selezionato, non la GUI.

## Risultati sui quattro slot

Sono stati provati due ordini × due valori fixture di 0xC9BF8 × quattro classi × pressione/rilascio = 32 casi. `stato` è rispettivamente 1/0 e il rilascio ha evento pressione +1.

| Fixture 0xC9BF8 | Classe ed eventi | Osservazione |
|---|---|---|
| 0 | 11: 0x580/581; 14: 0x700/701; 67: 0x2180/2181; 78: 0x2700/2701 | Una chiamata allo stub anello con evento e argomenti attesi; nessun post. |
| 1 | 11 e 14 | Nessun post e nessuna chiamata allo stub anello. |
| 1 | 67 e 78 | Due post intercettati: `(0, 0x4006, classe)` e `(0, evento, stato)`; nessuna chiamata allo stub anello. |

Questi esiti valgono per entrambi gli ordini imposti e per le altre fixture indicate. Per 67/78 il secondo post dipende dalla fixture 0xCB618=1; non è una garanzia generale di recapito. Per 11/14 nel ramo 0xC9BF8=1 la callback 0x16E588 restituisce zero, impedendo l'anello. Quando 0xC9BF8=0 restituisce uno; con le guardie imposte il fan-out chiama lo stub anello. L'ordine effettivo sulla fotocamera non è determinato.

## Controlli di ordine

Altri sei casi usano classe 1/stato 1 e soglie 130 o 131 nel contesto di 0x323A00. Con questa callback prima, la sua restituzione zero impedisce l'invocazione di 0x16E588 (contatore stub 0xC9BF8=0). Con 0x16E588 prima e 0xC9BF8=1, i post previsti avvengono e il contesto di 0x323A00 resta immutato; con 0xC9BF8=0 la seconda callback aggiorna il contesto ai due lati della soglia. Questi casi verificano lo short-circuit nell'ambiente simulato e il significato delle sentinelle del contesto.

Durante lo sviluppo sono conservati un link fallito per sezioni RAM sovrapposte e una corsa fallita per un'aspettativa errata sullo short-circuit. Non sono risultati PASS; la matrice qui citata è successiva alla correzione.

## Limiti e prossimi passi

Non sono provati l'ordine runtime, gli altri callback, gli stati reali delle guardie, temporizzazione, concorrenza, GPIO, recapito alla GUI o comportamento di ISO/diaframma/tempo/monocromatico. Integrare scanner e coda originali con le due callback, poi seguire i post verso il dispatcher e le impostazioni; non inferire una mappa fisica dai bit sintetici. Stato del progetto: **NON_INSTALLARE**.
