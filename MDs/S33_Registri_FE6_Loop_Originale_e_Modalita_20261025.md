# Ciclo FE6 originale e produttore della cache modalità

25 ottobre 2026. Atlante `Risultati/Processor_Registers/20261025T103147Z/`:
611 voci, 64 posizioni di codifica core / 197 AUX / 350 indirizzi MMIO.
Mappa fisica incompleta, obiettivo attivo. Le posizioni core includono slot
opzionali/riservati: non sono64 registri fisici verificati.

## Esito

32 nuovi indirizzi MMIO hanno accessi halfword originali osservati:

- 28 scritture a FE60010..FE601C0, passo16. I selettori1..28 decimali
  (1..1Chex) sono generati dal ciclo firmware239F00 e inoltrati a2C5D30.
  Il chiamante conserva il proprio argomento e l’accessor scrive solo i
  bit12..13: `(argomento&3)<<12`, azzerando gli altri bit della halfword.
- Quattro letture a FEF0020, FE800BC, FED3000, FED3800, a monte del gate.
  Il codice originale riempie una cache RAM e calcola il valore poi letto
  dal getter1F0A6C. Non sono nomi o identificativi fisici accertati.

Due indirizzi già presenti, FE60240/FE60244, ricevono ulteriori prove dal
chiamante originale23A270. Totale34 indirizzi osservati in questa prova.

## Sequenza originale e ingressi dichiarati

Il verificatore esegue Main originale senza patch, collegando il frontend
esterno alla GNUlibsim esistente in sola lettura. Cache RAM423F00..423F0B,
flag36932C..36932D, parole grezze e argomenti del chiamante sono fixture.
Nessuna regione RAM è dedotta libera o fisicamente disponibile.

Con ready0 e due flag1,1, i percorsi originali sono:

1. 1F08D0 legge FEF0020 e conserva la halfword nel primo word della cache.
2. Il produttore1F0980 verifica `((word>>4)&FFhex)==Ahex`, usa il nibble basso per
   il proprio dispatch e può invocare1F090C per il secondo word.
3. FE800BC bits10..11 nonzero oppure FED3000 bits14..15 nonzero fanno
   scrivere0 nel secondo word. Altrimenti FED3800 fornisce la halfword.
4. Il firmware scrive la parola modalità a cache+8 e ready1 a cache+4.
   1F0A6C restituisce la metà alta;239F00 entra nel ciclo solo se vale2.

Le fixture A4/8 producono20002hex, A4/0 o i gate nonzero producono20004hex.
A0/8 produce10002hex, A8/0 produce30004hex, AC/0 produce40004hex.
90hex non supera il controllo iniziale e lascia modalità0.
Sono risultati software su ingressi sintetici; non identificano il SoC o
la modalità reale della fotocamera.

## CPU e controlli

Prova: `outputs/gnu_arc700/20261025T102702Z_7be1e788/verified_evidence.json`.
Undici scenari, ripetuti con osservatore disabilitato e abilitato:22 run,
11 coppie di tracce identiche byte per byte e208 accessi completati osservati.

Sei scenari attraversano ciascuno tutte28 le iterazioni originali:168 scritture
in totale. I valori scritti0,1000,2000,3000hex coprono le quattro combinazioni
del campo software12..13. Una cache già pronta salta le letture grezze e
mantiene il comportamento del ciclo. Modalità1,3,4 e ingresso non riconosciuto
saltano il ciclo; le loro letture a monte sono contate separatamente.

Il chiamante23A270 raggiunge setterbit8, getterbit9, scrittore completo e
clearbit8 del selettore24hex. La cellaFE60244 parte da200hex: è una fixture
esplicita che rende il getter nonzero, non una transizione periferica causata
dal setter. Nessun completamento o tempo hardware è simulato.

Il chiamante sintetico verifica dopo ogni ritorno SP e r13/r14/r15/r16.
Il verificatore controlla sequenza PC/op/indirizzo/valore, larghezza16, celle
finali, padding A5, cache e flag. Main rimane identico byte per byte.

## Audit e integrità

`evidence/fe6_original_loop_audit.json`: PASS. Gli indirizzi dei quattro pool
sono legati ai byte originali e agli accessi CPU. L’audit ridecodifica dal PC
osservato per evitare che i pool incorporati disallineino il listing lineare.
Confronta poi ordine/valori con le tracce e prova gli indirizzi1..1C del ciclo.
Una riga risultato per accesso in questi run continui; il profiler non è
usato come conteggio di istruzioni ritirate.

Ledger143file verificato; parent137file invariati. AUX guest invariati:
22indici,74siti run/PC verificati. GNU installazioni/config/sorgenti/build e
copie laboratorio conservati, originali invariati. Nessun accesso a dispositivo,
flash, NAND/vendor, reset USB o scrittura SD. NON_INSTALLARE invariato.

Script riproducibili in `Python_Trace_Scripts/`:
`s33_verify_fe6_original_loop.py`, `s33_audit_fe6_original_loop.py`,
`s33_integrate_fe6_original_loop.py`. Rapporto e CURRENT sono fuori dal ledger
immutabile dell’atlante; checkpoint PMB registrato separatamente.

## Limiti e seguito

Restano aperti gli altri percorsi calcolati FE6/FF7/FFB/FFC, le famiglie AUX
parametrizzate e i candidati codice/dati. La configurazione fisica/BCR,
i veri ingressi dei gate e le semantiche hardware restano sconosciuti.
611 voci software non delimitano l’universo dei registri del processore.
