# S33 V1.1 — paginazione e scelta nella classe GUI 0x15

Analisi statica offline del 27 ottobre 2026, su payload originali con finestre
e record confrontati con `DUMPS/MainCode.dmp`. Gli indirizzi seguono la mappa
candidata V1.1; le condizioni riportate non dimostrano l'arrivo di un evento.

## Eventi e pagina condivisa

Il dispatcher di classe `0x15` usa la tabella `0x77F664`. Nella tabella,
`0x4401` chiama `0x631674`, che azzera il byte `0x681B6B`; questo stesso
byte è usato come indice di pagina nelle routine seguenti. Gli eventi iniziali
dei comandi diagnostici `KeyUp` e `KeyDown` sono rispettivamente `0x380` e
`0x400`; i secondi sono `0x381` e `0x401` ([prova dei comandi](S33_GUI_Tasti_Comandi_Eventi_20261027.md)).
L'associazione non identifica un interruttore fisico.

| Evento | Handler di classe | Comportamento statico |
| --- | --- | --- |
| `0x380` | `0x631BF0` | Se il bit `0x10` del risultato `0x1450D8(ctx,0x14)` è chiaro, decrementa la pagina se maggiore di zero. A pagina zero, torna all'ultima solo se `0x632664(ctx)` è maggiore di uno. |
| `0x400` | `0x631CA0` | Se il bit `0x20` del medesimo servizio è chiaro, avanza la pagina se l'indice calcolato è sotto il numero di record; altrimenti torna a zero solo se `0x632664(ctx)` è maggiore di uno. |
| `0x381`, `0x401` | `0x631C80`, `0x631D40` | Chiamano il servizio `0x1450D8(ctx,0x14)` e restituiscono zero; non scrivono la pagina nei corpi verificati. |

Dopo un cambiamento di pagina i primi due handler chiamano `0x145490(ctx)`.
Se una successiva lettura di `0x1450D8(ctx,0x14)` ha il bit `0x200`, chiamano
anche `0x14503C(ctx,8)` e `0x169D78` con rispettivamente `0x7CF4` o `0x7CF5`.
Il servizio può restituire valori diversi tra letture: non si assume stabilità.
Non sono state dimostrate le semantiche visive di questi servizi.

Per i valori positivi considerati qui `0x632664` calcola il numero di pagine
come `ceil((byte ctx+52 - byte ctx+47) / byte ctx+46)`. L'handler Down confronta
con `ctx+52` il valore a 8 bit `ctx+47 + ctx+46 * (pagina+1)`; mantiene la
troncatura a 8 bit. Il comportamento per geometrie alterate, divisore nullo o
aritmetica fuori dai valori studiati non è oggetto di questa conclusione.

## Due liste originali CaptureMenu

I byte iniziali delle due risorse e i loro record sono confrontati col dump:

| Risorsa | Dimensione pagina `+46` | Prefisso `+47` | Numero record `+52` | Pagine calcolate |
| --- | ---: | ---: | ---: | ---: |
| `0x4800` (`0x9801C0`) | 3 | 1 | 3 | 1 |
| `0x4801` (`0x980268`) | 4 | 0 | 4 | 1 |

**Se** l'evento `0x4401` è stato consegnato, pagina e geometria non sono state
modificate dopo l'inizializzazione e gli eventi raggiungono questa classe,
Up e Down non cambiano la pagina per entrambe le liste: Up vede zero e una
sola pagina; Down raggiunge o supera il numero di record e vede una sola
pagina. Non si deduce che i tasti non facciano nulla nell'intera GUI: altri
handler possono gestire o inoltrare gli eventi e lo stato runtime è ignoto.

## Selezione di uno slot

Le quattro coppie della stessa tabella sono `0x580 → 0x631878`,
`0x700 → 0x63195C`, `0x2180 → 0x631A38` e `0x2700 → 0x631B14`.
Gli handler usano gli slot 0, 1, 2 e 3, rispettivamente. Se `ctx+47` è
maggiore dello slot, usano direttamente lo slot come indice; altrimenti usano
`(pagina * ctx+46 + slot) & 0xFF`. Pertanto a pagina zero gli indici sono
0–3 in entrambe le liste; l'indice 3 è fuori dai tre record della `0x4800`.
Il limite e i bit 0 e 1 dei flag a `record+24` sono controllati prima di
selezionare; l'apertura è soggetta a ulteriori guardie già documentate nel
[rapporto sulle destinazioni](S33_GUI_CaptureMenu_Destinazioni_20261027.md).

L'associazione di `KeyMenu` a `0x700` riguarda il comando diagnostico, non
prova che un tasto fisico o il gestore di CaptureMenu consegni quell'evento
alla classe. Analogamente, `0x2180` e `0x2700` qui identificano eventi, senza
attribuire loro un tasto fisico. La [prova precedente](S33_GUI_CaptureMenu_Selezione_CPU_20261027.md)
eseguiva soltanto lo slot 0 con record copiati in un contesto sintetico e
non copriva il ramo `MULUDW`.

## Prove e limiti

[Verificatore](../Python_Trace_Scripts/s33_verify_gui_class15_paging.py),
[risultati e byte verificati](../Risultati/GUI_S33/class15_paging_static_20261027T175618Z/evidence.json),
[disassemblaggio](../Risultati/GUI_S33/class15_paging_static_20261027T175618Z/disassembly.txt).
Il verificatore ha dato **PASS**: controlla tabelle, ancore GNU, geometrie e
finestre confrontate con il dump; l'interpretazione dei rami è statica. Non
esegue CPU, servizi, coda eventi o renderer; non prova inizializzazione reale,
selezione visibile, display o hardware. Nessun firmware originale modificato;
candidati **NON_INSTALLARE**.
