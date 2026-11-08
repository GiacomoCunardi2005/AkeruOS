# S33 — puntatori dei tre stadi e registri dei buffer

Analisi statica V1.1, 19 ottobre 2026. Continuazione del [gruppo interrupt](S33_Gruppo_6000_Abilitazione_e_Interrupt_Padre.md) e dei [controlli di avvio](S33_Transizioni_Controlli_Stadi_Avvio_e_Arresto.md). Nessun accesso hardware.

## Risultato

Collegati i record runtime dei tre stadi a **11 coppie di registri halfword**, con scrittura prima dei 16 bit bassi e poi dei 16 alti. Il task seleziona tre puntatori dalla banca `0x392288` e li instrada in modo diverso secondo il campo **C+`0x90`**, con C=`0x367490`.

Nel ramo normale qui seguito, C+`0x90`=0 avvia lo stadio del bit `0x2000` con la terna selezionata; C+`0x90` diverso da0 salta questo stadio e usa la terna nei record degli stadi successivi. Non si attribuiscono ancora direzione lettura/scrittura, formato colore o nomi fisici ai registri. Circa 10% funzionale AkeruOS, invariato.

## 1. Record e riferimenti PCL scalati

Il task lega i registri alle seguenti aree:

| Registro | Record / impiego | Base |
|---|---|---|
| r16 | input runtime stadio `0x2000` | `0x4453CC` |
| r20 | input runtime stadio `0x800` | `0x445358` |
| r18 | input runtime stadio `0x1000` | `0x445368` |
| r13 | base usata per store che ricadono nei due record precedenti | `0x445318` |

Le istruzioni `ld.as [pcl,...]` a `0x15D032/36/3A` richiedono offset moltiplicato per4. Il calcolo esplicito usa PCL allineato4 e risolve i pool `0x15D30C/304/308`. I commenti GNU non scalati non sono stati usati come indirizzi effettivi.

Il task scrive le dimensioni `0x10` e `0x18` alle basi dei record `0x800/0x1000`. I servizi verificano questi valori prima di usare i campi. Il record `0x2000` ha invece tre parole puntatore a +0/+4/+8 e flag byte a +C/+D/+E/+F.

## 2. Terna selezionata e ramo di controllo

Sia **i = byte a C+`0x51`**. Il task calcola `12*i` tramite shift2 seguito da `add1` della quantità con sé stessa. La terna proviene da:

```text
T(i) = 0x392288 + 12*i
P0 = parola[T(i)+0]
P1 = parola[T(i)+4]
P2 = parola[T(i)+8]
```

La dimensione del campo indice è provata; il limite globale della banca e la capienza dei buffer non lo sono. Non viene dichiarato che ogni valore byte sia un indice valido.

Nel ramo che raggiunge `0x15D3BE`, dopo le precedenti guardie di modalità:

- se **C+`0x90`=0**, scrive P0/P1/P2 nel record `0x4453CC`, imposta i tre flag a1 e chiama `0x24A6CC`;
- se **C+`0x90` diverso da0**, salta la chiamata e segnala direttamente bit `0x2000` dell'evento task a `0x15D410`.

Gli store `st.as` con offset `-249/-248/-247` dalla base `0x4457B0` ricadono precisamente in `0x4453CC/D0/D4`: anche qui l'offset è scalato per4.

Questa conclusione vale per il ramo selezionato. Altri campi, fra cui C+`0x84` e C+`0xA8`, possono scegliere i bypass già descritti nel [protocollo evento](S33_Protocollo_Evento_Task_Azzeramenti_e_Bypass.md).

## 3. Instradamento verso i record successivi

Il tratto `0x15D420..478` usa di nuovo C+`0x90`:

| Campo runtime | Con C+`0x90`=0, valore letto da | Con C+`0x90` diverso da0 |
|---|---|---|
| stadio800 +8 (`0x445360`) | parola `0x445380` | P0 |
| stadio800 +C (`0x445364`) | parola `0x445384` | 0 |
| stadio1000 +8 (`0x445370`) | parola `0x445394` | P1 |
| stadio1000 +C (`0x445374`) | parola `0x445398` | 0 |
| stadio1000 +10 (`0x445378`) | parola `0x4453A8` | P2 |
| stadio1000 +14 (`0x44537C`) | parola `0x4453AC` | 0 |

Le celle della seconda colonna sono accessi scalati dalla base `0x444FB4`, con indici243/244/248/249/253/254. Sono state risolte come indirizzi delle celle: i loro valori runtime e i produttori completi restano da ricostruire.

Gli alias r13+`0x48/4C/58/5C/60/64` corrispondono ai campi dei record della prima colonna. Poi il task chiama `0x24B230(r20)` e `0x24BA5C(r18)` a `0x15D47A/488`. Nei rami con ritorni ammessi queste chiamate precedono l'attesa finale già documentata; questo ordine CPU non dimostra le dipendenze fisiche fra i tre motori.

L'origine dei campi runtime +4 di questi due record non è risolta qui.

## 4. Campi runtime e coppie MMIO

### Stadio associato a 0x2000

`0x24A6CC` copia 16 byte da `0x4453CC` a configurazione `0x50C1F8+0x4C = 0x50C244`. Nel ramo con tutti e tre i flag nonzero, già predisposto dal task sopra, la programmazione è:

| Campo runtime | Setter | Registri basso16 / alto16 |
|---|---|---|
| +0 | `0x2E2E00` | `0x0FFC2028 / 0x0FFC202C` |
| +4 | `0x2E2EB4` | `0x0FFC2050 / 0x0FFC2054` |
| +8 | `0x2E2F68` | `0x0FFC207C / 0x0FFC2080` |

Il secondo setter è invocato indirettamente tramite il pool `0x24A8EC`, con argomento nel delay slot. Con altre combinazioni dei flag il servizio può multiplexare il puntatore sul setter `0x2E2EB4`; questa tabella non viene estesa universalmente a quei rami.

### Stadio associato a 0x800

Il servizio `0x24B230` richiede record nonzero con dimensione iniziale `0x10`, oltre allo stato ammesso. Usa configurazione persistente `0x50C254` per le guardie:

| Campo runtime | Condizione locale | Setter | Registri basso16 / alto16 |
|---|---|---|---|
| +4 | configurazione+4=1 | `0x2E3A74` | `0x0FFC4070 / 4074` |
| +8 | nel tratto ammesso | `0x2E3AE8` | `0x0FFC40C0 / 40C4` |
| +C | configurazione+8=1 | `0x2E3B5C` | `0x0FFC40DC / 40E0` |

I valori di ritorno dei setter non sono confrontati nel tratto, ma questi corpi sono semplici programmatori di due halfword, non servizi che attestano il completamento del trasferimento.

### Stadio associato a 0x1000

Il servizio `0x24BA5C` richiede record nonzero con dimensione `0x18`. Le guardie seguenti sono espresse rispetto alla configurazione **`0x50C290`**, anche quando il codice usa la base precedente `0x50C254` con offset più grandi:

| Campo runtime | Condizione locale | Setter | Registri basso16 / alto16 |
|---|---|---|---|
| +4 | configurazione+4=1 | `0x2E3DC4` | `0x0FFC3070 / 3074` |
| +8 | nel tratto ammesso | `0x2E3E38` | `0x0FFC30C0 / 30C4` |
| +C | configurazione+8 diverso da0 | `0x2E3EAC` | `0x0FFC30DC / 30E0` |
| +10 | configurazione+40=0 | `0x2E3ED4` | `0x0FFC3100 / 3104` |
| +14 | configurazione+8 diverso da0 e +40=0 | `0x2E3F48` | `0x0FFC311C / 3120` |

Gli offset delle tabelle sono esadecimali. Lo zero scritto dal task nei campi opzionali non implica necessariamente la mancata scrittura hardware: il comportamento dipende anche da queste guardie persistenti.

## 5. Verifica dei setter e limiti

Tutti gli 11 setter qui selezionati conservano r0, estraggono i 16 bit bassi, eseguono il primo `sth.di`, spostano la copia di16 e fanno il secondo `sth.di`. Non contengono confronti locali con zero, controlli di allineamento o polling. Questo non esclude controlli superiori né assegna un contratto sicuro per valori arbitrari.

I due store separati non vengono trattati come un aggiornamento atomico. Non sono dimostrati traduzione degli indirizzi, coerenza cache, lunghezza o ultimo uso dei buffer.

[Script](../Python_Trace_Scripts/s33_trace_stage_buffer_registers.py), [JSON](../Ghidra_Results/ghidra_reports/stage_buffer_registers/verified_evidence.json), [GNU](../Ghidra_Results/ghidra_reports/stage_buffer_registers/gnu_verified.txt).

Riproduzione: `python3 Python_Trace_Scripts/s33_trace_stage_buffer_registers.py`.

Verificati **16 hash, roundtrip ELF del blocco00, 41 finestre, 16 collegamenti diretti, 104 istruzioni chiave, 36 pool e 11 setter**. Un interprete dei corpi decodificati verifica **2.816 casi** di programmazione e ricostruzione dei 32 bit, inclusi zero, limiti halfword e valori casuali riproducibili. Le prove sono offline e non assegnano validità hardware ai valori di test.

Prossimo: produttori delle celle `0x445380/384/394/398/3A8/3AC`, origine dei campi runtime+4 e limiti della banca `0x392288`, per ricostruire le dipendenze dei buffer fra stadi.


## Continuazione — origini delle sei celle risolte

Il [rapporto sulle origini](S33_Origine_Celle_Buffer_e_Area_Condivisa_Stadi.md) identifica le sei celle come configurazione `0x445380` prodotta da W=`0x4453DC`, risolve due regioni consecutive del workspace e distingue la banca a quattro terne. Config+4 inizialmente0 disabilita i due campi runtime+4 opzionali nel percorso preparato; restano possibili altre configurazioni.

## Continuazione — indice e layout della banca

Il [rapporto sulla banca](S33_Banca_Terne_Indice_e_Layout.md) collega il reset e tre avanzamenti modulo4 di C+51, risolve i sei casi della tabella e il layout locale di quattro terne. La validità globale dell’indice e l’ordine di inizializzazione restano da dimostrare; nessun controllo locale i<4 nel lettore selezionato.
