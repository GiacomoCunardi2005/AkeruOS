# S33 — uscita del kernel TBIB e ripristino del contesto

Analisi statica V1.1, 19 ottobre 2026. Continuazione del [passaggio TBIB→TBM](S33_Passaggio_TBIB_TBM_e_Ingresso_CPU.md). Nessuna esecuzione sulla fotocamera.

## Risultato

Il bootstrap TBIB conserva un contesto di **92byte a `0x01090988`**. L'uscita dal kernel salva il proprio stato in K+17C, chiama il callback facoltativo K+130 e ripristina quel contesto, tornando a **`0x01006B84` con r0=1**. Il ramo di rientro ripristina la base dei vettori da K+178 e restituisce lo stato al runtime.

Il callback K+130 viene inizializzato a **`0x0101F6F4` nel delay slot** di una chiamata. Richiede operazioni ai registri `dc_flsh`, `dc_ivdc` e `aux_irq_lv12`. Dopo il rientro, il runtime raggiunge la lista di callback finali che comprende il trasferimento al TBM già verificato.

È ora collegata una sequenza di uscita software, non soltanto la cella con l'indirizzo del TBM. **Il completamento cache e l'arresto di periferiche/DMA restano da provare**; non è ancora un contratto sicuro per sostituire la transizione con codice AkeruOS.

## 1. Salvataggio prima del bootstrap

Nel prefisso `0x01006B5C`, r17 conserva il `blink` del chiamante. Il codice prepara r0=`0x01090988` e chiama **`0x0103AF08`** con `bl.d` a `0x01006B7E`; la sottrazione di20byte allo stack avviene nel delay slot. Il contesto salvato contiene dunque lo stack dopo tale sottrazione e `blink=0x01006B84`.

Il helper salva23 parole consecutive:

| Offset dal buffer | Contenuto |
|---|---|
| +00..30, passo4 | r13..r25 |
| +34 / +38 / +3C | gp / fp / sp |
| +40 / +44 / +48 | ilink / r30 / blink |
| +4C / +50 / +54 | lp_count / lp_start / lp_end |
| +58 | status32 |

Gli offset sono esadecimali. Lo span è `[0x01090988,0x010909E4)`. Non è un nuovo spazio libero o un buffer assegnato ad AkeruOS.

La funzione termina con salto a `blink`, impostando r0=0 nel delay slot. A `0x01006B8A`, r0=0 seleziona la costruzione iniziale del kernel a `0x01006BBC`. Il salvataggio è quindi il punto di distinzione fra primo ingresso e ritorno non locale.

## 2. Uscita e ritorno non locale

La routine **`0x01006D20`** riceve lo stato in r0, lo conserva in r13 e consulta il contesto K tramite la cella `0x0104126C`:

```text
K+0x17C = stato ricevuto
se parola[K+0x130] != 0: chiama quel callback
r0 = 0x01090988
chiama 0x0103AF78 con r1=1 nel delay slot
```

Il helper di ripristino carica le23 parole salvate, applica il valore richiesto tramite `flag` e salta al `blink` salvato. L'argomento r1 diventa il valore di ritorno r0, con0 normalizzato a1. Nel chiamante esaminato r1 è già1.

Il punto raggiunto è dunque `0x01006B84`, sullo stack originale del bootstrap, con r17 che conserva nuovamente il ritorno del chiamante. Il ramo r0 nonzero:

1. legge K attraverso la struttura a `0x01041258+0x14`;
2. passa **K+178** a `0x0101F034` nel delay slot della chiamata;
3. legge lo stato da **K+17C**;
4. ripristina `blink` da r17 ed esce dal bootstrap.

Il percorso principale del TBIB chiama `0x01006D20` a `0x01000424` dopo le proprie guardie. Lo stesso servizio è anche richiamato da percorsi di errore: la sua presenza non basta a identificare il boot riuscito o a garantire che K e i suoi campi siano validi in ogni caso.

## 3. Base dei vettori salvata e ripristinata

Durante l'inizializzazione, **`0x0101F028`** legge `int_vector_base`, ne maschera i10bit bassi e restituisce il risultato. Lo store `0x0101F0A8` conserva tale valore a K+178.

Il setter **`0x0101F034`** legge a sua volta la base corrente, azzera i10bit bassi sia della base corrente sia dell'argomento e scrive l'argomento a `int_vector_base`. Ritorna la base precedente, che il ramo di uscita non usa.

La transizione esaminata ripristina quindi il valore salvato prima dell'installazione dei vettori TBIB. Questo non attribuisce tutti i vettori, il contenuto delle tabelle o gli interrupt pendenti al momento del cambio.

## 4. Callback CPU prima del ripristino del contesto

Il getter `0x010139D8` restituisce K. Nel tratto di inizializzazione:

```text
0x0101F538  r0 = 0x0101F6F4
0x0101F53E  bl.d 0x0102DD94
0x0101F542  parola[K+0x130] = r0   # delay slot, prima del chiamato
```

Il campo riceve quindi l'indirizzo del callback, **non il risultato della chiamata successiva**. Eventuali scritture successive al campo non sono escluse globalmente.

Il callback `0x0101F6F4` esegue, nell'ordine osservato:

| Chiamata/istruzione | Scrittura richiesta |
|---|---|
| `0x0101F6F6 → 0x01029C40` | `dc_flsh = 1` |
| `0x0101F6FA → 0x01029BFC` | `dc_ivdc = 1` |
| `0x0101F6FE` | `aux_irq_lv12 = 3` |

I due accessor cache contengono la scrittura e il ritorno; non un polling locale di completamento. I nomi dei registri sono quelli decodificati da GNU ARC700. Non si deducono da questi nomi tutti gli effetti o i tempi del silicio, né l'arresto di controller esterni.

## 5. Dal ritorno del kernel alla lista finale

Il ponte **`0x0103DE54`** chiama il bootstrap `0x01006B5C` e, quando questo ritorna, chiama **`0x0103B51C`**. Quest'ultimo servizio usa un flag a `0x01041750` per evitare di ripetere il primo passaggio dei callback di uscita. Il flag viene scritto a1 nel delay slot prima della chiamata a `0x0103BB88`.

Questo dispatcher consulta due hook distinti:

1. cella **`0x01041768`**: chiamata se nonzero, poi la cella viene azzerata;
2. cella **`0x0104176C`**: letta e chiamata se nonzero soltanto dopo il ritorno del primo hook.

Il registrar **`0x0103B478`** installa nel primo hook il dispatcher `0x0103B4B4` e aggiunge callback all'array `0x01096710`. Nel percorso normale il confronto ammette conteggi inferiori a36; la sicurezza con un contatore arbitrariamente corrotto non viene dimostrata. Il dispatcher prende il conteggio e legge gli elementi in ordine **n-1, n-2, …, 0**.

Durante il setup del kernel, la chiamata `0x0101F618 → 0x0103ADF8` registra **`0x0103FE68`** come callback dell'array e registra il record che contiene `0x01000C10`, già ricostruito. Quando viene eseguito, `0x0103FE68 → 0x0103E06C` percorre la lista finale e può raggiungere:

```text
0x01000C10 → 0x010000C4 → jl_s [parola[0x01041100]]
                                      → TBM 0x000BB540
```

Se il trasferimento al TBM non ritorna, il dispatcher del primo hook non completa il proprio ritorno e il secondo hook non viene raggiunto attraverso questa sequenza. **Non bisogna quindi assumere che ogni pulizia del secondo hook preceda il salto al TBM.** I callback aggiunti successivamente possono inoltre essere eseguiti prima del finalizzatore per l'ordine inverso.

## Evidenze e limiti

[Script](../Python_Trace_Scripts/s33_trace_tbib_shutdown_context.py), [JSON](../Ghidra_Results/ghidra_reports/tbib_shutdown_context/verified_evidence.json), [GNU](../Ghidra_Results/ghidra_reports/tbib_shutdown_context/gnu_verified.txt).

Riproduzione: `python3 Python_Trace_Scripts/s33_trace_tbib_shutdown_context.py`.

Verificati identità del contenitore e della porzione TBIB, checksum, roundtrip ELF, **20 finestre, 49 istruzioni chiave, 13 parole e 512 salvataggi/ripristini del contesto a23parole**. Il modello interpreta i trasferimenti di registri, memoria, loop e parola di stato, inclusi r1=0/1/2/FFFFFFFF e casi casuali riproducibili. Non emula gli effetti fisici di `flag`, cache, scheduler o interrupt.

Il prossimo passo è attribuire i callback di pulizia che precedono il finalizzatore e verificare gli stati dei controller durante il passaggio. Rimangono aperti caricamento modificato, memoria assegnabile, recupero e compatibilità V1.0; nessuna build AkeruOS è stata avviata.

## Continuazione — ordine noto e assenza di ritorno ordinario

Il [rapporto sull’ordine](S33_Ordine_Callback_TBIB_e_Confine_Pulizia.md) ricostruisce quattro registrazioni originali: nella lista2 il callback del salto, chiave1, precede il rilascio runtime, chiave120. Verificato anche il ciclo TBM dopo un eventuale ritorno di `0xAD890`; le pulizie successive non provano quiete hardware precedente alla transizione. Registrazioni ulteriori restano aperte.
