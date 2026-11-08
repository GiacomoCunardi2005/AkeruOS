# S33 — controllo ImgMgr, evento 0x4008 e alternanza delle aree di lavoro

Analisi statica del 18 ottobre 2026, campione Nikon S33 V1.1. Continuazione delle [notifiche Liveview](S33_Notifiche_Completamento_e_Liveview.md). Nessuna esecuzione sul dispositivo o modifica del firmware. I log hardware sono V1.0. **Avanzamento complessivo orientativo: circa 10%, invariato.**

## Risultato

Sono verificati tre elementi del protocollo originale:

- L'invio immagini imposta il bit `0x2000` di una maschera a 16 bit; la callback programmata al conteggio zero può cancellarlo.
- Il campo `0x368054` è usato, in una configurazione, come contatore la cui parità seleziona due aree di lavoro. Non è semplicemente un booleano di occupazione.
- Un consumatore di `0x4008` in CaptureLiveview richiama un servizio legato allo scheduler con valore 11. Il suo corpo non interpreta l'argomento dell'evento come esito fotografico.

Questi collegamenti completano parti del controllo e dell'ownership, ma non dimostrano stato pronto, salvataggio riuscito o corretta pulizia in ogni errore.

## 1. Evento 0x4008: il consumatore trovato

La stessa tabella `0x7833EC` di CaptureLiveview, passata al dispatcher `0x169F60`, contiene:

```text
0x78350C: ID 0x4008 → handler 0x65424C
```

L'handler conserva gli argomenti, imposta `r0=11`, `r1=0` e chiama `0x159B10` a `0x654264`. Poi raggiunge l'epilogo condiviso `0x652782`. Nel corpo locale non confronta un risultato di elaborazione o chiusura, né legge esplicitamente l'argomento dell'evento conservato in `r15`.

Il wrapper legge un handle da `0x3672D8` e chiama `0x158FA4(handle,11,0)`. Quest'ultima passa al servizio `0x23D154` una cella locale per ricevere il valore precedente, che non viene copiato verso il chiamante quando il puntatore di uscita è zero. Traduce inoltre il codice `0x100C` in un errore del proprio dominio.

**Interpretazione sostenuta ma ancora parziale:** `0x23D154` sembra un servizio di modifica della priorità di un task. Controlla il valore richiesto rispetto a un limite del kernel, legge un precedente valore da 16 bit, seleziona una struttura con passo 16 mediante il valore richiesto e modifica collegamenti di liste/task. Questa lettura non attribuisce versione del RTOS, nome ufficiale del servizio o significato completo dell'handle. Il valore 11 è compatibile con le priorità candidate nelle tabelle originali, ma non basta da solo a identificare quale task venga modificato.

Il destinatario dell'evento rimane condizionato all'oggetto corrente e ai filtri già documentati. Non è dimostrato che CaptureLiveview sia sempre il destinatario della notifica programmata.

## 2. Maschera di controllo e coppia imposta/cancella

| Operazione | Codice | Campo |
|---|---|---|
| Imposta bit | `0x1707D8`, OR a `0x17080E`, scrittura a `0x170810` | `0x367900+2 = 0x367902`, 16 bit |
| Cancella bit | `0x17083C`, BIC a `0x170872`, scrittura a `0x170874` | Stesso campo |
| Lettura | `0x170894` | Stesso campo |

Entrambi i modificatori consultano `0x0C9628` e, in uno dei rami, usano acquisizione/rilascio di sincronizzazione. L'acquisizione può fallire prima della modifica. Gli altri bit della parola vengono conservati dalle operazioni OR/BIC: queste operazioni non sono un conteggio dei proprietari della stessa maschera.

Nel produttore immagini `0x126D48`, `0x126D92..0x126D96` costruisce **`0x2000`** e chiama il setter **prima** dell'invio a `0x15A570`. Il ritorno del setter non viene confrontato nel tratto esaminato. La [continuazione sul contratto di invio](S33_Esiti_ImgMgr_e_Chiusura.md) precisa che il ritorno successivo proviene da errori preliminari oppure dall'ultima segnalazione evento: non conserva l'esito dell'accodamento.

La callback programmata `0x1357B4`, quando `0x12845C()` restituisce zero, esegue la sequenza già individuata:

```text
azzera 0x368054
→ 0x17083C(0x2000)
→ pubblica evento 0x4008 con argomento zero
```

L'abbinamento statico del bit fra invio e pulizia è quindi verificato. Non sono ancora ricostruiti tutti i percorsi alternativi di cancellazione, il comportamento dopo pubblicazione fallita o i rapporti temporali con altri produttori. Non si può dedurre un blocco permanente o un bug dalla sola assenza di cleanup locale nel produttore.

### Un consumatore effettivo della maschera

`0x171020` risolve nuovamente la base `0x367900` dal letterale `0x170FB8` e legge la parola +2 a `0x171042`. Un valore nonzero seleziona un ramo che usa soglie e altri campi del contesto. In un tratto successivo, a `0x1710A6`, legge di nuovo l'intera maschera e la passa in `r1` a `0x170C40`.

Questo prova che il campo partecipa a logica di controllo ulteriore. Non attribuisce ancora al bit `0x2000` un nome come «scatto occupato», «impedisci standby» o «tasti disabilitati». Cancellare quel solo bit non prova che la maschera sia zero né che tutte le condizioni per scattare siano soddisfatte.

## 3. 0x368054: contatore e selezione per parità

Il setter `0x18EE74` scrive la parola puntata dal letterale `0x18EE8C`, cioè **`0x368054`**. Il getter `0x18EE90` la legge. È il campo **+`0x30` del contesto risorse `0x368024`**.

La callback di preparazione `0x18EE98`, già collegata al lavoro immagini, distingue la configurazione letta da `0x1436A4`:

| Ramo | Operazioni sul contatore e sulle aree |
|---|---|
| Configurazione uguale a 1 | Richiede la risorsa `0x51`; legge il contatore globale; ne testa il bit 0 a `0x18EEF0`; sceglie base oppure base più metà dimensione; seleziona rispettivamente la risorsa `0x11` oppure `0x65`; incrementa il contatore a `0x18EF20..0x18EF24` |
| Configurazione diversa da 1 | Azzera il contatore globale a `0x18EF4E` e prosegue con un percorso differente di risorse |

La metà dimensione deriva dallo shift del valore caricato dal record risorsa; gli indirizzi e i valori effettivi della risorsa dipendono dalla configurazione originale e non sono costanti dimostrate da questa analisi.

L'alternanza per parità è verificata in quel ramo. Non è ancora dimostrato il contratto completo di due buffer utilizzabili in parallelo: assegnazione, attese, ultimo consumatore e cancellazioni sugli errori richiedono ulteriori prove. Il contatore non coincide con il numero dei lavori presenti nella coda ImgMgr, letto mediante `0x23FFDC`.

**Distinzione degli indirizzi:** la preparazione scrive anche campi a offset +`0x30` del contesto di elaborazione ricevuto come argomento. Queste scritture non vanno attribuite automaticamente al globale `0x368054`: condividono un offset, non la base. La pulizia del pool e il ciclo degli stati dei descrittori sono descritti separatamente nel [rapporto risorse](S33_Descrittori_e_Ciclo_Buffer.md).

## Conseguenze per l'adattatore AkeruOS

Il protocollo richiede di preservare configurazione, contatore di selezione dell'area, maschera condivisa, pubblicazione dei lavori e callback nei rispettivi contesti. Un adattatore che conservasse soltanto il puntatore al descrittore non avrebbe ancora le precondizioni necessarie.

Per chiudere R2 mancano soprattutto l'uscita dagli errori di pubblicazione/elaborazione, l'esito consumabile della chiusura e l'invariante di disponibilità del prossimo buffer. R3 resta aperta: occorre ricostruire l'avvio e come integrare un task nuovo senza interrompere questi servizi. Nessuno di questi passi costituisce una build AkeruOS eseguita sulla macchina.

## Riproduzione

Eseguire `python3 s33_trace_image_control.py` dalla radice. Lo [script](../Python_Trace_Scripts/s33_trace_image_control.py) verifica hash/dimensioni dei **16 blocchi**, letterali, coppia tabella/handler, istruzioni selezionate e destinazioni delle chiamate. Controlla il roundtrip ELF identico dei blocchi 00/02; produce **14 finestre GNU ARC700** nel [disassemblaggio](../Ghidra_Results/ghidra_reports/image_control/gnu_verified.txt) e un [JSON](../Ghidra_Results/ghidra_reports/image_control/verified_evidence.json), con hash dello script e limiti. Esecuzione completata con codice 0.

Interpretazione delle strutture dello scheduler distinta dai fatti sulle istruzioni. Nessun inventario esaustivo degli scrittori/lettori, nessuna misura runtime e nessuna prova di compatibilità V1.0 o persistenza JPEG.
