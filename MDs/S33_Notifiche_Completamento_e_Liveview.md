# S33 — notifiche di completamento e aggiornamento Liveview

Analisi statica del 18 ottobre 2026 sul firmware Nikon S33 V1.1. Continuazione degli [esiti ImgMgr e della chiusura](S33_Esiti_ImgMgr_e_Chiusura.md). Nessuna esecuzione sul dispositivo; i log hardware esistenti sono V1.0. **Avanzamento orientativo verso il firmware essenziale: circa 10%, invariato.**

## Risultato

L'evento `0x7C60` prodotto dalla callback immagini originale ha un consumatore nella tabella di CaptureLiveview. Il suo handler legge un campo del contesto e seleziona una routine che aggiorna valori e proprietà di oggetti dell'interfaccia. Nel corpo dell'handler non viene verificato un risultato di acquisizione o chiusura.

La callback programmata quando il conteggio della coda è zero ha un percorso distinto: sotto una guardia, azzera un campo di controllo, chiama un servizio con maschera `0x2000` e pubblica `0x4008` con argomento zero. Queste azioni non sono ancora una prova che lo scatto sia riuscito o che la macchina sia pronta per il successivo.

## 1. Dal produttore alla tabella CaptureLiveview

Il rapporto precedente verifica che `0x135770` pubblica `0x7C60` con destinatario 0 e argomento 0. Il callback originale dell'oggetto CaptureLiveview è `0x6524F4`, conservato nel descrittore `0x7833CC` a offset +12.

La parte finale di questo callback carica la tabella `0x7833EC` dal letterale `0x652754` e chiama `0x169F60` a `0x65272A`, passando oggetto, ID e argomento. La tabella contiene la coppia originale:

```text
0x783504:  0x00007C60, 0x00654228
```

Questo collega il produttore a un handler tramite la struttura originale e il dispatcher già ricostruito. Il destinatario zero dipende dall'oggetto corrente al consumo dell'evento; hook, filtri e coda possono alterare la consegna. Non è un collegamento incondizionato e non è un inventario completo dei consumatori dell'ID.

## 2. Che cosa legge l'handler

`0x654228` conserva i tre argomenti in `r14`, `r13`, `r15`, poi sostituisce `r1` con la parola letta da **`0x681EB8`** e chiama **`0x657624`** a `0x654240`. Conclude mediante l'epilogo condiviso `0x652782`.

Nel corpo locale non legge esplicitamente il valore dell'evento conservato in `r15`, né la cella risultato `0x3672FC`. Questo limite vale per il corpo esaminato: i servizi a valle possono leggere altri globali e non sono stati tutti analizzati.

`0x681EB8` è **contesto Liveview `0x681E74` + `0x44`**, un campo diverso dal byte di stato +59 che conduce a CaptureImage.

La routine `0x657624` distingue:

| Condizione | Azione verificata |
|---|---|
| Parola ricevuta uguale a `0xFFFFFFFF` e byte `0x681F02` uguale a zero | Chiama `0x633020(0x3ABB00,0)` |
| Tutti gli altri casi | Chiama `0x658A9C`, conservando l'argomento oggetto |

La semantica del ramo speciale e l'identità visiva dell'elemento non sono ancora attribuite.

## 3. Un produttore del campo e l'aggiornamento degli elementi

Un ramo di `0x658A9C` chiama `0x127284` a `0x658B0E` e ne scrive il risultato nel campo +`0x44` del contesto, a **`0x658B1A`**. Il confronto con il valore del letterale `0x658C90` può poi limitarlo. Questo identifica uno scrittore, senza attribuire tutti gli scrittori o l'inizializzazione del campo.

Il getter `0x127284` legge il campo +`0x20` della struttura `0x36683C`, può richiamare `0x1272BC` per aggiornarlo e contiene ulteriori condizioni. Non viene qui attribuito come risultato del worker immagini. È anche un promemoria che `0x36683C` è la base di più campi, non soltanto la cella callback al suo offset zero.

Il tratto seguente scompone il valore mediante operazioni con 1000, 100 e 10 e prepara valori per elementi figli risolti da `0x145654`. La routine `0x633768` scrive due campi da 16 bit a +`0x1C` e +`0x1E` dell'elemento e richiama `0x145490`. Altri rami usano `0x1450B8` e `0x145B08` per modificarne proprietà, con controlli su configurazione e servizi.

La combinazione di elementi figli, campi e proprietà sostiene l'interpretazione come aggiornamento dell'interfaccia. Non basta a stabilire quale contatore sia mostrato, quale testo compaia o quale significato abbiano tutti gli ID. Non è stato dimostrato un messaggio «salvataggio riuscito».

## 4. La callback programmata al conteggio zero

Il collegamento originale `0x135770 → programmazione di 0x1357B4` quando il conteggio è zero è documentato nel rapporto precedente. La continuazione verifica il corpo di `0x1357B4`:

1. Chiama `0x12845C`; se il risultato è nonzero salta le azioni successive e raggiunge l'epilogo.
2. Nel ramo con risultato zero chiama `0x149028` con risorsa e valore 1.
3. Chiama `0x18EE74(0)`, che scrive zero nella parola **`0x368054`**.
4. Chiama `0x17083C` con **`0x2000`**.
5. Pubblica tramite `0x169EB4` un evento con **destinatario 0, ID `0x4008`, argomento 0**.

`0x368054` coincide con il campo +`0x30` del contesto risorse `0x368024` già studiato. La [continuazione sul controllo immagini](S33_Controllo_ImgMgr_e_Workspace.md) verifica che il campo è usato come contatore di selezione per parità in un ramo e identifica la coppia OR/BIC della maschera `0x2000`. La guardia, le unità temporali e il contratto completo restano da ricostruire. L'azzeramento non va confuso con la chiusura del pool, che richiede altri controlli, né con l'esito del driver close.

## Cosa serve per AkeruOS

Le notifiche ricostruite collegano la pipeline a cambiamenti di interfaccia e controllo, ma non forniscono ancora un contratto completo di successo fotografico. Per dichiarare lo stato pronto la continuazione individua un consumatore di `0x4008` e gli usi di `0x368054` e della maschera `0x2000`; occorre completare il ripristino sugli errori e gli altri eventuali canali di esito, oltre alle attese e alla persistenza già aperte.

Non è stata trovata in questi corpi una propagazione esplicita del risultato del close. Questa osservazione circoscritta non dimostra che manchi in tutto il firmware.

## Riproduzione e limiti

Eseguire `python3 s33_trace_completion_notifications.py`. Lo [script](../Python_Trace_Scripts/s33_trace_completion_notifications.py) verifica hash e dimensioni dei **16 blocchi**, coppia evento/handler, puntatori, istruzioni selezionate e destinazioni delle chiamate. Esegue roundtrip ELF identico dei blocchi 00 e 02 e produce **11 finestre GNU ARC700** nel [disassemblaggio](../Ghidra_Results/ghidra_reports/completion_notifications/gnu_verified.txt) e nel [JSON](../Ghidra_Results/ghidra_reports/completion_notifications/verified_evidence.json), con hash dello script. Esecuzione completata con codice 0.

Le finestre sono radicate sugli ingressi o su punti del flusso specificati; non trasformano eventuali pool letterali in codice affidabile. Le conclusioni sono statiche, condizionali e limitate ai percorsi esaminati. Nessuna prova della sequenza reale V1.0, dell'assenza di altri errori o della persistenza sulla SD.
