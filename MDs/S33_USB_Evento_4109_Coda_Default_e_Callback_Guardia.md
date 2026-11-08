# USB: evento 4109, coda, gestore predefinito e callback della guardia

20 ottobre 2026 — R0/R3/R4. Continuazione di [notifica e guardia ComMgr](S33_ComMgr_Notifica_USB_Ordine_e_Guardia_Condizionale.md). Il candidato MSDC offline resta invariato; nessuna azione hardware.

## Risultato utile per il default MSDC

Il ramo di `0x138EFC` che, per stato grezzo 1 oppure 3, chiama `0x169EB4(0, 0x4109, 0)` **accoda un evento per l’interfaccia**. Non è una chiamata diretta al padre ComMgr `0x13901C` e non ne dimostra l’esecuzione successiva.

Nel gestore predefinito `0x20E814`, pool `0x20E844 → 0x3E8BB4`, la tabella originale contiene 67 record da otto byte compreso il terminatore. Il record **`0x3E8D0C`** è `[0x4109, 0x20FC04]`. Attenzione all’allineamento: la word immediatamente precedente, `0x20FBD8` a `0x3E8D08`, appartiene al record dell’evento precedente; non è il callback di 4109. Il dispatcher `0x169F60` confronta il primo halfword e legge il callback a record+4.

`0x20FC04` passa a `0x144314` con terzo argomento zero. Il corpo, dopo interrogazioni di stato, richiede `0x1453E4(ID, 0)`. I quattro esiti provati sono:

| Profilo di laboratorio delle interrogazioni | ID richiesto | Nome nel descrittore originale |
|---|---|---|
| Predicato `0xD21A4` zero, stato `0xCAD30` zero, modalità `0xBBC20` zero, oggetto corrente zero | `0x87` | AutoSceneLiveView |
| Predicato nonzero e oggetto corrente diverso da `0xC2` | `0xC2` | MSG_UNDERWATERWARNING |
| Oggetto corrente `0xA5`, modalità 2 e flag `0x366E84` nonzero | `0x07` | ShootingMode |
| Oggetto corrente zero, modalità 2 e flag `0x366E84` nonzero | `0x5E` | ReviewState |

La tabella degli oggetti è letta da `0x3F5900 + ID*4`; nome a descrittore+0x14. Sono richieste registrate, **non transizioni effettivamente completate**: `0x1453E4` e le interrogazioni esterne sono simulati. Non sono tutte le combinazioni possibili delle interrogazioni.

## Accodamento, estrazione e limite di coda piena

Il test esegue le istruzioni originali di `0x138E9C`, `0x138EFC`, `0x138EC0`, `0x139658`, `0x169EB4`, `0x17BC7C`, quindi il pop `0x17BD4C`. Sono provati selettori 1/2, stati grezzi 1/3 e indici 0/1/63/127, compreso il giro 127→0.

Il ring ha indici a `0x367BBC` e `0x367BBE`; i record da 12 byte sono a `0x47A848`. L’area `[0x47A848, 0x47AE48)` è mappata esplicitamente come memoria di laboratorio, non allocata ad AkeruOS. I campi verificati sono destinatario u32=0, evento u16=`0x4109`, argomento u32=0. Il padding a record+6 resta intatto: il test semina `0xDEADBEEF` e osserva `0xDEAD4109` nella word record+4.

- **64 casi con ring inizialmente vuoto:** il produttore avanza il cursore, pubblica la notifica `0x158CBC(0x00300008, 1)`, il pop restituisce 1 e ricopia i tre campi. Il test passa poi esplicitamente l’evento al gestore predefinito e osserva la richiesta di transizione prevista.
- **16 casi con ring pieno**, cioè `(scrittura+1)&127 == lettura`: nessun avanzamento, nessuna notifica e nessuna modifica alle tre word sentinella dello slot. `0x169EB4` restituisce il mancato inserimento, ma `0x138EFC` restituisce il risultato del backend conservato in `r13`. Con backend simulato che restituisce zero, il chiamante vede zero anche se l’evento non è stato accodato. La guardia resta 1 in questi casi.

Non si conclude che la fotocamera rimanga bloccata: possono esistere altri eventi, consumatori e percorsi di ripristino. È dimostrato il mancato inoltro in questa condizione locale e il fatto che questo chiamante non lo propaga come errore distinto.

L’intero task WindowMgr, l’oggetto corrente, gli hook e il suo inoltro a `0x169D78` non vengono eseguiti: dopo il pop il chiamante sintetico entra direttamente in `0x20E814`. Quindi il percorso dimostrato è **produttore e coda reali + gestore predefinito reale scelto dal test**, non un dispatch globale garantito su ogni schermata. Lock, contesto kernel, notifica della coda, backend e getter runtime sono simulati; nessuna concorrenza o attesa reale.

## Predicati e servizio alternativo della guardia

`0x1399D8` e `0x1399FC` sono getter di un byte, rispettivamente **`0x366BA1` e `0x366BA2`**. I setter `0x1399BC` e `0x1399E0` scrivono il byte basso del parametro. 518 casi eseguono setter e getter originali: per ciascuna coppia tutti i valori 0–255, più 256/257/`0xFFFFFFFF`; il getter restituisce 0–255 senza estensione di segno e il selettore MSDC resta 1.

Nel campione originale `0x366BA0..0x366BA2` sono zero. Il ramo di inizializzazione `0xC5F1E..0xC5F30` può impostare `0x366BA1=1` quando il getter del tasto logico `0x66` è nonzero e `0x1398E8` restituisce zero. Questo è un controllo distinto dai tasti 9/11 che sovrascrivono il selettore PTP; la mappatura fisica di `0x66` non è dimostrata.

Il servizio **`0x139CF4(argomento)`** legge il puntatore in **`0x366B90`**: se nullo restituisce zero, altrimenti lo chiama passando l’argomento. La registrazione passa dal setter originale `0x13A1A4`. Il valore iniziale nel payload è zero; non è una prova che rimanga nullo in ogni avvio.

Otto casi eseguono registrazione e wrapper originali con callback nullo oppure registratore di laboratorio e argomenti 0/4/256/`0xFFFFFFFF`. Il wrapper conserva l’argomento completo e propaga il ritorno del callback. Da solo non azzera la guardia. Restano da identificare chi registri un callback reale e i suoi effetti: non assumere che il salto di `0x139092` lasci sempre la guardia invariata dopo una chiamata indiretta.

## Riproducibilità e controlli

```bash
python3 Python_Trace_Scripts/s33_verify_usb_event_4109.py
```

[Script](../Python_Trace_Scripts/s33_verify_usb_event_4109.py), [indice](../Risultati/USB_MSDC_Default/Evento_4109/latest.json), [manifest finale](../Risultati/USB_MSDC_Default/Evento_4109/20261020T204703Z/verified_evidence.json), [606 casi](../Risultati/USB_MSDC_Default/Evento_4109/20261020T204703Z/cpu_cases.json), [finestre GNU](../Risultati/USB_MSDC_Default/Evento_4109/20261020T204703Z/gnu_verified.txt), [67 record](../Risultati/USB_MSDC_Default/Evento_4109/20261020T204703Z/default_event_table.json), [nomi degli oggetti](../Risultati/USB_MSDC_Default/Evento_4109/20261020T204703Z/requested_objects.json), [sostituzioni](../Risultati/USB_MSDC_Default/Evento_4109/20261020T204703Z/fixture_patches.json).

Esito `PASS_USB4109_BOUNDED_QUEUE_AND_DEFAULT_HANDLER`: 606 casi, exit 0, nessun fault, 71.195 istruzioni del simulatore; 18 finestre GNU e 346 PC originali distinti controllati contro il Main fornito. Stack e selettore verificati per ogni caso. Firmware originale V1.1 di 29.602.084 byte, SHA-256 `1d34e990a8f99019ffa53ca5de785399df863e942739a667ceb314ec6ce62a39`, identità dei 16 payload verificata. Manifest con 25 input per hash e 377 artefatti. Nessuna modifica agli alberi GNU.

Il tentativo `20261020T204559Z` si arrestava sullo store `0x47A848` a `0x17BCBC` perché il ring non era mappato nel laboratorio. È conservato come tentativo fallito e non contato come verifica riuscita; il difetto era nel modello. Il successivo tentativo passa; quello finale aggiunge il controllo delle sentinelle e delle finestre dei setter.

## Continuazione

Collegare il consumo effettivo di `0x4109` all’oggetto corrente/WindowMgr e alle transizioni richieste; cercare la registrazione runtime di `0x366B90` e gli scrittori di `0x366BA2`. Integrare l’ordine task/default solo con precondizioni dimostrate. Restano alias/copie della struttura, proprietà SD e recupero fisico.

BIN MSDC invariato, SHA-256 `af65ab0e66781c1a1036ab2349700e9d2110c6618738b02208da8b83c8813544`. Nessuna enumerazione USB, scrittura SD o installazione. Il default selezionato non prova la disponibilità del disco sul computer; NO-GO e circa 10% funzionale AkeruOS invariati.

## Continuazione — UI57 e callback conservato, 20 ottobre 2026

La [verifica successiva UI57](S33_USB_UI57_Ingresso_Callback_PTP_e_Ordine_LoadLater.md) aggiunge328casi: evento440E/arg1 dell’oggetto57 richiede il backend con guardia; ingresso4405 contiene un altro controllo del selettore a224660. Nel profiloC86CC!=10/CB5A8=1/1398E8=0,PTP registraD1870 in366B98,MSDC salta il setter e conserva il precedente; non è un azzeramento. ConC86CC=10 il setter è saltato perentrambi.366B98 è distinto da366B90. Staticamente il callbackC6234 che raggiungeC5EC0 è registrato in365618 e chiamato dal coordinatore Load Later dopoC5910, prima dei gruppi successivi; concorrenza e attivazione dell’oggetto57 non provate. Servono produttori440E,usi callback e ordine avvio. Candidato e hardware invariati.

## Continuazione — trigger UITimer originale, 20 ottobre 2026

La [verifica del timer UI57](S33_USB_Timer_UI57_Registrazione_Scadenza_e_Limiti.md) esegue24casi con registrar,tasktimer,lettorecampo14503C,dedup,coda,pop e cancellazione originali. Timer1 viene registrato solo conwordoggetto+18zero;tabellapiena impedisceallocazione senza controllo delritornoUI,39vocioccupate consentono timer1ma non4. Clockzero/passo minimo50 euscitacontesto laboratorio non sono scheduler o tempo fisico. Dopopop iltest sceglie esplicitamente callback57;8casi raggiungono backend simulato. Servono attivazione/creazione57 eprovenienzacampo+18 rispetto aldefault LoadLater. BIN e hardware invariati.
