# USB: ingresso UI57, callback PTP e ordine del default nel caricamento

**Continuazione corrente:** [manager UI57 e argomento del timer](S33_USB_Manager_UI57_Argomento_Timer_e_Dispatch.md),16casi originali nel contesto freddo, e [nuovo risultato hardware MSDC](S33_USB_MSDC_Default_Installazione_Riferita_e_PTP_Hardware.md). I limiti storici sotto vanno letti con questi avanzamenti; boot globale e recupero restano aperti.

20 ottobre 2026 — R0/R3/R4. Continuazione dello studio [MSDC predefinito](S33_USB_MSDC_Predefinito_Candidato_Offline.md), della [guardia ComMgr](S33_ComMgr_Notifica_USB_Ordine_e_Guardia_Condizionale.md) e dell’[evento 4109](S33_USB_Evento_4109_Coda_Default_e_Callback_Guardia.md). Nessun nuovo firmware o hardware modificato.

## Risultato

È collegato un ingresso UI del backend: l’oggetto con ID **`0x57`**, descrittore `0x3EB3E8`, usa il callback `0x22451C`. La sua tabella `0x3EB428` associa **`0x440E → 0x224704`**. Con argomento 1 questo handler chiama prima `0x149028(oggetto, 1)`, poi **`0x138E9C`**, che applica la guardia e seleziona il backend. Il corpo locale non controlla un esito di `0x149028` prima della richiesta USB; il servizio reale potrebbe comunque avere altri effetti o attese.

Inoltre, l’ingresso `0x4405` legge il selettore tramite `0x138F70` a **`0x224660`**: è un altro consumatore da considerare oltre ai due selettori dei descrittori e del backend. **In un ramo MSDC non cancella un callback preesistente: salta il setter.** Non ampliare quindi la patch del default per assumere un ripristino automatico di tutto lo stato USB.

## Callback condizionale a 366B98

Il campo word **`0x366B98`**, scritto da `0x13A1E4`, è distinto dal callback `0x366B90` studiato per `0x139CF4`. Non confondere i due campi.

Il percorso di ingresso `0x22457C..0x2246AE` contiene queste decisioni, dopo altri controlli e servizi esterni:

| Risultati dei getter e selettore | Effetto sul campo `0x366B98` |
|---|---|
| `0xC86CC(1) == 10` | Salta il setter; conserva il valore precedente |
| `0xC86CC(1) != 10`, `0xCB5A8() == 1`, `0x1398E8() == 0`, selettore == 2 | Registra **`0xD1870`** tramite `0x13A1E4` |
| Stessi getter del caso precedente, selettore != 2 | Salta il setter; conserva il valore precedente |
| `0xC86CC(1) != 10` e una delle condizioni degli altri getter non soddisfatta | Scrive zero tramite `0x13A1E4` |

Il salto specifico del selettore è **`0x224666 → 0x224672`**. I valori numerici dei getter sono ingressi di laboratorio: questa verifica non assegna loro un significato fisico. Per la prova sono usati solo selettori validi 1/MSDC e 2/PTP.

Il campo è inizialmente zero nel campione originale e la patch del default non cambia i dati iniziali. Perciò il ramo MSDC che conserva zero rimane nullo in quella precondizione. **Se però il campo conteneva un callback precedente, quel ramo lo conserva**: passare da PTP a MSDC durante l’esecuzione non equivale a partire con MSDC dal valore iniziale nullo.

Il test semina sia zero sia `0x12345678`, senza invocare quest’ultimo valore come puntatore. Non dimostra che quella sentinella esista sulla macchina. Il corpo di `0xD1870` non viene eseguito e non è ancora attribuito un contratto completo al suo uso.

## Evento di stato, validazione e guardia

Sono eseguiti callback, filtro e tabella originali dell’oggetto 57. Il suo evento `0x4403` passa a `0x224554`, che interroga il tasto logico **`0x66`**: restituisce zero con risultato nonzero, `0xFFFFFFFF` con zero. Otto prove coprono i due selettori e risultati grezzi 0/1/255/256. Nessuna mappatura a un pulsante fisico o a un segnale del cavo deriva da questo controllo.

I 320 casi di ingresso e stato passano direttamente dal chiamante sintetico, senza far applicare al manager il risultato della validazione. Non sono quindi 320 transizioni UI complete o accettate dalla fotocamera.

Per ciascuna configurazione il test invia due volte `0x440E` con lo stesso argomento:

- Argomento **1**, guardia iniziale 0: una chiamata backend e una notifica `0x158CBC(0x02100001, 1)`, poi guardia 1 che sopprime la ripetizione. Selettore 1 sceglie il registratore MSDC, 2 quello PTP.
- Argomento 1, guardia iniziale 1: nessuna chiamata backend o notifica.
- Argomenti 0/3/4/`0xFFFFFFFF`: nessuna chiamata backend nel profilo esterno provato. I rami 3/4 possono comunque richiedere altri servizi UI/timer, qui simulati; non sono operazioni innocue certificate.

La guardia iniziale viene impostata esplicitamente dal laboratorio dopo l’ingresso. Il getter runtime usato da `0x138EC0` fornisce zero, per selezionare la notifica diretta ComMgr e non l’evento applicativo4109. Entrambi i backend sono registratori, con ritorno zero; i casi di errore sono nelle [prove ComMgr precedenti](S33_ComMgr_Notifica_USB_Ordine_e_Guardia_Condizionale.md).

## Ordine statico dell’inizializzazione e Load Later

Sono riancorate anche le istruzioni che collegano il default al coordinatore già studiato:

1. `0xC5E90` chiama `0xC58F8` caricando nel delay slot il pool `0xC5EBC = 0xC6234`. `0xC58F8` scrive il callback in **`0x365618`**.
2. Il percorso di richiesta `0xC5E96` pubblica il coordinatore `0xC58C8`, attraverso `0xC578C`; il letterale PC-relative scalato di `0xC5E9A` va calcolato come `(PC & ~3) - 104*4`, non preso dal commento GNU non scalato.
3. Il coordinatore `0xC58C8` chiama prima `0xC5910`, poi interroga `0x365618` e, se non nullo, lo chiama a `0xC58D6`.
4. Con il callback appena registrato si arriva a **`0xC6234 → 0xC6272 → 0xC5EC0`**. Qui creazione ComMgr a `0xC5EDE` e assegnazione del default a `0xC5EEA/C5EEC` precedono i controlli dei tasti.
5. Dopo il ritorno del callback, il coordinatore prosegue a `0xC59AC`, `0xC5AF4`, `0xC5A50`, poi pubblica il bit finale80.

L’attribuzione `C5910=C2`, `C59AC=C3`, `C5AF4=C4`, `C5A50=Resource` è riusata dalle [verifiche precedenti dei gruppi](S33_Gruppi_C2_C3_C4_Risorse_e_Segnali_Caricamento.md) e dei [consumatori Load Later](S33_Load_Later_Attese_Bit_Persistenti_e_Limite_Ready.md), non rieseguita come trasferimento in questo test. Ne segue un ordine locale del default nel callback dopo C2 e prima dei gruppi successivi, **sotto la condizione che il callback registrato sia ancora C6234 e che le chiamate ritornino**.

Questa è evidenza statica, distinta dalle 328 esecuzioni UI. Non esclude eventi asincroni o scritture concorrenti prima dell’assegnazione; non prova che l’oggetto57 sia già attivo o inattivo durante quella finestra. Resta da collegare l’ordine dei task e degli ingressi effettivi.

## Controlli e riproducibilità

```bash
python3 Python_Trace_Scripts/s33_verify_usb_ui57.py
```

[Script](../Python_Trace_Scripts/s33_verify_usb_ui57.py), [indice](../Risultati/USB_MSDC_Default/UI57/latest.json), [manifest](../Risultati/USB_MSDC_Default/UI57/20261020T205313Z/verified_evidence.json), [328 casi CPU](../Risultati/USB_MSDC_Default/UI57/20261020T205313Z/cpu_cases.json), [GNU](../Risultati/USB_MSDC_Default/UI57/20261020T205313Z/gnu_verified.txt), [sostituzioni](../Risultati/USB_MSDC_Default/UI57/20261020T205313Z/fixture_patches.json).

Esito `PASS_UI57_BOUNDED_ENTRY_AND_BACKEND_GATE`, exit0, nessun fault, 261.645 istruzioni del simulatore. 18 finestre GNU e 281 PC originali distinti controllati contro il Main fornito. I 320 casi coprono due selettori × due risultati di ciascuno dei tre getter × due valori callback iniziali × due guardie × cinque argomenti; si aggiungono otto validazioni. Stack e selettore sono verificati per ogni caso, campo callback e numero di chiamate per ogni caso di ingresso/stato.

Firmware originale V1.1 di 29.602.084 byte, SHA-256 `1d34e990a8f99019ffa53ca5de785399df863e942739a667ceb314ec6ce62a39`, 16 payload verificati. 26 input per hash e 818 artefatti nel manifest. Le finestre conservano i byte originali; i servizi UI, timer, volumi, contesto e backend sono sostituiti fuori da esse. Nessuna modifica a installazioni/sorgenti/build GNU.

Il tentativo `20261020T205236Z` ha eseguito la matrice ma si è fermato sul controllo del caso54: l’attesa del verificatore prevedeva erroneamente zero, mentre il ramo originale MSDC conserva la sentinella del callback. Il tentativo fallito rimane disponibile; è stato corretto il verificatore, non il firmware.

## Continuazione

Seguire la selezione e l’attivazione dell’oggetto57, i produttori del suo evento440E e gli usi/azzeramenti di `0x366B98` e `0x366B90`. Stabilire le precondizioni temporali rispetto a Load Later e al default. Restano i writer indiretti/copie/alias, proprietà SD, enumerazione MSC e recupero fisico.

Il candidato offline resta SHA-256 `af65ab0e66781c1a1036ab2349700e9d2110c6618738b02208da8b83c8813544`. La nuova differenza fra partenza MSDC e cambio durante l’esecuzione non autorizza una seconda modifica automatica. NO-GO installazione e circa10% funzionale AkeruOS invariati.

## Continuazione — trigger UITimer originale, 20 ottobre 2026

La [verifica del timer UI57](S33_USB_Timer_UI57_Registrazione_Scadenza_e_Limiti.md) esegue24casi con registrar,tasktimer,lettorecampo14503C,dedup,coda,pop e cancellazione originali. Timer1 viene registrato solo conwordoggetto+18zero;tabellapiena impedisceallocazione senza controllo delritornoUI,39vocioccupate consentono timer1ma non4. Clockzero/passo minimo50 euscitacontesto laboratorio non sono scheduler o tempo fisico. Dopopop iltest sceglie esplicitamente callback57;8casi raggiungono backend simulato. Servono attivazione/creazione57 eprovenienzacampo+18 rispetto aldefault LoadLater. BIN e hardware invariati.

## Continuazione hardware — installazione riferita e PTP, 20 ottobre2026

L’utente riferisce installazione del candidatoMSDC con messaggio completato e accensione manuale prima delcavo. La [nuova osservazione hardware](S33_USB_MSDC_Default_Installazione_Riferita_e_PTP_Hardware.md) conserva10campioni PTP06/01/01 senza discoNikon; non è stato riletto il codice flash/runtime. I precedenti risultati restano prove locali, non dimostrazione diMSC operativo. Prossimo confronto: collegamento da spenta;nessun altroflash/reset/formattazione per questa osservazione.
