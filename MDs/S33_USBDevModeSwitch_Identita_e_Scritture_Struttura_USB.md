# USBDEVMODE negli MD: identità e scritture della struttura USB

20 ottobre 2026 — R0/R3/R4. Su richiesta dell’utente è stata cercata negli MD l’identità di USBDEVMODE prima di aggiungere altre modifiche. Il riferimento trovato è **USBDevModeSwitch**, già ricostruito nel [rapporto persistenza](S33_HiddenMenu_Persistenza_MSDC_e_Inizializzazione_USB.md). Negli MD ricercati non è definito un flag autonomo con il nome USBDEVMODE.

La funzione dell’interprete cambia il selettore PTP/MSDC `0x366B9D`:

| Parametro grezzo del suo helper | Valore scritto | Modalità selezionata |
|---|---:|---|
| esattamente1 | 2 | PTP |
| diverso da1 | 1 | MSDC / mass storage |

Quindi, nel contesto richiesto, attivare MSDC per default corrisponde al valore1 del selettore, **non al parametro1 dell’helper**. Il [candidato offline esistente](S33_USB_MSDC_Predefinito_Candidato_Offline.md) realizza già quel default cambiando l’assegnazione iniziale; non è stato aggiunto un secondo flag o modificato di nuovo il BIN.

## Identità verificata

Il record dell’interprete è l’indice110 / `0x6E`, indirizzo `0x9A1490`: tipo ritorno6, nome USBDevModeSwitch, un parametro di tipo0, terminatore7. Il record di20byte coincide col Main fornito. Il dispatcher `0x80A7A8` chiama l’helper `0x80D604`, che chiama il setter `0x138F7C` a `0x80D61C`.

L’helper confronta il parametro32bit con1 prima della scrittura. Sono provati tutti i256 valori0..255 e, in aggiunta,256,257, `0x80000001` e `0xFFFFFFFF`, ciascuno su due contenuti diversi della struttura: **520 casi, 260 valori distinti**. Per esempio257, pur avendo byte basso1, seleziona MSDC: il confronto non è sul solo byte basso.

Sono prove dell’helper CPU con valori grezzi in registro. Non attribuiscono il significato completo del tipo0 dell’interprete e non dimostrano sintassi, file SD di autoavvio o un comando USB da inviare. La disponibilità dell’interprete sulla macchina resta separata.

## Flag diagnostico distinto

Il setter diagnostico `0x138FB0` scrive il byte `0x366B9F`, poi chiama `0x13993C` passando0 se il parametro32bit era zero, altrimenti1. Quest’ultimo scrive `0x366BB1`. Nessuno dei due store raggiunge `0x366B9D`.

Il setter MSDC `0x138F7C` scrive invece soltanto `0x366B9D`. Non abilita automaticamente queste due celle diagnostiche. Il corpo e il contenuto circostante sono verificati nelle nuove prove, senza dedurre capacità di debug o disponibilità di opcode sulla connessione reale.

## Verifica delle scritture vicine

Sono eseguiti i corpi originali di nove setter locali, il registrar delle callback `0x138F34` e l’helper dell’interprete. Ogni caso parte con64byte di struttura a `0x366B7C` predisposti dal test; il selettore è impostato a1. Dopo la chiamata vengono confrontati **tutti i64byte**, il ritorno e lo stack, non soltanto il byte atteso.

| Corpo | Celle scritte nel percorso provato |
|---|---|
| `0x138E84` | halfword a `0x366B7C` |
| `0x138F34` | parametro indice1→word `0x366B80`; indice0→word `0x366B84`; indici2/255→nessuno store, errore locale |
| `0x138F7C` | byte MSDC `0x366B9D` |
| `0x138F94` | byte distinto `0x366B9C` |
| `0x138FB0→0x13993C` | byte `0x366B9F` e byte normalizzato `0x366BB1` |
| `0x13A184` | word `0x366B88` |
| `0x13A1A4` | word `0x366B90` |
| `0x13A1C4` | word `0x366B8C` |
| `0x13A1E4` | word `0x366B98`, che termina prima del selettore |
| `0x13A200` | word `0x366B94` |

Sono180 casi per i nove setter (dieci valori su due contenuti),80 per il registrar,520 per l’helper USBDevModeSwitch,8 per il wrapper di creazione del task e20 per il piccolo helper `0xC6058`, che ritorna senza operazioni: totale808. I campi degli input comprendono valori oltre8/16bit per verificare ampiezza dello store e confronto32bit.

La prova ha corretto un’assunzione del verificatore: i setter `0x13A1E4` e `0x13A200` conservano il valore in r0 al ritorno; gli altri tre setter di word sopra restituiscono esplicitamente0. Il primo tentativo è conservato come fallito; nessun byte del firmware è stato cambiato per adeguarlo al test.

Questa verifica esclude sovrascritture incidentali nei **corpi e casi indicati**. Non esclude tutte le copie di strutture, alias, chiamate indirette o scritture concorrenti del firmware.

## Ordine parziale: ComMgrTask viene creato prima del default

È ricostruita un’altra parte della catena, coerente con il [contratto di creazione task](S33_Avvio_Runtime_e_Creazione_Task.md):

1. Nell’inizializzatore `0xC5EC0`, la chiamata `0xC5EDE→0x138E4C` precede l’assegnazione del selettore a `0xC5EEA/C5EEC`.
2. `0x138E4C` chiede al servizio `0x158E78` la creazione del task con ID `0x02100001`, selettore0 e parametro d’uscita sullo stack. Il wrapper non scrive il selettore USB e non confronta il ritorno della creazione nel proprio corpo.
3. Il record task `0x3727C8` contiene lo stesso ID, ingresso `0x138E20` e nome **ComMgrTask** a `0x3765A7`.
4. Il task attende evento con lo stesso valore numerico ID `0x02100001`, maschera1, poi cancella1 e chiama `0x13901C`, che costruisce i descrittori attraverso `0x139120`.
5. L’evento è un oggetto distinto: record `0x373880`, flags statici2. Il valore uguale dell’ID task/evento non rende i due record lo stesso oggetto.

Gli otto casi del wrapper eseguono `0x138E4C` con quattro esiti predisposti del servizio su due contenuti della struttura: la richiesta registrata ha ID e selettore attesi, il contenuto USB resta invariato e il ritorno del servizio viene conservato. **Il servizio di creazione è l’unico stub di questo test; non crea un task e non esegue lo scheduler.**

Il codice del task e la posizione delle chiamate forniscono un ordine statico locale, non una cronologia completa del boot. In particolare, la creazione del task precede il default: resta necessario seguire chi imposta l’evento1, quando il task può essere eseguito e quando USB legge il selettore. Non si assume che la sola vicinanza delle chiamate impedisca una preemption o garantisca MSDC in ogni avvio.

## Riproduzione ed evidenze

```bash
python3 Python_Trace_Scripts/s33_verify_usbdevmode_structure.py
```

[Script](../Python_Trace_Scripts/s33_verify_usbdevmode_structure.py), [indice](../Risultati/USB_MSDC_Default/Struttura_USB/latest.json), [manifest del controllo riuscito](../Risultati/USB_MSDC_Default/Struttura_USB/20261020T203243Z/verified_evidence.json), [808 casi](../Risultati/USB_MSDC_Default/Struttura_USB/20261020T203243Z/cpu_cases.json), [finestre GNU](../Risultati/USB_MSDC_Default/Struttura_USB/20261020T203243Z/gnu_verified.txt), [candidati letterali nei16payload](../Risultati/USB_MSDC_Default/Struttura_USB/20261020T203243Z/structure_literal_candidates.json).

Esito `PASS_USBDEVMODE_IDENTITY_AND_LOCAL_STORES`, exit0 e nessun fault. Firmware, dump,16payload e strumenti sono verificati dagli helper e per hash. Finestre e PC originali controllati coincidono col Main fornito; nel candidato MSDC differisce soltanto l’istruzione già dichiarata. Nessun nuovo flash, USB, SD, modifica al candidato o scrittura negli alberi GNU.

## Continuazione

Il significato richiesto di USBDEVMODE è ora attribuito dal nome negli MD al record e al codice: è il selettore PTP/MSDC. Per completare lo studio del default restano produttori dell’evento di ComMgrTask, ordine dei diversi ingressi USB, eventuali copie/alias della struttura, proprietà SD e recupero fisico. Il candidato mantiene gli override originali; non è una modalità forzata per ogni sequenza. Circa10% funzionale AkeruOS invariato.

## Continuazione — notifica e guardia condizionale, 20 ottobre 2026

Il [nuovo rapporto ComMgr](S33_ComMgr_Notifica_USB_Ordine_e_Guardia_Condizionale.md) aggiunge 156 casi originali con servizi esterni simulati: il backend precede la notifica; stato grezzo 1/3 invia evento applicativo4109, gli altri provati pubblicano ComMgr02100001/bit1, anche con errore backend. Il reset locale della guardia139092 è saltato dal ramo139084 quando entrambi i predicati1399D8/1399FC sono nonzero. 139CF4 è un registratore, quindi i suoi effetti reali sulla guardia restano aperti. La matrice precedente del candidato imponeva l’ordine descrittori→backend e il reset delle fasi successive: non prova l’intero avvio. Nessun BIN o hardware modificato. Proseguire su4109, predicati e ordine task/default prima di concludere sul comportamento globale.

## Continuazione — evento 4109 e callback, 20 ottobre 2026

Il [rapporto successivo](S33_USB_Evento_4109_Coda_Default_e_Callback_Guardia.md) verifica606casi: accodamento/pop originali, default scelto dal test con quattro richieste UI e coda piena senza inoltro, mentre138EFC restituisce l’esito backend. Non è un’esecuzione di WindowMgr o dell’oggetto corrente. I predicati1399D8/FC leggono i byte366BA1/A2;139CF4 chiama il callback366B90 registrabile da13A1A4, inizialmente nullo. Servono routing reale4109, registrazionecallback e scrittoriA2, quindi ordine task/default. Candidato e hardware invariati, NO-GO confermato.
