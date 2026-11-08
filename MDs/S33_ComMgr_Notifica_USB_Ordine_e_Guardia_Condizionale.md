# ComMgrTask: notifica USB, ordine locale e guardia condizionale

20 ottobre 2026 — R0/R3/R4. Continuazione dello studio [MSDC predefinito](S33_USB_MSDC_Predefinito_Candidato_Offline.md) e del chiarimento [USBDevModeSwitch](S33_USBDevModeSwitch_Identita_e_Scritture_Struttura_USB.md). Il candidato offline precedente resta identico. Nessuna operazione sulla fotocamera.

## Risultato

Il percorso originale `0x138E9C → 0x138EFC → 0x139658` sceglie il backend **prima** della notifica successiva. Il risultato del backend viene restituito al chiamante, ma non decide se notificare. Il valore numerico fornito da `0x18AC58`, normalizzato da `0x138EC0`, distingue due percorsi:

| Valore originale a 32 bit | Percorso dopo il backend |
|---|---|
| 1 oppure 3 | `0x169EB4(0, 0x4109, 0)`: evento applicativo |
| Altri valori provati: 0, 2, 255, `0xFFFFFFFF` | `0x158CBC(0x02100001, 1)`: pubblicazione del bit 1 per ComMgrTask |

Non attribuiamo a questi numeri significati come «cavo collegato» senza una prova ulteriore. Il consumatore di `0x4109` e il suo raccordo a ComMgrTask restano aperti.

L’ingresso del task `0x138E20` attende l’evento `0x02100001`, maschera 1, opzione 0 e quarto argomento 0; poi cancella il bit con `0x158CE0` e chiama `0x13901C`. Questa sequenza è verificata staticamente. Il test corrente esegue produttore e corpo `0x13901C` in matrici separate: **non esegue scheduler, attesa reale o una sessione completa del task**.

## Correzione della sintesi sulla guardia

Il byte guardia è `0x366BB2`. `0x138E9C` lo imposta a 1 prima del backend e, se è già nonzero, salta backend e notifica.

Il padre `0x13901C` esegue il costruttore dei descrittori `0x139120` a `0x13903E`, poi il selettore di servizi `0x1394B0` e vari servizi esterni. Il suo store diretto di azzeramento della guardia è a `0x139092`, ma **non si trova su tutti i percorsi**:

| Risultato `0x1399D8` | Risultato `0x1399FC` | Percorso locale |
|---|---|---|
| Zero | Non interrogato | Callback opzionali, poi store zero a `0x139092` |
| Nonzero | Zero | Callback opzionali, poi store zero a `0x139092` |
| Nonzero | Nonzero | `0x139CF4(4)`, salto `0x139084 → 0x139094`, store saltato |

Nell’ultimo caso il registratore che sostituisce `0x139CF4` non modifica la guardia e il test osserva 1. **Questo non dimostra che il servizio reale lasci la guardia a 1:** i suoi effetti e quelli dei suoi discendenti non sono eseguiti. La conclusione acquisita è il salto dello store locale, non un blocco permanente del firmware.

I precedenti test del candidato costruivano esplicitamente prima i descrittori e poi richiedevano il backend, con reset della guardia imposto dal laboratorio nelle fasi successive. Rimangono validi per quella sequenza, ma non provano l’ordine completo dell’avvio. Il percorso statico qui raccordato può selezionare il backend, pubblicare l’evento e far costruire successivamente i descrittori al task; quando il task sia realmente eseguito rispetto al default `0xC5EEA` non è ancora dimostrato.

## Contratti aggiuntivi osservati

Il costruttore originale registra il puntatore di configurazione in `0x3680A4`: selettore 2 dà `0x3900F0`/PTP, selettore 1 dà `0x3901B0`/MSC. Il fallback 255 dà anch’esso il descrittore MSC, ma è soltanto un ingresso diagnostico del test, non una configurazione hardware valida dimostrata.

`0x1394B0` richiede il servizio `0x12A738` con identificatore `0x1E` per selettore 1; con 2 richiede `0x1C` e `0x1D`; con 255 non lo richiede. Il servizio è un registratore: nessuna conclusione su flush, montaggio, rilascio o proprietà della SD deriva da questi soli identificatori.

## Verifica riproducibile

```bash
python3 Python_Trace_Scripts/s33_verify_com_manager_protocol.py
```

[Script](../Python_Trace_Scripts/s33_verify_com_manager_protocol.py), [indice corrente](../Risultati/USB_MSDC_Default/Protocollo_ComMgr/latest.json), [manifest](../Risultati/USB_MSDC_Default/Protocollo_ComMgr/20261020T204050Z/verified_evidence.json), [casi CPU](../Risultati/USB_MSDC_Default/Protocollo_ComMgr/20261020T204050Z/cpu_cases.json), [GNU](../Risultati/USB_MSDC_Default/Protocollo_ComMgr/20261020T204050Z/gnu_verified.txt), [sostituzioni di laboratorio](../Risultati/USB_MSDC_Default/Protocollo_ComMgr/20261020T204050Z/fixture_patches.json).

- 108 casi produttore: selettori 1/2/255 × sei stati grezzi × guardie 0/1/255 × ritorno backend 0/`0x200304`.
- 48 casi padre: tre selettori × due risultati di ciascuno dei tre predicati × callback assenti/presenti. Due callback distinte sono installate insieme quando presenti.
- 16 finestre GNU, 411 PC originali distinti controllati contro il Main fornito; corpi nelle finestre preservati integralmente nel laboratorio.
- Exit 0, nessun fault, 57.607 istruzioni del simulatore. Stack e selettore preservati; intero record finale dell’evento e fixture kernel controllati.
- Firmware V1.1 originale di 29.602.084 byte, SHA-256 `1d34e990a8f99019ffa53ca5de785399df863e942739a667ceb314ec6ce62a39`, 16 payload verificati. 24 input per hash e 547 artefatti nel manifest.

La pubblicazione `0x158CBC → 0x23C758` è originale, con record ComMgr marcato attivo, liste di attesa vuote e kernel sintetico con lock annidato: non avviene alcun risveglio reale. Gli altri eventi del controllore restano non inizializzati; le notifiche interne dei setter dei descrittori possono quindi restituire errore nel modello. Il puntatore viene comunque scritto dalle istruzioni originali: il test non certifica che il controllore USB lo abbia accettato.

I 21 ingressi sostituiti registrano backend, stato runtime, evento applicativo, predicati e servizi esterni; due callback puntano a un ulteriore registratore. Seriale `12` e campi temporali zero sono dati di laboratorio. Nessuna modifica a installazioni, sorgenti o build GNU.

## Continuazione

Seguire il consumatore di `0x4109`, poi significato ed effetti reali di `0x1399D8`, `0x1399FC` e `0x139CF4`; collegare l’attivazione del task all’inizializzazione senza imporre l’ordine dal test. Restano anche copie/alias e scrittori indiretti, proprietà SD, enumerazione MSC e recupero fisico.

Il candidato `S33_USB_MSDC_DEFAULT_OFFLINE_NON_INSTALLARE.bin` mantiene SHA-256 `af65ab0e66781c1a1036ab2349700e9d2110c6618738b02208da8b83c8813544`. Nessun nuovo firmware generato e nessuna installazione. NO-GO e circa 10% funzionale AkeruOS invariati.

## Continuazione — evento 4109 e callback, 20 ottobre 2026

Il [rapporto successivo](S33_USB_Evento_4109_Coda_Default_e_Callback_Guardia.md) verifica606casi: accodamento/pop originali, default scelto dal test con quattro richieste UI e coda piena senza inoltro, mentre138EFC restituisce l’esito backend. Non è un’esecuzione di WindowMgr o dell’oggetto corrente. I predicati1399D8/FC leggono i byte366BA1/A2;139CF4 chiama il callback366B90 registrabile da13A1A4, inizialmente nullo. Servono routing reale4109, registrazionecallback e scrittoriA2, quindi ordine task/default. Candidato e hardware invariati, NO-GO confermato.

## Continuazione — UI57 e callback conservato, 20 ottobre 2026

La [verifica successiva UI57](S33_USB_UI57_Ingresso_Callback_PTP_e_Ordine_LoadLater.md) aggiunge328casi: evento440E/arg1 dell’oggetto57 richiede il backend con guardia; ingresso4405 contiene un altro controllo del selettore a224660. Nel profiloC86CC!=10/CB5A8=1/1398E8=0,PTP registraD1870 in366B98,MSDC salta il setter e conserva il precedente; non è un azzeramento. ConC86CC=10 il setter è saltato perentrambi.366B98 è distinto da366B90. Staticamente il callbackC6234 che raggiungeC5EC0 è registrato in365618 e chiamato dal coordinatore Load Later dopoC5910, prima dei gruppi successivi; concorrenza e attivazione dell’oggetto57 non provate. Servono produttori440E,usi callback e ordine avvio. Candidato e hardware invariati.
