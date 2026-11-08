# USB: timer UI57, registrazione, scadenza e limiti del trigger

**Continuazione corrente:** [manager UI57 e argomento del timer](S33_USB_Manager_UI57_Argomento_Timer_e_Dispatch.md),16casi originali nel contesto freddo, e [nuovo risultato hardware MSDC](S33_USB_MSDC_Default_Installazione_Riferita_e_PTP_Hardware.md). I limiti storici sotto vanno letti con questi avanzamenti; boot globale e recupero restano aperti.

20 ottobre 2026 — R0/R3/R4. Continuazione dell’[ingresso UI57](S33_USB_UI57_Ingresso_Callback_PTP_e_Ordine_LoadLater.md), con i servizi timer ora eseguiti. Candidato MSDC invariato, nessuna azione sulla fotocamera.

## Risultato

L’evento **`0x440E` con argomento 1** che nell’oggetto57 richiede il backend USB può essere prodotto dal **timer UI1**. La sua registrazione è condizionale e può fallire. Cambiare il default a MSDC decide il backend quando il percorso lo raggiunge; non garantisce da solo che questa richiesta venga prodotta.

La catena eseguita nel laboratorio è:

```text
UI57 / evento4405 / callback22451C
  → ingresso22457C
  → registrar originale14905C
  → tabella timer443ADC
  → task UITimer149228, N scansioni limitate
  → ricerca duplicati17BE80 e coda17BC7C
  → pop17BD4C
  → callback UI57 scelto esplicitamente dal test
  → evento440E/arg1 →224704
  → cancellazione originale149028
  →138E9C →139658 → registratore backend
```

Il passaggio dal pop al callback resta una scelta del chiamante sintetico: non è stato eseguito WindowMgr né provata l’attivazione runtime dell’oggetto57.

## Due registrazioni diverse

A `0x22460E`, il lettore originale **`0x14503C(oggetto, 0x18)`** legge la word a oggetto+0x18. Con zero l’ingresso chiama:

```text
0x14905C(oggetto, 1, 1000, 1000, 0)   // sito224624
```

Con word nonzero salta questa registrazione. Il lettore non è più simulato: legge la word seminata nel descrittore di laboratorio. Nel descrittore originale `0x3EB3E8`, tale word iniziale è zero; la copia/istanza runtime e gli effetti dei servizi esterni rimangono aperti. Non è attribuito un significato fisico al campo.

Più avanti, a `0x22468E`, l’ingresso richiede anche:

```text
0x14905C(oggetto, 4, 10000, 1000, 0)
```

I numeri sono intervalli interni del modello; questa verifica non li converte in millisecondi reali. L’handler UI distingue i timer: solo il caso1 qui seguito chiama il backend.

## Capacità, errore ignorato e registrazione parziale

Il registrar e il cancellatore originali usano **40 record da 28 byte** in `[0x443ADC, 0x443F3C)`. Sono eseguiti ricerca della voce precedente, normalizzazione degli intervalli, assegnazione, flag attivo e ritorno1/0 del registrar. I chiamanti UI di queste due registrazioni non ne confrontano il ritorno.

| Word oggetto+18 | Record occupati iniziali | Effetto provato |
|---|---:|---|
| 0 | 0 | Registra timer1 e timer4; timer1 produce la richiesta backend |
| 0 | 39 | Timer1 occupa l’ultima voce; timer4 non viene assegnato; la richiesta backend avviene comunque |
| 0 | 40 | Entrambe le assegnazioni falliscono; questo percorso non produce la richiesta backend |
| 1 | 0 oppure39 | Timer1 saltato; timer4 assegnato; nessuna richiesta backend entro il limite provato |
| 1 | 40 | Timer1 saltato e assegnazione timer4 fallita; nessuna richiesta backend entro il limite |

I proprietari delle voci occupate sono sentinelle non corrispondenti all’oggetto57 e i loro flag sono inattivi. La piena capacità è quindi una precondizione sintetica, non un’osservazione sulla macchina. Non è dimostrato che tutti gli altri percorsi di richiesta USB manchino in quei casi.

Il registrar invia la notifica di lavoro anche quando non riesce ad assegnare la voce, con il flag globale di laboratorio iniziale0. **La notifica del registrar non prova l’esistenza di un timer assegnato.** Nella traccia finale ci sono36 ingressi al registrar e16 passaggi sul ramo di mancata assegnazione `0x14909A`.

## Scadenza, duplicati e cancellazione

Il task originale è identificato dal descrittore `0x372548`, ingresso `0x149228`, nome **UITimer** a `0x3764BB`. Sono eseguite 20 oppure40 scansioni complete dei40record per caso. Il servizio dell’orologio restituisce sempre zero e l’attesa temporale è simulata: il calcolo originale impone il passo minimo50. Non sono letture di tempo fisico.

Con timer1 assegnato, dopo20scansioni il contatore iniziale1000 arriva a zero; viene accodato `(oggetto57, 0x440E, 1)`. Nei casi da40scansioni si raggiunge anche la successiva scadenza, ma la ricerca originale `0x17BE80` trova l’evento già presente e sopprime il duplicato. Il controllo indipendente della traccia conta **quattro passaggi a `0x17BED4`** che restituiscono presenza, e **otto pubblicazioni a `0x1492F6`** nell’intera matrice.

Dopo il pop, il callback57 viene invocato esplicitamente dal test. La cancellazione reale `0x149028` disattiva la voce timer1 e azzera il suo proprietario; il ramo di eliminazione degli eventi in coda `0x17C074` viene percorso con ring già vuoto. Sono quindi provati il disarmo del timer e la selezione backend con guardia, **non la compattazione di una coda con altri eventi**.

Nei casi positivi, selettore1 sceglie il registratore MSDC e selettore2 quello PTP; la notifica ComMgr avviene una volta. Nei casi negativi non viene chiamato un backend. I corpi dei backend restano simulati.

## Riproducibilità e dati di laboratorio

```bash
python3 Python_Trace_Scripts/s33_verify_usb_timer_trigger.py
```

[Script](../Python_Trace_Scripts/s33_verify_usb_timer_trigger.py), [indice](../Risultati/USB_MSDC_Default/Timer_UI57/latest.json), [manifest](../Risultati/USB_MSDC_Default/Timer_UI57/20261020T205912Z/verified_evidence.json), [24 casi](../Risultati/USB_MSDC_Default/Timer_UI57/20261020T205912Z/cpu_cases.json), [GNU](../Risultati/USB_MSDC_Default/Timer_UI57/20261020T205912Z/gnu_verified.txt), [sostituzioni](../Risultati/USB_MSDC_Default/Timer_UI57/20261020T205912Z/fixture_patches.json).

Esito `PASS_UI57_ORIGINAL_TIMER_BOUNDED_TRIGGER`: 24casi, exit0, nessun fault,404.983istruzioni;16finestre GNU e613PC originali distinti controllati contro il Main fornito. Matrice:2selettori ×2word oggetto+18 ×3occupazioni ×2limiti di scansione. Otto casi raggiungono il backend,16no; selettore, record del primo slot disponibile, evento, notifiche e contatori controllati.

Firmware originale V1.1 di29.602.084byte, SHA-256 `1d34e990a8f99019ffa53ca5de785399df863e942739a667ceb314ec6ce62a39`, identità16payload verificata.28input per hash,828artefatti.32ingressi esterni sostituiti: servizi UI/volumi, lock e contesto, orologio/attesa temporale, attesa/segnalazione eventi, getter runtime e backend. Registrar, cancellatore, tasktimer, ricerca duplicati, push/pop e lettore campo oggetto conservano i byte originali.

Il task reale non ritorna. Dopo N scansioni, lo stub dell’orologio ripristina esplicitamente lo SP salvato e salta a una continuazione di laboratorio. Questo delimita il test: **non è un ritorno firmware, un cambio task originale o una prova di scheduler**. Le notifiche e le attese sono registratori, senza risveglio reale. Le scansioni con orologiozero dimostrano soltanto il comportamento sotto quel contesto temporale dichiarato.

La tabella timer ha un padding di28byte per controllare la sentinella dopo il quarantesimo record nei casi pieni; non è una quarantunesima voce disponibile. Le aree aggiunte sono soltanto fixture, non RAM assegnata ad AkeruOS. Nessuna scrittura negli alberi GNU.

## Continuazione

Seguire la selezione e la creazione effettive dell’oggetto57 e la provenienza della sua word+18; collegarle al callback Load Later che assegna il default, mantenendo distinti ordine statico, scheduling e stato runtime. Restano usi dei callback USB, writer indiretti/alias/copie, proprietà SD e recupero fisico.

Candidato MSDC invariato, SHA-256 `af65ab0e66781c1a1036ab2349700e9d2110c6618738b02208da8b83c8813544`. Nessuna enumerazione USB, installazione o scrittura SD. Default selezionato e trigger del backend rimangono distinti dalla disponibilità del disco sul computer. NO-GO e circa10% funzionale AkeruOS invariati.

## Continuazione hardware — installazione riferita e PTP, 20 ottobre2026

L’utente riferisce installazione del candidatoMSDC con messaggio completato e accensione manuale prima delcavo. La [nuova osservazione hardware](S33_USB_MSDC_Default_Installazione_Riferita_e_PTP_Hardware.md) conserva10campioni PTP06/01/01 senza discoNikon; non è stato riletto il codice flash/runtime. I precedenti risultati restano prove locali, non dimostrazione diMSC operativo. Prossimo confronto: collegamento da spenta;nessun altroflash/reset/formattazione per questa osservazione.
