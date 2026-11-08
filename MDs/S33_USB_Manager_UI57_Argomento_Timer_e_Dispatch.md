# USB: richiesta al manager UI57, argomento di inizializzazione e timer

20 ottobre 2026 — R0/R3/R4. Continuazione del [timer UI57](S33_USB_Timer_UI57_Registrazione_Scadenza_e_Limiti.md). Prova locale del codice originale V1.1; nessuna nuova azione sulla fotocamera o sulla SD.

## Risultato verificato

La word a **oggetto+0x18**, che condiziona la registrazione del timer1, può essere assegnata dal wrapper originale di inizializzazione **`0x16A05C`**, tramite lo store **`0x16A0AC`**. Nel percorso provato riceve l’argomento della richiesta **`0x1453E4(0x57, argomento)`**. Non è più un valore semplicemente seminato dal test prima del callback di ingresso.

Con richiesta accettata, argomento zero e timer disponibile, la catena originale arriva al selettore USB e al registratore del backend. Con argomento uno, il timer1 viene saltato. Il parametro qui studiato è l’argomento del manager UI: **non è il parametro di USBDevModeSwitch né il selettore PTP/MSDC**.

Questo chiude la provenienza del campo per una **richiesta con manager inizialmente vuoto**. Non dimostra chi produca quella richiesta durante l’avvio fisico, il suo ordine rispetto al default MSDC o la causa dell’[enumerazione PTP osservata](S33_USB_MSDC_Default_Installazione_Riferita_e_PTP_Hardware.md).

## Catena originale eseguita

```text
Fixture: manager366E94 vuoto, hook nulli, descrittore57 originale
  →145018(tabella3F5900, conteggioC5)
  →1453E4(57, argomento)
  →14507C risolve57 a3EB3E8
  →145180 verifica/transizione del manager
  →169D78 / evento4403 →16A6E4 →16A028 →22451C →224554
  → se accettata:169D78 / evento4401 →16A05C
      →16A0AC scrive l’argomento a oggetto+18
  →1452EE pubblica l’oggetto corrente
  →169D78 / evento4405 →16A188 →16A028 →22451C →22457C
      →14503C legge oggetto+18 →14905C registra i timer
  →UITimer149228,20 scansioni limitate
  →dedup17BE80 →push17BC7C →pop17BD4C
  →169D78 sul proprietario letto dalla coda
  →16A6E4 →16A028 →22451C /440E,arg1 →224704
  →149028 cancella timer1 →138E9C →139658 →registratore backend
```

Il pop è ancora chiamato dal laboratorio; questa volta il proprietario, l’evento e l’argomento sono consegnati al **dispatcher originale `0x169D78`**. Non viene scelto direttamente il callback57. Rimangono esclusi il task WindowMgr e il suo scheduler.

Le tabelle di salto del dispatcher sono controllate come dati: nove byte a `0x169DDC`, ingressi a `0x169DE6` e pool a `0x16A138…0x16A160`. Il pool del manager a `0x145350…0x145378` rimane distinto dal codice. La coppia evento4401/4405 seleziona rispettivamente `0x16A05C` e `0x16A188`; 4403 e440E passano dal wrapper generale `0x16A6E4`.

## Matrice e controlli

**16 casi:** due selettori1/2 × due argomenti0/1 × due esiti del getter del tasto logico `0x66` × due occupazioni timer0/40. Ogni caso esegue20scansioni. La word+18 parte da `0xDEADBEEF`, così il suo azzeramento non può essere attribuito alla fixture iniziale.

| Getter tasto logico0x66 | Argomento UI | Timer occupati | Risultato provato per ciascun selettore |
|---|---:|---:|---|
| 0 | 0 oppure1 | 0 oppure40 | Validazione rifiutata, ritorno0, nessun oggetto corrente, word+18 restaDEADBEEF, nessuna registrazione |
| 1 | 0 | 0 | Ritorno1, word+18=0, timer1 e4 assegnati, una chiamata al backend |
| 1 | 0 | 40 | Ritorno1, word+18=0, entrambe le assegnazioni falliscono, nessuna chiamata backend |
| 1 | 1 | 0 | Ritorno1, word+18=1, solo timer4 assegnato, nessuna chiamata backend nel limite |
| 1 | 1 | 40 | Ritorno1, word+18=1, timer4 non assegnato, nessuna chiamata backend |

Il getter del tasto è simulato; `0x66` è un identificatore logico **esadecimale**, non una mappatura a un pulsante fisico. Non attribuire l’esito di validazione alle spie o a una misura hardware.

Negli otto casi accettati, i flag del descrittore passano da `0x402` a `0x702`, il manager pubblica `0x3EB3E8` e torna con busybyte zero. Negli otto casi rifiutati conserva i flag iniziali e la sentinella del campo. Sono verificati SP prima/dopo richiesta, SP ripristinato dall’uscita timer di laboratorio, risoluzione dell’ID, contatori di notifiche, record timer, proprietario/evento/argomento in coda, selettore e guardia USB.

I due casi che raggiungono il backend producono rispettivamente il registratore MSDC con selettore1 e quello PTP con selettore2. **Non sono corpi hardware del backend.** I contatori della traccia verificano16richieste,16validazioni,8store reali a `0x16A0AC`,8ingressi4405,34ingressi al dispatcher,12registrazioni timer,6fallimenti di assegnazione e2richieste backend. Nessun duplicato al limite20scansioni.

## Riproduzione ed evidenze

```bash
python3 Python_Trace_Scripts/s33_verify_usb_timer_trigger.py --manager-entry
python3 Python_Trace_Scripts/s33_verify_usb_timer_trigger.py
```

Lo [script esistente](../Python_Trace_Scripts/s33_verify_usb_timer_trigger.py) ora accetta `--manager-entry`; senza opzione conserva la matrice precedente. Gli output dei due modi restano separati.

- [Indice manager](../Risultati/USB_MSDC_Default/Manager_UI57/latest.json), [manifest](../Risultati/USB_MSDC_Default/Manager_UI57/20261020T211658Z/verified_evidence.json), [casi](../Risultati/USB_MSDC_Default/Manager_UI57/20261020T211658Z/cpu_cases.json), [GNU](../Risultati/USB_MSDC_Default/Manager_UI57/20261020T211658Z/gnu_verified.txt), [fixture](../Risultati/USB_MSDC_Default/Manager_UI57/20261020T211658Z/fixture_patches.json).
- Esito **PASS_UI57_COLD_MANAGER_AND_TIMER_TRIGGER**,16casi,194.754istruzioni,exit0,nessun fault;28finestre e955PC originali distinti verificati contro il Main fornito.28input e903artefatti registrati per hash,35servizi esterni sostituiti.
- [Regressione timer](../Risultati/USB_MSDC_Default/Timer_UI57/20261020T211658Z/verified_evidence.json):24casi,404.983istruzioni,16finestre/613PC,exit0,nessun fault. Restano8casi backend e4duplicati soppressi. È stata rieseguita dopo la modifica dello script.

Firmware originale:29.602.084byte, SHA-256 `1d34e990a8f99019ffa53ca5de785399df863e942739a667ceb314ec6ce62a39`;16payload controllati dal preparatore esistente. Il candidato MSDC rimane `af65ab0e66781c1a1036ab2349700e9d2110c6618738b02208da8b83c8813544`.

Il primo tentativo `20261020T211601Z` ha terminato l’esecuzione CPU senza fault, ma fallito l’assert host che confrontava l’ID tasto con66decimale: la traccia e lo stato riportano `0x66`=102. Corretta solo l’aspettativa del verificatore; lo snapshot del tentativo è conservato. Una seconda esecuzione `20261020T211617Z` è passata; la versione finale sopra aggiunge anche assert sui contatori della traccia e riesegue entrambi i modi. Nessun byte firmware modificato per risolvere il fallimento.

## Assunzioni e limite della conclusione

Il contesto manager vuoto, gli hook globali nulli, i flag iniziali del descrittore, l’occupazione timer e il valore del getter del tasto sono precondizioni dichiarate. La tabella originale viene registrata mediante145018; non è stato eseguito il suo inizializzatore di boot. Associazione attributi1455E4, contesto grafico145790 e ridisegno145158 sono simulati, insieme ai servizi esterni già dichiarati nel rapporto timer. Gli effettivi binding grafici e lo schermo non sono verificati.

Orologiozero, passo minimo50, attese/notifiche registrate e uscita esplicita dal task mediante ripristino SP restano quelli del test precedente: non tempo fisico, reale risveglio o ritorno del task. Le voci occupate hanno proprietari sentinella e flag inattivi. Nessuna RAM è assegnata ad AkeruOS; strumenti e sorgenti GNU restano intatti.

## Continuazione

Seguire i **chiamanti effettivi di1453E4 con ID57**, i relativi argomenti e la relazione con il callback Load Later che imposta il default aC5EEA. Il manager freddo ora è provato nel contesto dichiarato; restano riattivazioni con oggetto precedente, hook/callback reali, scheduling e stato runtime. Non ripartire dalla semplice semina host della word+18.

Il file sulla SD è già stato [confrontato integralmente con il candidato](S33_USB_MSDC_Default_Installazione_Riferita_e_PTP_Hardware.md): questo non legge la flash della fotocamera. La prima installazione riferita era seguita da PTP; dopo la seconda è stata osservata MSDC08/06/50 con disco Nikon, poi capacità0 dopo rimozione SD. La sequenza della seconda connessione non è specificata. Confronto controllato da spenta, identità runtime, override indiretti/alias/copie, integrità dei contenuti SD e recupero fisico restano aperti. Nessun aggiornamento eseguito dall’agente. Circa10% funzionale AkeruOS invariato.
