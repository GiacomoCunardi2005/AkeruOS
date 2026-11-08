# Emulatore: profilo runtime GPIO iris, TIMER1 e service-request

22 ottobre 2026 — R0/R1/R3 — laboratorio P-code V1.1. **39 casi PASS_CONDITIONAL_RUNTIME_MODEL** eseguiti con il comando:

```bash
make -C AkeruOS runtime-devices-verify
```

Equivalente: `python3 Python_Trace_Scripts/s33_run_runtime_devices.py`.

## Cosa cambia

Il nuovo profilo opzionale `S33RuntimeDevices.java` si collega al filtro di memoria dell'emulatore P-code esistente. Il runner `ProbeRuntimeDevices.java` riusa `ProbeStatusRead` e il linguaggio `ARCompact:LE:32:loopfix`. Nessuna nuova dipendenza, modifica al firmware o ricompilazione GNU. I runner GNU e i loro profili precedenti restano invariati.

- Le coppie pending/enable delle sei tabelle generiche e della famiglia iris sono lette dai descrittori statici del payload1 verificato; la classe B iris è inclusa. Enable è una cella R/W; pending adotta l'**ipotesi W1C** per gli acknowledgement. Le richieste si iniettano con un'operazione host distinta dagli store guest; nessuna sorgente fisica o consegna automatica di interrupt è inventata.
- I GPIO `0x0FF04024` e `0x0FEF0388` conservano i valori halfword e registrano gli accessi.
- I 17 indirizzi censiti del banco `0x0FE400xx` accettano scritture halfword; le letture sono esplicitamente non modellate e fermano la prova. Il registro +0x14 non viene aggiunto.
- Accessi MMIO di larghezza diversa da due byte o a registri sconosciuti fermano il profilo. La RAM resta quella dei payload e dello stack di laboratorio, con letture non inizializzate bloccate.

## Prove eseguite sulle istruzioni originali

Evidenza valida: [verified_evidence.json](../Risultati/Runtime_Kernel/Emulator_Devices/20261022T074943Z_ca5b13e3/verified_evidence.json). Traccia: [runtime_trace.txt](../Risultati/Runtime_Kernel/Emulator_Devices/20261022T074943Z_ca5b13e3/runtime_trace.txt). La cartella conserva comando, log, snapshot dei sorgenti e hash del firmware, del manifest, del linguaggio e del motore di emulazione. `latest.json` viene aggiornato soltanto dopo un esito positivo; le prove precedenti restano conservate.

| Casi | Codice eseguito | Controllo |
|---|---|---|
| 16 | register `0x242414`, walker `0x264250`, dispatcher `0x242488` | Tutte le combinazioni enable/pending dei due livelli. Callback eseguita solo con tutti i gate attivi; seconda invocazione senza nuovo evento non ripete la callback. Pending disabilitati preservati, acknowledgement W1C applicati. |
| 8 | Big `0x2358F4`, Small `0x235950`, completion `0x2359B0` | Quattro valori iniziali GPIO, entrambe le direzioni, bit ausiliari 0/1 cancellati, flag movimento 1→0, impulso finale e spegnimento, argomento attesa 500. Eseguiti anche gli epiloghi originali. |
| 10 | handler TIMER1 `0x146104` | One-shot/periodico con countdown 0/1/2/3/7 e scala esplicita 2. Confronto al limite, decremento, ricarica 5, chiamata callback, rilascio slot e contatore attivi. |
| 1 | Main `0x301EC0` | Scritture 0x4321/0x6641/0xE972/0xFFFF nei quattro registri previsti. |
| 4 | Filtro MMIO | W1C preserva bit non serviti, scrivere zero non azzera pending; lettura banco non modellata, accesso word e store su registro sconosciuto respinti. |

## Assunzioni e limiti

I lock `0x1786E8/0x179354` sono stub di ritorno dichiarati: non vengono verificati scheduler o esclusione fra interrupt. La callback usata per contare gli invii è lo stub Nikon originale `0x241E58`, installato nel test al posto del consumatore completo `0x241E5C`. Il callback esterno della classe 0x6xx è impostato dal test al dispatcher originale `0x242488`; la registrazione interna 0x3002 viene invece eseguita dal firmware originale.

Il delay `0x23C620(500)` viene controllato e sostituito da un ritorno di laboratorio. TIMER1 viene invocato dall'host con AUX count1 iniziale 0, control1=3 e scala 2: le istruzioni del tick vengono eseguite, ma il tempo fisico e la consegna hardware dell'IRQ non sono simulati.

W1C è inferito dal codice di acknowledgement. **Il setter richieste `0x242224`, che scrive anch'esso `0xFED3818`, non è modellato da questo profilo**: la semantica completa set/clear del dispositivo resta da risolvere, senza fingere che la sola regola W1C chiuda il percorso produttore. I pending inizialmente vuoti sono un contesto sintetico, non valori di reset misurati.

Nessuna prova di boot completo, UI o foto. Circa 10% funzionale invariato, NON_INSTALLARE. Il nuovo runner non prosegue automaticamente Main oltre il limite GNU FED2018 e non sostituisce il checkpoint di boot.

## Correzione del punto di ripresa GNU

Il prossimo passo del rapporto [banco FE400xx](S33_Obiettivo_Banco_0x0FE400xx_Census_Boot_e_Main.md) suggeriva di superare lo store TBIB `0x10091F8`. Questo era **già stato fatto** dal verificatore `s33_verify_gnu_boot_device_writes.py`, come documentato in [AUX/IRQ e fonti](S33_GNU_AUX_Interrupt_e_Fonti_Archiviate.md). Esiste anche il verificatore successivo `s33_verify_gnu_boot_control_cluster.py`. Queste sono evidenze storiche lette, non verifiche rieseguite qui. Non ricominciare dallo store FE40004 né ricostruire GNU per questo passaggio.

## Prossimo punto utile

Risolvere il contratto del pending `0xFED3818` fra setter e acknowledgement, poi eseguire il consumatore completo `0x241E5C` con provider/eventi espliciti. Per il boot GNU il punto Main resta FED2018 a `0x169A84`; per TIMER1 restano sorgente IRQ, precedenza dei due installatori del vettore 7 e frequenza fisica.
