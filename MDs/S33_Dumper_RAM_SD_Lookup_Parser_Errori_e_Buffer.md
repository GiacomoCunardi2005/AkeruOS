# Dumper RAM: lookup originale, parser, errori e buffer

**Aggiornamento prioritario:** [catena integrata e falso successo](S33_Dumper_RAM_SD_Lookup_Integrato_e_Falso_Successo_Parser.md). Le condizioni a fixture di questo rapporto non predicono ogni esito della catena originale: errore alloc257 del parser, scratch0, finder originale→record vuoto con stato0, accettato dalla callbackr. Non assumere sempre01A00002 né identità del file dal solo successo. Risultato offline, non hardware.

23 ottobre 2026, R0/R1/R4. Segue [handle di lettura e protezione volume](S33_Dumper_RAM_SD_Handle_Lettura_e_Protezione_Volume.md). **18 casi CPU eseguono2A3360, il parser29FFB0/29FF74, i validatori e l'allocatore259A58 originali.** I due livelli inferiori che cercano directory e record rimangono fixture. Il test precedente di r non viene dichiarato automaticamente integrato con questa nuova prova separata.

Il risultato più rilevante è un errore mascherato: se fallisce il buffer interno del parser,2A3360 non propaga il suo errore. Nel profilo con scratch inizialmente zero e lookup inferiore senza corrispondenza per nome vuoto, l'esito diventa01A00002 anziché01A00006. Il solo esito «non trovato» non dimostra quindi che tutte le fasi di preparazione siano riuscite.

## Prove riproducibili

- [Runner](../Python_Trace_Scripts/s33_verify_ram_dump_sd_lookup.py), [probe](../S33-sections/analysis_ghidra/scripts/ProbeDumpSDLookup.java).
- [Manifest](../Risultati/Runtime_Kernel/RAM_Dumper_SD_Lookup/20261022T235541Z/verified_evidence.json), [18 esiti](../Risultati/Runtime_Kernel/RAM_Dumper_SD_Lookup/20261022T235541Z/trace.txt), [sei finestre GNU](../Risultati/Runtime_Kernel/RAM_Dumper_SD_Lookup/20261022T235541Z/gnu_verified.txt), [log](../Risultati/Runtime_Kernel/RAM_Dumper_SD_Lookup/20261022T235541Z/headless.log).

```bash
python3 Python_Trace_Scripts/s33_verify_ram_dump_sd_lookup.py
```

2A3360 riceve un contesto predisposto backend1, percorso già privo di prefisso B:, puntatore stato e due uscite metadata. Il flag context+720 vale1, salvo un controllo con0. La prova è del coordinatore, non dell'intera callback open o di una FAT montata.

**Originali eseguiti:**2A3360,29FFB0/29FF74,2A47C4/2A461C, stringhe/copie, confronto2A0484 e ramo numerico;259A58 con il contatore critico originale del task.

**Fixture esplicite:** allocazione inferiore2E4EC4 e registrazione metadati2599AC, free25980C; walker directory2A318C restituisce2 o sentinella1; finder record2A2D88 espone un dataset sintetico con nomi AKERUDMP.ON/FILE.BIN/DIR, oppure errore/assenza. I metadata restituiti dal finder sono0x22/0x33. Nessuna lettura SD, I/O USB o mutazione del contenitore firmware. Hash/snapshot e payload canonici verificati; GNU solo letto/eseguito.

## Parsing e selezione della base directory

29FFB0 separa la parte directory dal componente finale. Sono eseguiti entrambi i separatori, componenti annidati, un percorso relativo e un separatore finale. I seguenti valori sono gli argomenti realmente ricevuti dai confini inferiori nel modello.

| Percorso | Directory normalizzata | Base passata al walker | Componente finale |
|---|---|---|---|
| `\AKERUDMP.ON` o `/AKERUDMP.ON` | `\` | 0 | `AKERUDMP.ON` |
| `AKERUDMP.ON` | vuota | 0x123, valore predisposto in context+0x74 | `AKERUDMP.ON` |
| `\DIR\AKERUDMP.ON` | `\DIR` | 0 | `AKERUDMP.ON` |
| `/DIR/sub/FILE.BIN` | `\DIR\sub` | 0 | `FILE.BIN` |
| `\DIR\` | `\` | 0 | `DIR` |

Il componente DIR nel caso con separatore finale viene passato al finder, che nel dataset sintetico lo trova. Questo non dimostra che il percorso possa essere aperto come file: la callbackr successiva controlla gli attributi del record, qui non eseguita. Gli input originali sono verificati invariati.

Nel profilo zero, percorso vuoto e A*B.TXT arrivano al finder rispettivamente come nome vuoto e A*B.TXT, che la fixture non trova:2A3360 produce01A00002. Non si deduce la semantica reale di wildcard o nomi vuoti del finder. In particolare il chiamante21A0D0 ha già un controllo sul nome iniziale: i due input diretti non rappresentano tutti percorsi raggiungibili attraverso l'open r.

## Allocatore e contenuto dello scratch

La sequenza con flag1 richiede **517 byte** per directory/nome, **257 byte** interni a29FFB0, **256 byte** per il componente usato dal coordinatore. La sequenza con flag0 ne richiede soltanto517/257.

259A58 è eseguito fino all'allocatore inferiore e alla registrazione metadati: **in questo wrapper non compare l'azzeramento che era stato provato per268EE4**. Il livello inferiore è simulato, quindi non si assegna un contenuto iniziale universale al vero heap Nikon. La prova usa due profili espliciti, riempimento0 e0xA5.

Tutti i buffer realmente allocati nei18casi vengono rilasciati esattamente una volta. Guardie da16byte ai lati rimangono0xA5; stack e nesting critico ritornano ai valori iniziali. Nessuna liberazione riguarda un puntatore non posseduto dal modello.

Con nome alla radice e flag1, il profilo0 raggiunge il finder tramite **2A34BA**; il profilo0xA5 tramite **2A353A**. Il confronto originale2A0484 legge il buffer del componente e la stringa context+448; per la directory radice il buffer non è stato riempito da un componente. Il percorso è quindi sensibile al contenuto esplicito dello scratch. Nel dataset della prova entrambi trovano lo stesso record e restituiscono0. Non è una misura dello stato del heap fisico né una dimostrazione di identica semantica dei due finder in ogni circostanza.

I casi annidati prendono2A353A con entrambi i profili. La traccia conserva i conteggi dei due callsite, senza identificarli soltanto tramite i loro esiti finali.

## Esiti e errore del parser non propagato

| Condizione | Stato finale | Finder finale | Buffer rilasciati |
|---|---|---:|---:|
|nomi validi con record nel dataset|0|1|3, o2 con flag0|
|walker directory restituisce sentinella1|01A00003|0|3|
|finder restituisce nullo con stato0|**01A00002 sintetizzato da2A3360**|1|3|
|finder restituisce nullo con errore01A00021|01A00021 conservato|1|3|
|prima allocazione517 fallisce|01A00006|0|0|
|allocazione257 del parser fallisce, scratch0|**01A00002**|1, con nome vuoto|2|
|terza allocazione256 fallisce|01A00006|0|2|
|puntatore percorso nullo|01A00013|0|1|

Il callsite **2A33AA→29FFB0** non controlla il ritorno: a **2A33B0 sovrascrive r0 con context+720**. Quando l'allocazione257 fallisce,29FFB0 ritorna01A00006 prima di inizializzare le stringhe d'uscita. Nel profilo0 queste restano vuote; il coordinatore continua, alloca il componente256 e arriva al finder. La mancata corrispondenza viene infine tradotta in01A00002. Non vi è una perdita di buffer nei casi eseguiti: è la classificazione dell'errore a cambiare.

Questa catena è verificata soltanto per scratch0 e per il finder del modello. Non sostituirla con un'affermazione universale su ogni errore di memoria o ogni file mancante della Nikon. I tentativi preliminari hanno corretto un'ipotesi errata sui nomi con separatore finale e una fixture che trovava qualunque nome, compreso il vuoto: gli snapshot storici sono conservati, la prova pubblicata usa il dataset esplicito.

Lo stato temporaneo **context+764 (191×4)** risulta0 a ogni uscita completata; le uscite metadata non usate restano ai canary iniziali. Quando il finder viene effettivamente chiamato, i metadata possono essere già modificati anche con ritorno d'errore: il solo stato non autorizza a considerarli nuovi risultati validi.

## Conseguenze e prossimo passo

Il futuro adattatore non deve interpretare «non trovato» come prova di assenza fisica senza considerare l'intero percorso e i suoi fallimenti. Questo non cambia il contratto del prototipo né giustifica l'uso dei percorsi di creazione come controllo di esistenza. La prova del riferimento r del rapporto precedente rimane valida nella sua portata, ma deve ancora essere raccordata a questo coordinatore originale.

Prossimo: seguire2A318C e2A2D88, con i relativi stati e buffer, poi integrare il tratto originale nel percorso r e verificare gli altri scrittori del backend/sincronizzazione. Rimangono lookup fisico, concorrenza, altri backend, mappa RAM completa e lifetime launcher/stack.

Nessun C o BIN modificato; nessuna fotocamera o SD fisica usata. **NON_INSTALLARE**, circa10% funzionale AkeruOS invariato, obiettivo generale ancora attivo.

## Continuazione — walker e scanner originali, 23 ottobre 2026

[Nuova verifica](S33_Dumper_RAM_SD_Directory_e_Scanner_Record_Originali.md):20casi con2A318C originale nel coordinatore,8separati dello scanner2A2D88 su settore sintetico,18regressione. Errori directory e allocnull diventano01A00003; al marcatore0 lo scanner può conservare lo stato ricevuto. Non sono ancora una catena integrata né I/O fisico; prossimo albero di settori sintetici e raccordor. NON_INSTALLARE.
