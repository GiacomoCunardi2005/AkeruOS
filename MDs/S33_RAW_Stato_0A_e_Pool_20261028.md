# S33 V1.1 — stato CaptureImage 0x0A e inizializzazione del pool RAW

28 ottobre 2026. Verifica statica dei collegamenti e tre sequenze CPU con chiamate ordinate dal banco e servizi sintetici. Nessun accesso a fotocamera o SD; **NON_INSTALLARE**.

## Risultato

Il sito CaptureImage stato `0x0A` a `0x65F262` passa **zero** come argomento che giunge a `0x18ED60` e seleziona il ramo del pool interno, purché il controllo preliminare e le chiamate intermedie arrivino a quel punto. Questo rafforza il raccordo con il confronto fra distanza dei nodi e writer 2N, senza provare che il percorso sia stato effettivamente eseguito da uno scatto reale.

Il produttore di stato `0xCBAF0`, nel caso documentato che scrive `0x0A`, inizialmente scrive anche **zero nel selettore pool `0x366E34`**. I due rami che scrivono direttamente 1 o 2 nel selettore escono invece prima del caso che scrive stato `0x0A`. Se quel selettore non viene successivamente modificato e il pool è **inattivo** quando viene inizializzato, la distanza fra inizi dei nodi è `0xCA6400`, più corta della lunghezza 2N richiesta dal writer. Non è ancora dimostrato che queste condizioni rimangano vere lungo l'intero percorso: servizi chiamati, altre attività, riscritture e un pool già attivo restano da verificare. Il selettore RAW `0x366F90` è distinto da quello del pool.

## Catena statica degli argomenti

1. Il sito `0x65F25C` prepara `r2=0`; a `0x65F262` chiama `0x1B9EA8`. Il ramo che lo raggiunge richiede stato CaptureImage `0x0A` e altri controlli già documentati in [origine dello stato](S33_S2_Stato_CaptureImage.md).
2. `0x1B9EBA` conserva `r2` in `r21`. Se il precontrollo `0x12F0AC` restituisce zero, `0x1B9F0E` ripristina `r2=r21` e `0x1B9F1E` chiama `0x1B8F24`.
3. `0x1B8F3C` salva il terzo argomento in `fp−200`. Il valore a `fp−204` è l'argomento di stato e nel caso `0x0A` non seleziona il ramo `0x10`. `0x1B8FFC` ricarica `fp−200` come `r0`; `0x1B9004` chiama `0x18ED60`.
4. Con `r0=0`, `0x18ED60` chiama `0x141CE8` a `0x18EDA2`. Questo può chiamare l'inizializzatore `0x18E4B4`; l'inizializzatore salta la creazione dei nodi se il pool risulta già attivo. Una chiamata arrivata a questo punto non dimostra quindi una nuova inizializzazione o successo dell'acquisizione.

## Produttore stato e selettore pool

`0xCBAF0` chiama `0x141CC4(0)` a `0xCBB0E`, scrivendo `word[0x366E34]=0`. Nelle guardie speciali, codice modalità `0x6D` porta a `0x141CC4(1)` e codice `0x68` a `0x141CC4(2)`; entrambi escono tramite `0xCBB62` prima del ramo `0xCBBC8` che scrive `0x0A` nell'uscita. Altre chiamate a servizi hanno effetti non completamente esauriti e possono esistere altri scrittori: il semplice fatto che il produttore abbia restituito `0x0A` non stabilisce in assoluto il valore del selettore alla successiva inizializzazione del pool.

Il collegamento condizionale esistente passa dal byte `0x681EAF` alla transizione CaptureImage, fino al controllo dello stato `0x0A`. La consegna degli eventi, eventuali alterazioni del byte, invocazioni concorrenti e tempi non sono qui dimostrati. La voce diagnostica `Take12BitCCDRawImage` imposta il diverso selettore `0x366F90` a 3 quando abilitata; non è stato stabilito un effetto diretto di quella voce su `0x366E34` o un'invariante fra i due valori.

## Prova CPU

Eseguire `python3 Python_Trace_Scripts/s33_verify_raw_state_pool_cpu.py`. Il banco usa gli ingressi originali `0xCBAF0` e `0x18ED60`, chiamati direttamente in questo ordine, con selettore pool iniziale 2, modo sintetico 4, pool inattivo, coda e regione modellate. Tre casi PASS: ingressi del produttore `(0,2)` danno stato `0x0A`, `(0,3)` danno `0x0B`, `(1,2)` danno zero; tutti lasciano selettore pool zero e la distanza osservata dei primi due nodi `0xCA6400`. Il banco controlla anche le istruzioni originali della catena argomenti CaptureImage sopra, ma **non esegue** CaptureImage, il wrapper, il writer, lo scatto o il JPEG.

[Script](../Python_Trace_Scripts/s33_verify_raw_state_pool_cpu.py), [casi](../Risultati/Mono_RAW/state_pool_cpu_20261028T143655Z/cases.json), [flusso statico](../Risultati/Mono_RAW/state_pool_cpu_20261028T143655Z/capture_flow.txt), [finestre originali](../Risultati/Mono_RAW/state_pool_cpu_20261028T143655Z/gnu_windows.txt), [fixture](../Risultati/Mono_RAW/state_pool_cpu_20261028T143655Z/fixture_patches.json). Regione di 256 MiB, indirizzi, riserve e code sono sintetici; solo il suo inizio è mappato e nessun frame è letto. Il simulatore usa il modello DSP sperimentale. I tentativi falliti iniziali sono conservati: le finestre includevano dati o un'istruzione troncata, poi corrette senza alterare il firmware.

Il [confronto precedente](S33_RAW_Pool_Stride_Confronto_Writer_20261028.md) quantifica la possibile sovrapposizione. Non prova validità degli indirizzi, allocazione fisica, stesso frame, corruzione o persistenza dei file.
