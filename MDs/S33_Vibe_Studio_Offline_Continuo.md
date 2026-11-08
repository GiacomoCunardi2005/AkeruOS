# Studio generale continuo con Mistral Vibe

21 ottobre 2026 — strumento di supporto R0, nessun avanzamento funzionale del
firmware: circa 10% invariato. Script:
[s33_vibe_offline_loop.py](../Python_Trace_Scripts/s33_vibe_offline_loop.py).

Il programma richiama `vibe --yolo` in modalità headless, una sessione alla volta,
senza limite al numero di cicli per impostazione predefinita. Ogni sessione riceve
il contesto del progetto e deve affrontare un punto aperto verificabile dello
studio generale: sensore, obiettivo, pulsanti, display, acquisizione, JPEG,
salvataggio, runtime o caricamenti. Il prompt richiede sottoagenti `explore` per
ricerca e revisione, se disponibili, e lascia la scrittura al coordinatore.

## Avvio e arresto

Da qualsiasi directory:

```bash
python3 /home/jack/Documenti/NikonS33_AkeruOS_Alpha1/Python_Trace_Scripts/s33_vibe_offline_loop.py
```

Il processo resta in primo piano fino a Ctrl+C, SIGTERM o creazione del file:

```bash
touch /home/jack/Documenti/NikonS33_AkeruOS_Alpha1/Risultati/Vibe_Offline/STOP
```

Il file STOP resta presente: rimuoverlo esplicitamente prima di un nuovo avvio.
Un lock impedisce due istanze di questo runner nello stesso progetto; non blocca
altri editor o sessioni Vibe avviate manualmente. Evitare modifiche simultanee
agli stessi rapporti. Alla ripartenza nasce un nuovo diario; il passaggio di
consegne persistente è [S33_Vibe_Offline_Checkpoint.md](S33_Vibe_Offline_Checkpoint.md).
Non usa `--continue`, che potrebbe riprendere sessioni estranee. Dopo `turn_limit`
usa `--resume` con l’UUID esatto restituito nell’export di quella sessione.

Anteprima senza chiamate al modello:

```bash
python3 Python_Trace_Scripts/s33_vibe_offline_loop.py --dry-run
```

Esempio di esecuzione limitata:

```bash
python3 Python_Trace_Scripts/s33_vibe_offline_loop.py --max-rounds 2 --max-price 1
```

`--max-rounds 0` significa infinito. Default per sessione: 60 turni e 1800 secondi;
pausa 15 secondi dopo exit 0. Il limite turni (`outcome: turn_limit`, exit 3) viene registrato separatamente:
la sessione viene ripresa con il suo UUID al ciclo seguente, dopo la pausa
normale. Gli altri errori causano attese crescenti da 30 fino a
900 secondi, senza interrompere definitivamente il ciclo. Un exit 3 di Vibe
per limite temporale resta registrato come uscita non riuscita, senza cancellare
eventuali risultati prodotti. Il runner terminato normalmente restituisce 0
anche se alcune sessioni falliscono: consultare i codici individuali nei diari.
`--max-price` è facoltativo e limita ogni singola sessione, **non il costo totale**
del ciclo infinito. Il runner usa modello e credenziali già configurati in Vibe.

## Log e continuità

In `Risultati/Vibe_Offline/`:

- `latest.json`: ultima sessione/iterazione, stato, comando, tempi ed exit code.
- `<data_UTC_pid>/journal.jsonl`: diario di tutte le iterazioni della sessione.
- `round_NNNNNN/prompt.txt`, `console.log`, `run.json`: input e risultato locali.
- `round_NNNNNN/vibe/`: export e journal che la CLI Vibe salva all'uscita.

Ogni cartella è distinta; i log precedenti sono conservati. La console interpreta gli eventi `--output streaming`: mostra i messaggi
dell’assistente con prefisso `Vibe:` e una riga per operazione. Prompt,
ragionamento e contenuto completo dei file letti restano nel log integrale
grezzo; `--raw-output` permette di mostrare anche il JSON nel terminale. Con `--quiet` si disattiva la
diretta mantenendo i log. Una sola sessione Vibe resta attiva alla volta. Per l'arresto il runner
manda SIGTERM al gruppo Vibe, attende fino a `--grace` secondi (default 30), poi
usa SIGKILL; un watchdog interviene se la CLI non rispetta il proprio limite.
Un SIGKILL al runner stesso o un'interruzione di alimentazione possono lasciare
`status: running` e discendenti: non sono arresti gestibili dal programma.

## Ambito e verifiche

La CLI locale è stata verificata tramite `vibe --version` e `vibe --help`:
versione 3.0.1, flag `--yolo`, `--prompt-file`, `--workdir`, `--time-limit`,
`--output-dir`, `--max-turns` e `--max-price`. Il sorgente locale di
`vibe/core/tools/builtins/task.py` documenta l'agente predefinito `explore`.
Non sono state modificate configurazioni di Vibe.

Il prompt impone esclusivamente analisi locale e vieta interazioni hardware,
installazione di firmware, accesso ai dispositivi, scritture SD e modifiche GNU.
**Questi vincoli sono istruzioni al modello, non una sandbox tecnica**:
`--yolo` approva gli strumenti del processo con i permessi dell'utente.
Offline descrive lo studio del firmware; le richieste a Mistral richiedono rete
e possono trasmettere al servizio il contenuto letto dal modello.

Collaudo riproducibile senza API e senza fotocamera:

```bash
python3 Python_Trace_Scripts/s33_test_vibe_offline_loop.py
```

Le prove e gli hash del runner sono in
[test_latest.json](../Risultati/Vibe_Offline/test_latest.json).
Nessuna sessione Mistral reale è stata avviata per il collaudo; autenticazione,
qualità delle scoperte e delegazione effettiva dipendono dalla futura esecuzione.
Il checkpoint iniziale propone di riprendere i punti aperti recenti della roadmap.

## Diretta nel terminale — aggiornamento del 21 ottobre 2026

12 test offline PASS, inclusi messaggio visibile prima della conclusione della
sessione e modalità quiet con log preservato. Nessuna chiamata Mistral reale.

## Flusso leggibile — correzione del 21 ottobre 2026

L’output reale incollato dall’utente mostra messaggi NDJSON di tipo message,
reasoning ed effect: la precedente diretta riversava metadati e output dei tool.
L’ultimo evento incollato è troncato. Il renderer ora filtra quei campi, gestisce
righe, UTF-8 spezzati ed eventi JSON non leggibili, e sopprime snapshot duplicati.
15 test offline PASS e replay dell’output incollato PASS;
[anteprima leggibile](../Risultati/Vibe_Offline/display_replay.txt). Nessuna nuova
chiamata Mistral da parte nostra; l’output utente prova l’inizio di una sessione
reale, non il completamento dello studio. Un processo già attivo deve essere
riavviato con Ctrl+C e lo stesso comando per caricare questa correzione.

## Ripresa dopo limite turni — 21 ottobre 2026

L’output utente e l’export locale della sessione
`ce5331f6-abab-fa45-212a-852bd6c3d1d9` indicano `turn_limit`, `stop_reason: limit`,
exit 3. I 60 turni erano esauriti, non un crash. Prima il runner classificava
ogni exit nonzero come errore e iniziava da un nuovo contesto al ciclo seguente.
Ora legge solo i metadati di esito e salva l’UUID in
`Risultati/Vibe_Offline/continuation.json`, poi richiama `--resume UUID`
con un prompt breve che dà priorità a chiudere e documentare il lavoro avviato.
Una sola chiamata Vibe alla volta; il prompt richiede anche checkpoint intermedi.

La continuazione sopravvive al riavvio del runner; se manca il file, può essere
recuperata dall’ultimo export `turn_limit` indicato da `latest.json` all’interno
della cartella dei log. Un normale exit 0 chiude la continuazione. Altri errori
restano errori: exit 3 da solo non basta a identificare un limite turni.
Le due opzioni quiet/raw e il log integrale restano disponibili.

18 test simulati PASS, incluse ripresa nello stesso ciclo persistente, ripartenza
del programma e recupero del vecchio export. Non è stata inviata da noi una
nuova richiesta al modello né verificato il completamento della ricerca.
Per caricare la correzione serve riavviare il runner già attivo.

## Correzioni ripetute nello studio

Il 21 ottobre il ciclo è stato fermato e un verificatore riparato; vedere
[rapporto e prove](S33_Vibe_Blocco_Riparazione_Wrapper_Obiettivo.md). Il prompt
ora richiede di fermare una serie di tentativi falliti e lasciare un checkpoint,
senza sed globale sulle regex né pipe che nascondano l’exit code Python.
Il supervisore non rileva automaticamente ogni stallo semantico del modello.

## Controllo del silenzio ed errori strumenti

[Correzione e verifiche](S33_Vibe_Silenzio_Watchdog_e_Errori_Reali.md): default
`--heartbeat 30` e `--idle-timeout 300`, configurabili in secondi. Una sessione
senza nuovi byte di output per 5 minuti viene terminata; il ciclo successivo
legge il riferimento al log in `recovery.json` e parte con un contesto nuovo.
Lo stato negativo degli strumenti è visibile come failed, con ultima riga
dell’errore. Tracciati anche figli che creano nuove sessioni di processo.
20 test simulati PASS. Il runner lasciato attivo prima di questa modifica
deve essere riavviato per caricare il controllo automatico.
