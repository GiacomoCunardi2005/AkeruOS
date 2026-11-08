# Vibe: silenzio, stato degli strumenti e watchdog

21 ottobre 2026 — supporto R0. Nessun nuovo risultato firmware; circa 10% invariato.

## Osservazione e arresto

Il runner PID 786821, Vibe PID 786822 e il server PID 786824 erano attivi;
nessun processo Python del verificatore risultava in esecuzione. L'ultimo
evento del log, alle 21:32:08 UTC, conteneva:

```text
AssertionError: semaphore 0x12A71C missing
```

Lo strumento aveva `state.status: completed`, ma `state.display.success: false`.
Il renderer precedente usava solo il primo campo e mostrava `[completed]`,
rendendo poco visibile il fallimento. Vibe restava attivo senza nuovi eventi:
non è dimostrata la causa interna dell'attesa (modello, server o sottotask).

Il runner è stato fermato con SIGTERM; è stata confermata l'uscita dei tre PID.
Non è stata avviata da noi una nuova richiesta Mistral. Lo script
[s33_verify_lens_status_api.py](../Python_Trace_Scripts/s33_verify_lens_status_api.py)
è conservato con un avviso iniziale **INCOMPLETO**: nessuna asserzione è stata
corretta o rimossa e nessuna delle sue descrizioni viene promossa a conclusione
verificata. Snapshot prima dell'avviso, errori estratti e hash del log sono
collegati da [osservazione](../Risultati/Vibe_Offline/recovery_observation_latest.json).

## Correzioni nel supervisore

- Il risultato negativo `state.display.success: false` viene mostrato come
  `[failed]` insieme all'ultima riga dell'errore; l'output completo resta nel log.
- Ogni `--heartbeat` secondi (default **30**) viene indicato da quanto manca
  output. Viene aggiornato anche `latest.json`; processo attivo non significa
  progresso verificato dello studio.
- Dopo `--idle-timeout` secondi senza nuovi byte nel log (default **300**) il
  runner invia SIGTERM e, dopo la grazia configurata, SIGKILL. Questo è un limite
  automatico del supervisore e funziona anche con `--quiet`.
- Dopo `idle_timeout` viene salvato `recovery.json` con il percorso del log.
  Il ciclo seguente usa un contesto nuovo, senza riprendere quello silenzioso,
  e richiede di documentare gli incompleti e cambiare domanda se il blocco si ripete.
  Il normale backoff sugli errori resta applicato (30..900 secondi).
- I discendenti vengono tracciati tramite `/proc`, inclusi quelli che creano
  gruppi/sessioni di processo separati, e chiusi prima di procedere al ciclo
  seguente. I PID sono confrontati con il loro starttime per evitare riusi.

Le chiamate Vibe restano seriali. Il limite turni continua invece a riprendere
lo stesso UUID; limite turni e assenza di output sono casi distinti. Il timeout
può interrompere anche un'elaborazione legittima ma silenziosa: è configurabile.
Il tracciamento dei discendenti è periodico e non è un contenitore di processi
del kernel; SIGKILL al runner stesso non permette una pulizia garantita.
Non viene rilevato automaticamente ogni ciclo semantico che continui a emettere
output: per quello restano le istruzioni di checkpoint e limite ai tentativi.

## Verifica

```bash
python3 Python_Trace_Scripts/s33_test_vibe_offline_loop.py
```

**20 test PASS** con CLI simulata. Nuove prove: silenzio, heartbeat, arresto
automatico e recupero con contesto nuovo, errore reale dietro uno stato completed;
le prove STOP/watchdog ora includono un nipote in una sessione separata che ignora
SIGTERM. [Evidenze e hash](../Risultati/Vibe_Offline/test_latest.json).
Nessuna API Mistral o operazione hardware eseguita per i test.

Prossimo passo: riavviare il runner aggiornato per caricare il watchdog;
conservare la catena Status_API come lavoro incompleto e scegliere una domanda
offline diversa o un audit circoscritto delle finestre, senza inseguire PASS.
