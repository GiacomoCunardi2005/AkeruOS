# Tasti logici, coda e quattro slot — prova CPU, 28 ottobre 2026

Otto casi GNU ARC700 collegano la scrittura originale di uno stato di tasto logico `0x16F72C`, la generazione dell'evento `0x16F6B0`, l'inserimento nella coda originale `0x17BC7C`, l'estrazione originale `0x17BD4C` e il dispatcher originale di classe `0x15` `0x631610`. Il banco consegna esplicitamente l'evento estratto al controllo sintetico: non esegue lo scheduler né il routing del WindowManager.

| Tasto logico iniettato | Stato 1: evento estratto | Stato 0: evento estratto | Slot selezionato | Destinazione registrata dalla fixture |
|---:|---:|---:|---:|---|
| 11 | `0x0580` | `0x0581` | 0 | ISO `0x3F` oppure tempo `0x3E`, secondo la variante |
| 14 | `0x0700` | `0x0701` | 1 | menu colore originale `0xBB` |
| 67 | `0x2180` | `0x2181` | 2 | nessuna richiesta, destinazione sintetica zero |
| 78 | `0x2700` | `0x2701` | 3 | impostazioni `0xB7`, argomento 1 |

L'evento di stato 1 è passato al dispatcher e verifica selezione, richieste di apertura e stack; l'evento di stato 0 viene solo estratto e verificato, non inoltrato al menu. Stato 1 e 0 sono valori logici, non una polarità fisica verificata. Gli indirizzi di destinazione si trovano nei record sintetici del banco: ISO e tempo sono varianti alternative, non un sottomenu completo; il menu colore originale non è Mono RAW Luminance. La destinazione zero non dimostra la disabilitazione del tasto nel sistema reale.

La lista sintetica deriva da `CaptureMenu 0x4801` con pagina zero e guardie permissive; contesto di coda, hook e gate sono impostati dal banco. Lock, notifica, filtro tasti, selezione, attributi e apertura sono fixture; la lista completa è in `fixture_patches.json`. Il simulatore DSP v7 è sperimentale. Le finestre originali sono confrontate con il dump; i due record di coda per caso, l'evento, la selezione e le richieste sono verificati con assert, con trace dei percorsi originali. [Script](../Python_Trace_Scripts/s33_verify_gui_key_queue_four_routes_cpu.py), [risultati](../Risultati/GUI_S33/key_queue_four_routes_cpu_20261028T092449Z/).

Non sono stati eseguiti acquisizione degli ingressi MMIO, scheduler, routing reale dalla coda, rendering, apertura effettiva, sensore o persistenza. L'associazione dei tasti logici ai quattro interruttori fisici e il loro ordine restano non verificati; nessun accesso alla fotocamera. **NON_INSTALLARE**.

Una [prova successiva con dispatcher del manager](S33_GUI_Dispatch_Coda_Ricaduta_CaptureMenu_CPU_20261028.md) mostra che, in condizioni sintetiche specifiche, lo slot 2 con destinazione zero lascia propagare `0x2180` al menu padre, che richiede `0x87`.
