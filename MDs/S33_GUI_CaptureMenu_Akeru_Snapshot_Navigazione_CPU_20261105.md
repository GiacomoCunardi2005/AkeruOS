# Snapshot → CaptureMenu → AkeruOS → snapshot, CPU V1.1

Data 2026-11-05. Estensione della prova `S33_GUI_CaptureMenu_Akeru_Apertura_Navigazione_CPU_20261105.md`: dopo l'ingresso in CaptureMenu originale, anche l'evento che apre la pagina AkeruOS e tutti gli eventi di navigazione sono prodotti da snapshot MMIO simulati. Il banco chiama esplicitamente il lettore originale `0x2d62d8`, passa il risultato al callback originale `0x1406d0`, che attraversa `0x16ec38`, `0x16e6e0`, scanner `0x16f86c`, generatore e coda originali. Il banco estrae i record e li consegna al dispatcher originale `0x169e1c`.

L'apertura riusa l'ID 0x3e: la voce della tabella e il record CaptureMenu sono modificati solo nell'immagine emulata, affinché il manager originale selezioni un descrittore AkeruOS sintetico. Callback e stato AkeruOS sono sperimentali. Dopo la pressione `0x2180` il descrittore corrente cambia; il rilascio `0x2181` è generato con il lettore/scanner e consegnato alla nuova pagina. Il verificatore controlla che sia consumato e non crei azioni. Per gli eventi seguenti, controlla snapshot, record di coda, dispatcher, stato del modello compilato per ARC, azione prelevata esplicitamente e stack. Le trace confermano l'esecuzione delle funzioni di lettura, normalizzazione, scansione e modello.

## Risultati: 12/12 PASS

Sei percorsi × UI fixture 0 e 0x23, in processi indipendenti. Le associazioni bit-evento sono ipotesi software, non identità dei tasti fisici. I rilasci corrispondenti sono verificati e non emettono azioni.

| Pressioni successive all'apertura | Risultato del modello |
| --- | --- |
| `580`, `2700`, `700` | esposizione → pagina successiva → richiesta tempo (4) |
| `700`, `2180` | colore → richiesta monocromatico (6) |
| `580`, `580` | esposizione → pagina principale |
| `580`, `700` | esposizione → richiesta ISO (2) |
| `2700` | richiesta impostazioni (7) |
| `2180` | terza voce senza azione, resta pagina principale |

Le richieste sono prelevate dal banco, non eseguite. Il ritorno è tra pagine del modello, non alla live view Nikon. I bit usati sono 12→580, 7→700, 8→2180, 13→2700; per i bit 12 e 13 vengono modificate entrambe le halfword poiché il lettore le combina. Ogni pressione è seguita dal rilascio prima del successivo ingresso.

## Prove

Comando base `python3 Python_Trace_Scripts/s33_verify_snapshot_capture_focus_original_cpu.py --boot-2c --custom-targets --open-targets --akeru-menu`; aggiungere rispettivamente `--akeru-color`, `--akeru-back`, `--akeru-iso`, `--akeru-settings`, `--akeru-empty`, e per la seconda fixture `--ui-mode-23`.

- UI 0, nell'ordine tabella: `Risultati/GUI_S33/snapshot_capture_focus_original_cpu_20261105T110048366365Z`, `...110049145357Z`, `...110049947134Z`, `...110050736220Z`, `...110051539516Z`, `...110114980616Z`.
- UI 0x23: `...110052329715Z`, `...110053111635Z`, `...110053904555Z`, `...110054682912Z`, `...110055514928Z`, `...110115782410Z`.
- Regressioni: destinazione Nikon originale `...110056317396Z` PASS; precedente matrice CaptureMenu 4/4 `...110057058963Z` PASS.

Ogni cartella contiene trace, snapshot del verificatore, codice compilato, fixture e risultati. Per il percorso ritorno si usa `580` due volte, come previsto dal modello; la precedente prova separata aveva utilizzato `480` iniettato nel generatore.

## Limiti

Ingresso MMIO, RAM e descrittore sono sintetici; modo `0x2c`, guardie, servizi, callback lifecycle AkeruOS e prelievo delle azioni sono fixture. L'inizializzazione dello scanner è predisposta, non viene eseguito il task/scheduler della camera. Non sono dimostrati mapping fisico o polarità degli interruttori, pressioni simultanee, rendering, ritorno alla live view, persistenza, controllo otturatore/ISO/colore o hardware. Il DSP emulato è sperimentale; gli indirizzi di laboratorio non provano RAM disponibile. REA aveva rifiutato l'ELF ARC; nessuna modifica dell'emulatore o firmware originale. **NON_INSTALLARE**.
