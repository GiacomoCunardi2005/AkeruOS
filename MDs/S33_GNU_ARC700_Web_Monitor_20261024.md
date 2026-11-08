# GNU ARC700 — monitor web locale

24 ottobre 2026. Richiesta: osservare graficamente funzionamento, registri e RAM
dell'emulatore GNU usato nel progetto. Implementato in `AkeruOS/tools/arc700_web/`.

Avvio dalla radice: `python AkeruOS/tools/arc700_web/server.py`.
URL: <http://127.0.0.1:8700>. Istruzioni e limiti completi nel README della directory.

## Collegamento e funzionalità

Frontend C esterno collegato alla vera `libsim.a` defined-memoryv2 esistente,
con BFD/opcodes/libiberty. Solo il frontend viene compilato in
`outputs/arc700_web/`; GNU è montatoRO anche durante la compilazione.
Identità input, comando e frontend: `outputs/arc700_web/build.json`.
SessioneCPU separata, nessun collegamento a processi GNU già avviati.

Servizio Python standard library e pagina HTML/CSS/JS senza dipendenze nuove.
Controlli: Passo/blocco, Avvia/Pausa, ricarica del contesto e profiliMain/TBIB
V1.1 verificati. Vista: PC/SP/STATUS32, r0–r60 con alias/filtro/modifiche,
disassemblatoELF, PC campionato, RAMhex/ASCII/mappa/uint32LE, segmenti e logGNU.

Bindloopback, verificaHost/Origin/Sec-Fetch-Site e tokenPOST. Nessuna shell,
upload o scrittura diretta di registri/memoria tramiteweb. LettureRAM256byte
nel banco128MiB, MMIO escluso. La CPU può scrivere nella memoria emulata.
Container runtime con filesystemRO, rete disabilitata, ELF/bridgeRO,
nessun dispositivo Nikon o percorso workspace montatoRW.

## Verifiche

- `outputs/arc700_web/tests.log`: **5test d'integrazione PASS**, vero GNU,
  durata3,767s; nessuna CPUfake. Confronto registri/byte, passo, Main fino al
  fault, TBIB, limitiRAM, inputinvalidi/origini/token/traversal.
- Main ingresso: PC `0x000BB540`, r0=1 dall'ABIGNU. Unpasso:
  PC `0x000BB544`, r0=0. ByteELF/RAM `4a 20 00 00` confrontati.
- Main stop: **579.743chiamate single-step**, PC `0x00169A84`, segnale11,
  read2 MMIO non mappati `0x0FED2018`. Nessun `S33_UNDEFINED`.
  Arresto coerente con i verificatori precedenti.
- TBIB ingresso `0x01000000` e10passi verificati; identità rispetto al corpo
  del firmwareV1.1 originale. Il rifiuto degli inputinvalidi non avanza laCPU.
- `outputs/arc700_web/browser_evidence.json`: **6gruppiUI PASS** con Chromium
  headless già installato, desktop1512×1100/mobile390×844. Controlli,
  filtroregistri, memoria/decoder/limiti, profili, layout. Nessun erroreJS/console
  né overflow orizzontale della pagina; tavolahex scorre dentro il pannello.
- Screenshot `outputs/arc700_web/desktop.png` e `mobile.png`.
- SintassiPython/JS PASS. Hash inputGNU collegati ricontrollati invariati;
  evidenza aggregata `outputs/arc700_web/verified_evidence.json`.

## Limiti e decisioni

Riutilizzata libsim per leggere stato vivo, senza modificare GNU o ricostruire
registri da una traccia. Nessuna modifica a sorgenti/build/installazioni/
copielabGNU, firmware originali o dati Nikon.

PassiGNU conta `sim_resume(step=1)`, inclusa la chiamata del fault, non il
profilerGNU (583.306istruzioni nel precedente runnerMain). Il grafico contiene
80campioni, non tutte le istruzioni. Pausa tra blocchi1000 in corsacontinua.
Il disassemblato è staticoELF e non segue scritturecodiceRAM; `sim_read` restituisce
RAMcorrente ma non espone il bitmapprovenienza. Zero non certifica RAMnota/libera.

RAM128MiB, resetCPU/AUX e halfwordMMIOzero restano ingressi sintetici; DSPv7
provvisorio. L'ingressoMain/TBIB non è un resetfisico completo. Nessun nuovo
modello periferiche, hardware, dumper, USB/NAND/vendor/flash/resetUSB/scritturaSD.
Nessuna prova di geometriaDDR, bootcompleto, foto, persistenza o recupero.
**NON_INSTALLARE** resta invariato.
