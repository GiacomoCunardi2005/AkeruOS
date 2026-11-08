# S33 — protocollo interno Recorder Still

Analisi statica del 17 ottobre 2026. La fotocamera non deve essere collegata per riprodurre questa analisi. Non è stata prodotta un'immagine installabile.

## Risultato

È stato individuato un produttore condizionale di un segnale consumato dal task denominato `Recorder Still Task`. È un punto utile per ricostruire il servizio originale da riutilizzare nell'applicazione essenziale. Non dimostra ancora come richiedere una fotografia dal nuovo programma: potrebbe partecipare anche alla gestione dei buffer dell'anteprima.

| Elemento | Evidenza statica |
|---|---|
| Worker | Entry `0x12e720`, già associata al nome dalla tabella dei task |
| Oggetto evento | Identificatore `0x40100003`; non va confuso con gli ID dei task |
| Contesto | Indirizzo `0x366920` |
| Produttore | Funzione `0x130a94`: scrive il byte del primo argomento in `0x3669ba` (contesto + `0x9a`) e, se il byte in `0x3669a2` vale 1, imposta il bit `0x200` |
| Consumatore | Attende attraverso `0x158d04` con maschera `0x200`, cancella `0x200` e `0x400`, imposta `0x4000`, elabora dati e reimposta `0x400` |
| Buffer | Il worker usa il byte a contesto + `0x9a` come indice in descrittori da 12 byte, attraverso il puntatore a contesto + `0x94` |
| Callback | Il worker può invocare puntatori a contesto + `0xa4` e `0xa8` |

Il bit `0x400` è un candidato marcatore di disponibilità/fine iterazione del worker. **Non equivale a “JPEG salvato sulla SD”.** L'ABI completa, il legame col pulsante e la persistenza del file restano da ricostruire.

## Verifiche

`0x158cbc` conduce alla primitiva `0x23c758`: l'OR sui bit dell'evento e il successivo store supportano l'interpretazione “imposta bit”. `0x158ce0` conduce a `0x23c8ac`: BIC e store supportano “cancella bit”. La semantica completa degli argomenti di attesa di `0x158d04` non è stata stabilita.

Il carico `ld.as` a `0x130ab4` usa uno spostamento scalato: `(PC & ~3) - 87*4 = 0x130958`, dove il campione contiene `0x40100003`. Il commento di objdump mostra invece l'indirizzo non scalato: non usarlo come riferimento dati. La scalatura per dati a 32 bit è descritta nella [documentazione Synopsys della toolchain ARC](https://foss-for-synopsys-dwc-arc-processors.github.io/toolchain/gcc/small-data.html).

Il controllo tramite REA ha verificato SHA-256 del blocco originale, uguaglianza byte per byte della sezione ELF con il blocco e cinque valori letterali. Le cinque finestre disassemblate non presentano troncamenti di istruzioni al limite superiore. Questo verifica la riproducibilità dell'analisi, non l'esecuzione sulla macchina.

- [Disassemblaggio mirato](../outputs/s33_capture_protocol_disassembly.txt)
- [Valori e intervalli verificati](../outputs/s33_capture_protocol.json)
- [Evidenza REA](../outputs/s33_rea_capture_evidence.json), record `ev_223553722e0459eecb522b1e2d961b26181004b9cd59dae648cc3808e143ffd3`; include il comando Python riproducibile.

## Prossimo passo

La [continuazione sul servizio JPEG](S33_JPEG_Richiesta_e_Risultato.md) ha identificato il punto che registra `0x130a94` e lo scambio separato di parametri ed esito del task JPEG. Resta da risolvere chi invoca la callback e seguire la richiesta di scatto fino a codifica JPEG e chiusura del file. Solo dopo aver definito avvio, ABI e recupero sarà sensato costruire e provare una modifica. Velocità e consumi non sono stati misurati; installare ora un firmware sperimentale potrebbe rendere la fotocamera inutilizzabile.
