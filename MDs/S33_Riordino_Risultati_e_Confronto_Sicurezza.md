# Risultati accessibili e confronto delle garanzie

20 ottobre 2026 — R0/R3/R4. [Punto di ingresso](00_INIZIA_QUI.md).

## Organizzazione completata

Tutti i documenti Markdown sono in `MDs/`. L’alias `percorsi_progetti.md` è conservato lì; `AGENTS.md` nella radice è un collegamento, necessario per la scoperta automatica delle istruzioni. I collegamenti verso codice, evidenze e immagini usano la nuova posizione dei documenti.

| Cartella dalla radice | Contenuto |
|---|---|
| `Risultati/Firmware_sperimentali/SD/` | BIN completo con interruttore SD e SHA-256 |
| `Risultati/Disassemblati/` | Due ASM integrali, diff e CSV dei comandi |
| `Risultati/Analisi_storiche/` | 16 vecchi ELF/BIN/ASM trasferiti da work; non nuovi firmware installabili |
| `Risultati/GNU/` | Indice delle prove e 18 varianti esportate: patch e231snapshot di sorgente modificato, con commit e hash |
| `Risultati/Hardware/` | Fotografie originali preservate, trascrizioni e osservazioni dell’utente |
| `outputs/arc700_public_references/` | Quattro PDF ARC prima nella radice, testi e manifest delle fonti |

La prima sistemazione ha trasferito10file dalla radice; la seconda16artefatti dawork. La centralizzazione ha poi spostato291file, inclusi gli export GNU, nelle categorie di `Risultati/`, controllando gli hash prima e dopo. La mappa e gli archivi dei metadati precedenti sono sotto [file_organization](../outputs/file_organization/). La documentazione era già stata spostata dall’utente inMDs quando è stata recepita la nuova regola: sono stati corretti i collegamenti in155documenti, senza ricreare copie nella radice.

Gli strumenti GNU, le sorgenti operative e le build restano nei loro percorsi, in sola lettura. Le modifiche riutilizzabili sono ora esportate fuori da quelle cartelle: tutti i file tracciati modificati e gli untracked non ignorati sono presenti negli snapshot; il commit identifica la base e la patch contiene le differenze tracciate. I sorgenti esportati non sono nuove prove di correttezza dell’emulatore.

Sono aggiornate le destinazioni dei generatori del BIN, dei listati e dei rapporti Markdown. I manifest operativi dei listati hanno percorsi aggiornati e copie dei metadati precedenti. I log e gli snapshot delle vecchie esecuzioni conservano i percorsi originali; le mappe consentono di risolverli.

## Il nuovo BIN è sicuro quanto CMP1?

**Non possiamo assegnare una sicurezza equivalente né una percentuale di rischio.** Entrambi hanno controlli d’integrità coerenti. CMP1 modifica una sola istruzione già esistente, oltre alle somme. Il nuovo candidato introduce220byte di codice, un collegamento di8byte, uso aggiuntivo dello stack e una ricerca SD durante il selettore: aggiunge questioni di collocazione, disponibilità del supporto e comportamento in errore.

La prima risposta, prima dell’installazione, indicava più questioni aperte nel candidato. Successivamente l’utente ha installato proprio questo BIN e fornito foto del menu funzionante: ora il candidato ha una prova d’uso reale circoscritta che i soli confronti statici non offrivano. Il vantaggio è concreto: il caso osservato è arrivato alla GUI. Non prova stabilità generale, tutti gli stati del file SD o recupero dopo un guasto. Il resoconto prima dell’installazione è storico; non va ripetuto come se la macchina non fosse mai partita.

Il file SD può disabilitare la richiesta del menu quando il controllo viene raggiunto. Non disinstalla il codice e non è un sistema di ripristino. L’utente riferisce avvio normale senza SD; resta distinto il caso SD presente senza marcatore. Le foto non dimostrano che l’USB diagnostica sia attiva.

## Controlli e limiti del riordino

Hash dei file trasferiti invariati; contenuto BIN locale sempre `ce504526dcb1ebffab33f17bf1467fd03f70b01c5393ad03812523f978b3e8c9`,29.602.084byte. Le verifiche del contenitore e60scenari sono state rieseguite dopo la prima modifica del percorso di pubblicazione; l’ultima centralizzazione è un trasferimento a byte invariati. Le verifiche GNU storiche non sono state ripetute come conseguenza del riordino e non è stata ricompilata alcuna toolchain.

Prossimo punto utile: osservazione controllata SD inserita senza marcatore, uscita e comportamento normale, poi verifica distinta del recupero. Per USB, il controllo già eseguito inHiddenMenu non rilevava la Nikon; nessuna modalità diagnostica o scrittura USB è stata tentata.

## Verifica finale del riordino

[Controllo del20 ottobre](../outputs/file_organization/20261020T132019Z/validation.json): hash invariati del candidato e dell’originale, dueASM verificati sui rispettivi manifest,18variantiGNU/231snapshot confrontati anche con le sorgenti rimaste inwork,4fotografie preservate, link dei quattro rapporti centrali risolti e10script modificati sintatticamente validi.335vociMarkdown inMDs al controllo; nella radice soltanto il collegamentoAGENTS. Non sono nuove prove di avvio o semanticaCPU.
