# S33 — origine delle celle buffer e area condivisa degli stadi

Analisi statica V1.1, 19 ottobre 2026. Continuazione dei [puntatori dei tre stadi](S33_Puntatori_Tre_Stadi_e_Registri_Buffer.md). Nessun accesso hardware.

## Risultato

Le sei celle lasciate aperte nel rapporto precedente sono campi di **un'unica configurazione a `0x445380`**, costruita da `0x244234`. Derivano da tre basi e due offset nel descrittore di lavoro **`0x4453DC`**. Il task le legge poi per gli stadi `0x800/0x1000`, mentre l'inizializzatore dello stadio `0x2000` copia la stessa configurazione nella propria area persistente.

Il costruttore precedente interroga due regioni consecutive, selettori3/4, per un totale di **`0x4000` byte**. Un'altra banca, `0x392288`, viene invece costruita con un ciclo da quattro terne. Queste due sorgenti di puntatori rimangono distinte.

È quindi dimostrato il riuso software delle basi fra configurazioni dei diversi stadi; direzione dei trasferimenti e durata fisica dei buffer restano aperte. Circa 10% funzionale AkeruOS, invariato.

## 1. Chiamante e identità degli oggetti

Nel tratto di inizializzazione, i riferimenti PCL scalati risolvono:

| Registro del chiamante | Indirizzo | Impiego |
|---|---|---|
| r17 | `0x4452CC` | configurazione formato0x3C dello stadio800 |
| r18 | `0x445308` | configurazione formato0x50 dello stadio1000 |
| r16 | `0x4453DC` | descrittore di lavoro prodotto dal builder |
| r13, nel secondo tratto | `0x445380` | configurazione formato0x4C dello stadio2000 |

A `0x15F024`, il chiamante invoca `0x243F48`, passando il descrittore in r7 nel delay slot. In un ramo successivo, dopo il controllo dei ritorni e con C+`0x90`=0, a `0x15F082` chiama `0x244234` con questi argomenti:

```text
r0 = 0x445380     configurazione da costruire
r1 = 0x4453DC     descrittore di lavoro
r2 = 0x4452CC     configurazione800
r3 = 0x445308     configurazione1000
r4 = byte C+0xA8
r5 = halfword C+0x9E, nel delay slot
```

Se il ritorno è ammesso, `0x15F08E` passa `0x445380` a `0x24A488`, che la copia a `0x50C1F8` come già verificato. I puntatori dei record runtime provengono quindi da una configurazione preparata durante l'inizializzazione, non da valori immediati nei setter MMIO.

## 2. Formule delle sei celle

Sia W=`0x4453DC`, con:

```text
P0 = parola[W+0x10]
P1 = parola[W+0x14]
P2 = parola[W+0x18]
D0 = parola[W+0x08]
D1 = parola[W+0x0C]
```

Il builder scrive, con aritmetica32bit:

| Cella | Campo configurazione | Valore | Uso runtime successivo già risolto |
|---|---|---|---|
| `0x445380` | +0 | P0 | stadio800 +8 |
| `0x445384` | +4 | P0+D0 | stadio800 +C |
| `0x445394` | +14 | P1 | stadio1000 +8 |
| `0x445398` | +18 | P1+D1 | stadio1000 +C |
| `0x4453A8` | +28 | P2 | stadio1000 +10 |
| `0x4453AC` | +2C | P2+D1 | stadio1000 +14 |

Gli offset sono esadecimali. L'uso runtime indicato è quello del ramo C+`0x90`=0 seguito nel rapporto precedente, sotto le sue ulteriori guardie.

Per la prima coppia esistono due rami che sommano gli addendi in ordine opposto; producono lo stesso risultato modulo2^32. Le altre quattro celle sono costruite da due sequenze rettilinee. Un interprete limitato a queste istruzioni confronta **2.048 casi** fra entrambi i rami locali. Non esegue le parti geometriche del costruttore o l'hardware.

Le quantità D0/D1 sono qui chiamate offset: il loro significato di riga, piano o componente non viene dedotto dalla sola addizione.

## 3. Origine delle tre basi nel descrittore

`0x243F48` prepara il descrittore W durante la suddivisione dell'area di lavoro. Nel ramo formato0x3C seguito:

- il cursore r18 parte dalla regione ottenuta con selettore3;
- il codice riserva una quantità allineata8 e scrive il cursore risultante a W+`0x10` (`0x244074`);
- dopo altre quantità calcolate dai servizi inferiori, scrive W+`0x14` e W+`0x18` a `0x2440EC/F0`;
- i valori restituiti da tali servizi vengono conservati anche nei campi W+8/W+C usati nelle formule sopra.

Il ramo alternativo formato0x50 ha propri store a W+`0x10/14/18` nel tratto `0x2441EE..20E`. È un'altra costruzione ammessa, non un secondo insieme di costanti fisse.

I valori numerici finali delle tre basi dipendono dalle dimensioni e dalle scelte del builder. Non vengono inventati a partire dal solo inizio della regione.

## 4. Due regioni consecutive per il workspace

Il builder chiama `0x1774C8` prima con selettore3 e poi4, chiedendo base e lunghezza attraverso puntatori stack. La tabella di salto, letta come byte con segno e passo2, risolve:

| Selettore | Caso | Base restituita | Lunghezza |
|---|---|---|---|
| 3 | `0x17750C` | `0x2696F4(1) + 8*1584` = `0x0F79B180` | `0x1000` |
| 4 | `0x17751E` | `0x2696F4(1) + 0x4180` = `0x0F79C180` | `0x3000` |

Il getter `0x2696F4(1)` restituisce dal pool **`0x0F798000`**, nel delay slot del ritorno. Questi sono indirizzi della mappa software statica; non identificano da soli il tipo o la capacità della memoria fisica.

I due intervalli sono consecutivi:

```text
[0x0F79B180, 0x0F79C180)  0x1000 byte
[0x0F79C180, 0x0F79F180)  0x3000 byte
unione: 0x4000 byte
```

Il builder somma le due lunghezze a `0x243FD0/FD2`. A `0x244216..21E` confronta lo spazio consumato rispetto alla base con la capienza combinata; il ramo successivo può ridurre un parametro e ripetere la costruzione. La verifica qui non dimostra tutti i casi del ciclo di retry, gli overflow delle quantità o la proprietà esclusiva della regione. Gli store ai descrittori precedono il controllo finale.

## 5. Campi runtime+4 inizialmente non usati

I default osservati nei builder scrivono **configurazione+4=0** sia per il formato0x3C (`0x243FE8/FEA`) sia per il formato0x50 (`0x244080/082`). I servizi di avvio programmano i registri del campo runtime+4 soltanto se il corrispondente campo persistente di configurazione vale1.

Quindi il percorso inizializzato con questi default non richiede che quel campo runtime sia una nuova sorgente attiva. Questo riduce il punto aperto del rapporto precedente, senza escludere modifiche successive o altre modalità che impostino configurazione+4=1.

## 6. Banca a quattro terne distinta dal workspace

Il produttore della banca `0x392288`, già letta dal task, è il ciclo `0x15EAF4..EB48`: inizializza il contatore a4, salva tre puntatori per iterazione e avanza la destinazione di12 byte. I cursori sono aggiornati con allineamento8 e quantità derivate dai campi dell'input.

Un controllo successivo, `0x15EB84..9C`, confronta la differenza tra cursore finale e base iniziale con input+8. La presenza di questo confronto è provata; la sicurezza di ogni calcolo e l'intera catena di provenienza della memoria restano da verificare. Il task legge un indice byte: il ciclo di costruzione da4 elementi non basta a provare che tutti i consumatori restino sempre in0..3.

## Evidenze e prossimo passo

[Script](../Python_Trace_Scripts/s33_trace_stage_pointer_origins.py), [JSON](../Ghidra_Results/ghidra_reports/stage_pointer_origins/verified_evidence.json), [GNU](../Ghidra_Results/ghidra_reports/stage_pointer_origins/gnu_verified.txt).

Riproduzione: `python3 Python_Trace_Scripts/s33_trace_stage_pointer_origins.py`.

Verificati **16 hash, roundtrip ELF del blocco00, 19 finestre, 5 collegamenti diretti, 54 istruzioni chiave, 7 pool, due casi della tabella di salto e 2.048 costruzioni dei puntatori**. Le finestre e il modello coprono i tratti descritti, non il costruttore completo.

Prossimo: ricostruire i calcoli delle quantità e dei retry nel builder, verificare i limiti dell'indice della banca e collegare le basi condivise ai ruoli dei registri dei tre stadi. Direzione dei dati e ultimo accesso fisico restano aperti.

## Continuazione — layout e retry locale risolti

Il [rapporto sul dimensionamento](S33_Dimensionamento_e_Retry_Workspace.md) risolve i due layout, il contatore3→2→1 inizializzato nel delay slot e il salto del confronto capienza solo per argomento stack=1 (C+90 nel task). Nel ramo alternativo P0=P1. Restano da completare la geometria dei servizi inferiori, i limiti globali dell’indice e il protocollo fisico dei buffer.
