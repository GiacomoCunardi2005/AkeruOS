# Chi scrive lo stato letto dal confronto HiddenMenu

20 ottobre 2026. Campione Nikon V1.1; indirizzi CPU della mappa candidata. Il confronto legge **r0**, ma r0 viene caricato dal getter a partire dal byte RAM **`0x366880`**. La variabile persistente da seguire è quel byte; gli altri usi temporanei di r0 nel firmware non sono automaticamente modifiche dello stato HiddenMenu.

## Elenco confermato e ruolo di ciascun elemento

| Funzione o punto | Cosa fa | Valore | Certezza e limite |
|---|---|---|---|
| Setter `0x129904` | Esegue `stb_s r0,[r1,0]` a `0x12990E`, con r1=`0x366880` | Byte basso di r0; non c'è un controllo locale che ammetta soltanto1/3 | Scrittore diretto verificato in GNU e ora eseguito nel simulatore |
| Wrapper `0xC5DDC`, chiamata a `0xC5DE8` | Dopo una chiamata a `0x16C6E8`, imposta r0=1 e chiama il setter |1 | Unico chiamante diretto del setter trovato e riancorato nei16payload; non è una prova di assenza di chiamate indirette |
| Chiamata `0xC5BD2` | Chiama il wrapper `0xC5DDC` | Il wrapper sceglie1 | Collegamento GNU fresco; non è un secondo store diretto alla variabile e non attribuisce da solo una fase hardware |
| Byte iniziale nel payload dati1, mappa `0x366880` | Contiene1 nel campione |1 | Dato verificato, non funzione. La copia/caricamento dei dati è un produttore iniziale possibile; non sono risolti qui tutti i loader runtime |

Il setter usa il pool `0x12991C → 0x366880`. Il getter **`0x129920`** legge quel pool e poi il byte: è un lettore. **`cmp_s` a `0x1353F6`** confronta il valore in r0 con l'immediato3 nel campioneCMP3: aggiorna i flag, non scrive la variabile RAM. L'altro campione ha immediato1; i file sono identificati per byte/hash, senza dedurre dai nomi la storia della modifica.

## Scritture aggiunte soltanto nel prototipo di laboratorio

Il [nuovo prototipo CPU](S33_Due_Set_CPU_Prima_Dopo_Confronto.md) aggiunge due chiamate allo stesso setter:

| Indirizzo nel prototipo | Operazione | Dove avviene lo store effettivo |
|---|---|---|
|`0x02000008` |`set(3)`, prima del getter/confronto |Nel setter Nikon a `0x12990E` |
|`0x0200002A` |`set(1)`, dopo il confronto e prima del ramo |Nello stesso setter Nikon a `0x12990E` |

Queste chiamate sono codice sperimentale nuovo, non scrittori presenti originariamente nel firmware Nikon. Nel test non viene più cambiato il byte RAM dal computer fra le due chiamate: vengono eseguite le vere istruzioni del setter. La fixture iniziale rimane naturalmente un input del laboratorio.

## Riferimenti da non confondere con scrittori confermati

- I tre pattern del setter nel payload9 a `0xED4364/0xED4834/0xED48FE` restano candidati di dati; nessuna call diretta è stata trovata lì.
- Il falso branch a `0x129922` è l'interno dell'istruzione reale del getter a `0x129920`; non è una seconda funzione.
- I risultati della scansione lineare nelle zone dati non diventano automaticamente codice eseguibile.
- Indirizzi costruiti con base+offset/GP, alias, puntatori runtime, chiamate indirette e modifiche di altre fasi non sono esclusi da una ricerca di pattern. Non è una lista esaustiva certificata di tutte le possibili scritture fisiche.

## Verifiche effettivamente rieseguite

Il [runner](../S33-sections/safety_audit_codex/verify_setter_calls.py) richiama il [verificatore esistente](../S33-sections/safety_audit_codex/menu_state_dependencies.py):16identità payload,16roundtrip ELF,32finestre GNU e coincidenza esatta con lo sweep precedente. Poi aggiunge4finestre GNU per setter/getter/wrapper/chiamante del wrapper e i test CPU. [GNU fresco](../Ghidra_Results/ghidra_reports/state_setter_calls/gnu_verified.txt), [log sweep](../Ghidra_Results/ghidra_reports/state_setter_calls/writer_sweep_run.log), [manifest](../Ghidra_Results/ghidra_reports/state_setter_calls/verified_evidence.json).

Prossimo per completare l'elenco: risolvere i riferimenti indiretti e seguire le scritture nelle fasi di avvio/task, senza generalizzare da un solo percorso. Firmware e hardware intatti; nessuna prova di recupero o sicurezza flash.
