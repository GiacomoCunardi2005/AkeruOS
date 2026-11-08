# Nikon S33: FFC3000 e provenienza delle uscite FFB

25 ottobre 2026. Mappa fisica incompleta; obiettivo attivo. Nessun accesso
hardware, nessuna modifica a GNU o firmware originali. NON_INSTALLARE.

Il nuovo atlante contiene **966 voci: 64 posizioni core, 197 indici AUX,
705 indirizzi MMIO singoli**. Sono aggiunti 35 indirizzi singoli e una finestra
di 38 uscite, separata dai registri indipendenti. Le 22 finestre hanno
3.118 appartenenze di cella e 3.086 indirizzi distinti; rimangono le 32
ripetizioni tra finestre e la sovrapposizione del parametro FF74088. Due
famiglie MMIO indicizzate restano formule con dominio dei chiamanti irrisolto.
Le posizioni core comprendono encoding opzionali/riservati e non provano
altrettanti registri fisici. Il totale fisico resta sconosciuto.

## Prove riutilizzate e nuovamente controllate

Queste esecuzioni CPU erano già conservate durante una precedente sospensione:
`outputs/gnu_arc700/20261025T131136Z_9412fb7f/verified_evidence.json`.
Sono state riutilizzate, senza rilanciare l’emulatore. Checksum di tutti gli
input e file conservati verificati; audit indipendente rieseguito con esito
`PASS_FFC3000_FFB_COMPUTED_AUDIT`.

Le prove coprono 24 entry originali, 12 scenari/24 run e 1.288 accessi halfword:
FFC 464 letture e 616 scritture; FFB 16 letture e 192 scritture.
Tutte le 12 coppie di tracce osservatore spento/acceso sono identiche.
L’osservatore esterno, il simulatore e il Main originale sono quelli legati
ai rispettivi hash nel manifest; non sono ricompilati per questa integrazione.

L’audit verifica byte delle istruzioni, literal pool, formule dei controlli,
ordine degli accessi, larghezza halfword, backing finale e input conservati.
Per le uscite calcolate verifica una provenienza eseguita; non pretende una
validazione matematica indipendente della funzione.

## Ventotto indirizzi FFC

| Indirizzo o gruppo | Contratto software osservato |
|---|---|
| `FFC3000` | bit5 set solo con argomento0; bit0/1/8/9 set solo con1; bit3/4 set con qualunque nonzero. RMW conserva gli altri bit |
| `FFC3130` | RMW bit0: set solo con1, altrimenti clear |
| `FFC3008` | Lettura full16, store low16 dell’argomento, rilettura nel backing sintetico |
| `FFC300C` | Secondo argomento come maschera: set quando primo argomento==1, altrimenti clear; getter full16 |
| `FFC3044/48`, `3070/74`, `30C0/C4`, `30DC/E0`, `3100/04`, `311C/20` | Sei coppie: prima low16 poi high16 di un argomento32 |
| `FFC3078/7C/80/84`, `30C8/CC/D0/D4`, `3108/0C/10/14` | Tre quartetti: low16/high16 del primo argomento, poi low16/high16 del secondo |

Valori di test per i controlli comprendono 0, 1, 2, 3, 80000000 e FFFFFFFF;
le maschere e i valori delle coppie includono anche 12345678 e A55A5AA5.
Ordine software e readback di fixture non provano atomicità, reset, W1C,
latch, permessi o funzionamento della periferica reale.

## Sette indirizzi FFB e una finestra di 38 uscite

`2E2918` distribuisce tre argomenti32 in sei scritture halfword agli indirizzi
`FFB9F10/14/18/1C/20/24`: per ciascun argomento scrive prima low16, poi high16.
`2E2C8C` aggiorna bit0 di `FFB9FC4`, impostandolo con qualunque argomento
nonzero e cancellandolo con zero. Questi sette indirizzi sono ammessi come
voci singole, con funzione fisica sconosciuta.

`2E29B4` legge 21 byte d’ingresso: sei halfword e nove byte. Esegue l’helper
originale `303A40` e copia 38 halfword dal record locale agli indirizzi
`FFB9F2C..FFB9FC0`, passo quattro. Sono 38 destinazioni letterali in una copia
srotolata, rappresentate come una finestra di uscita, senza promuoverle a 38
registri di controllo indipendenti. Per ogni uscita l’atlante conserva store
MMIO, load dallo stack, offset nel record e istruzione produttrice dell’helper.

Le quattro combinazioni d’ingresso conservate completano il percorso:
helper originale → record locale → load dallo stack → store MMIO.
Sono 152 scritture di finestra, mentre gli altri accessi sono 1.136.
**La matematica delle 38 uscite non è stata verificata indipendentemente.**
L’helper esegue nel modello GNU DSP provvisorio: l’accordo fra valori tracciati,
input e backing prova questa provenienza eseguita, non l’esattezza numerica
rispetto al silicio Nikon. Non sono assegnati nomi periferici o significati
fisici ai risultati.

Il sito SR `303ADE` scrive operando0 su AUX65/0x41, denominato AUX_MACMODE
nella toolchain. È presente in quattro run osservati con input diversi:
quattro nuovi siti run/PC, un unico PC nuovo. La copertura AUX diventa
**146 siti run/PC, 22 indici distinti**. L’operando SR non è lo stato fisico
successivo al setter e non prova il comportamento matematico dell’estensione.

## Atlante e conservazione della copertura

Risultato: `Risultati/Processor_Registers/20261025T153744Z/REGISTER_MAP.md`,
con JSON, CSV, grafo e `atlas_validation.json`. Il ledger SHA-256 contiene
**232 file**. Parent `20261025T153232Z` da 931 voci e 226 file immutato.
`coverage_lineage_audit.json` verifica che nessuna chiave dei 27 atlanti
precedenti validati venga omessa. Sovrapposizioni software e contratti dei
rami riconciliati sono conservati.

Copie delle prove: `evidence/ffc3000_ffb_computed.json`,
`evidence/ffc3000_ffb_computed_audit.json` e
`evidence/ffc3000_ffb_computed_disassembly.txt`. Quest’ultimo è navigazione
lineare e può disallinearsi sui pool; i byte/PC effettivi sono verificati
nell’audit. Script: `Python_Trace_Scripts/s33_verify_ffc3000_ffb_computed.py`,
`s33_audit_ffc3000_ffb_computed.py`, `s33_integrate_ffc3000_ffb_computed.py`.

Firmware SHA-256:
`1d34e990a8f99019ffa53ca5de785399df863e942739a667ceb314ec6ce62a39`;
Main SHA-256:
`06754a1f451f17b3047fe03cdb83fd08af11dac725638818254ef0de26a5ed29`.
Input RAM700000, stack, MMIO iniziali e backing sono fixture, non reset o
RAM fisica libera. Nessun flash, dumper, NAND/vendor, resetUSB o scritturaSD.

Restano aperti i controlli FF7 residui, gli altri gruppi MMIO e i domini dei
chiamanti runtime/calcolati, i candidati AUX codice/dati e BCR/configurazione
reale del SoC. Per l’helper303A40 servono una validazione numerica indipendente
e prove delle istruzioni DSP prima di sostenere equivalenza matematica o
funzionamento hardware. Nessuna percentuale globale viene dedotta.
