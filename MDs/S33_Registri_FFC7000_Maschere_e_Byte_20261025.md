# Nikon S33: maschere condizionali e campi byte FFC7000

25 ottobre 2026. Mappa fisica incompleta; obiettivo attivo. GNU e firmware
originali invariati; nessun accesso hardware. NON_INSTALLARE invariato.

L’atlante raggiunge **1.024 voci: 64 posizioni core,197 indici AUX,763 indirizzi
MMIO singoli**, con13nuovi indirizzi di questo passo. Le posizioni core
comprendono encoding speciali/opzionali/riservati, non altrettanti registri
fisici provati. Le22finestre conservano3.118appartenenze di cella e3.086indirizzi
distinti,32ripetizioni eFF74088anche scalare. Le celle restano separate dai
registri indipendenti. Due famiglie MMIO indicizzate mantengono domini dei
chiamanti irrisolti. Nessuna percentuale globale fisica è dimostrata.

## Prove con il codice originale

Run valido: `outputs/gnu_arc700/20261025T160309Z_4b54e74f/verified_evidence.json`,
PASS_FFC7000_CONDITIONAL_AND_BYTE_CONTROLS. Tredici entry originali,otto scenari,
16run,29chiamate per run:232chiamate osservate,464incluse le ripetizioni.
Completati **504accessi halfword:280letture e224scritture**. Tutte le otto coppie
di tracce osservatore spento/acceso sono identiche byte per byte. Ogni chiamata
conserva SP e le sentinelle r13..r19; i getter sono controllati sul ritorno r0.

I valori principali sono0,1,7F,80,FF,100,80000080,FFFFFFFF. I flag delle maschere
sono0,1,2,FFFFFFFF; i secondi argomenti e i byte superiori usano rotazioni dei
valori principali. Seed MMIO0000,FFFF,A55A,5AA5,FF00,00FF,8080,7F7F.
Originale Main e frontend osservatore restano invariati.

L’audit indipendente ricostruisce maschere, rami e packing dagli argomenti,
byte originali e fixture iniziali. Controlla89istruzioni riallineate, literal
pool, tuple PC/indirizzo/operazione/valore, larghezza2byte, ordine dei singoli
accessi, coppie begin/result dell’osservatore, backing finale e padding A5.
Esito PASS_FFC7000_CONTROLS_INDEPENDENT_AUDIT.

## Due polarità opposte per le maschere

| Indirizzo | Entry | Primo argomento==1 | Altri valori |
|---|---|---|---|
| `FFC7060` | `3087BC` | Cancella la maschera del secondo argomento | Imposta la maschera |
| `FFC7084` | `3088D0` | Imposta la maschera del secondo argomento | Cancella la maschera |

In ogni caso il risultato è troncato alla halfword e gli altri bit sono
conservati nel backing. Non si può applicare una sola convenzione al flag
per entrambi i wrapper. Non sono dimostrati W1C,acknowledgment o permessi fisici.

`308820` aggiorna bit0 diFFC7064 e `308854` bit1 diFFC7068: impostano solo con
argomento1, cancellano altrimenti. `308888` imposta sempre bit0 diFFC7068,
ignorando l’argomento.

## Getter e store a larghezze software diverse

`3087F0` leggeFFC706C, `308808` leggeFFC7074 e `30890C` leggeFFC7084: restituiscono
l’intera halfword nel modello. `3088A4` leggeFFC7080 e restituisce solo low5
(valore&1F). Il setter `3088BC` scrive invece tutti i16bit bassi dell’argomento
suFFC7080. La maschera del getter non prova una larghezza hardware di5bit.
Letture e scritture sono eseguite su fixture, senza prova di readback periferico.

## Aggiornamenti in due fasi e destinazioni differenti

`308920` aggiornaFFC7088 eFFC708C; `3089A0` aggiornaFFC7090 eFFC7094. Per ogni
cella esegue questa sequenza:

1. legge la halfword;
2. scrive (vecchio&FF00)|(argomento_basso&FF);
3. rilegge la halfword aggiornata;
4. scrive (riletto&00FF)|((argomento_alto&FF)<<8).

Le prime due celle usano rispettivamente r0/r1 e r2/r3; la seconda routine ha
lo stesso schema sulle altre due destinazioni. Tutte le scritture intermedie
restano nelle prove. Non è una singola scrittura atomica del valore composto.
Per esempio, nel run con seed5AA5 e lowbyte80 la prima uscita è5A80; il valore
altoFF dell’argomento successivo produce poiFF80.

`308A20` aggiorna invece due destinazioni differenti: inserisce low8 di r0
inFFC7098 preservandone high8, poi inserisce low8 di r1 come high8 diFFC709C,
preservandone low8. Non combina i due argomenti nella stessa cella.

## Correzione dell’ipotesi EXTB e tentativo fallito conservato

Il primo verificatore assumeva erroneamente un’estensione con segno del byte.
La prova `outputs/gnu_arc700/20261025T155940Z_9e4cf536/verified_evidence.json`
si è fermataFAIL al confronto delle scritture osservate. La traccia mostra,
per esempio, EXTB con input80 che produce80 e nonFFFFFF80.
La definizione GNU locale `ARCompact.cpu`, nella copia del simulatore usato,
definisce EXTB come `(zext SI (cast QI C))`: estensione con zeri.

L’oracolo è stato corretto con questa semantica e le esecuzioni sono ripartite
in una nuova directory. Il codice Nikon e il simulatore non sono modificati.
L’audit controlla20prime scritture con bit7 del byte d’ingresso impostato:
tutte conservano il precedente high8; sedici sono seguite da una distinta
scrittura del nuovo high8 nella stessa cella.

Nell’atlante sono conservati manifestFAIL,copia del primo verificatore e
traccia iniziale, insieme a `evidence/ffc7000_controls_oracle_correction.json`
e all’estratto della definizione GNU `evidence/ffc7000_extb_definition.txt`.
Il primo manifest,interrotto prima di finish,non contiene il ledger completo
degli input: gli hash delle sue copie sono misurati durante l’archiviazione.
Per le ammissioni si usa esclusivamente il successivo run valido con audit.
Gli hash firmware e simulatore nei due manifest coincidono.

## Atlante e limiti

Risultato: `Risultati/Processor_Registers/20261025T160624Z/REGISTER_MAP.md`,
con JSON,CSV,grafo, `atlas_validation.json` e ledger SHA-256 di **255file**.
Parent `20261025T155444Z`,244file,verificato e immutato. Tutte le chiavi dei
**30atlanti precedenti validati** sono conservate. Nessun nuovo indirizzo
coincide con celle delle finestre. Manifest finestre,sovrapposizioni e tracce
AUX sono byte-identici al parent:22indici AUX e146siti run/PC invariati.
Non sono presenti nuovi SR nelle tracce selezionate.

Prove principali: `evidence/ffc7000_controls.json`,
`evidence/ffc7000_controls_audit.json`, `evidence/ffc7000_controls_linear_navigation.txt`.
Il listing lineare è solo navigazione; i PC effettivi sono riallineati nell’audit.
Script: `Python_Trace_Scripts/s33_verify_ffc7000_controls.py`,
`s33_audit_ffc7000_controls.py`, `s33_integrate_ffc7000_controls.py`.

Firmware SHA-256:
`1d34e990a8f99019ffa53ca5de785399df863e942739a667ceb314ec6ce62a39`;
Main SHA-256:
`06754a1f451f17b3047fe03cdb83fd08af11dac725638818254ef0de26a5ed29`.

Stack,seed e backing sono fixture,non reset o RAM fisica libera. Le riletture
vedono il backing sintetico aggiornato; questo non prova coerenza o sequenze
periferiche reali. Restano ignoti funzione,permessi,side effect,IRQ,tempi e
domini dei chiamanti Nikon. Nessun flash,dumper,NAND/vendor,resetUSB o scritturaSD.
Restano aperti i successivi accessor dal buffer writer308A74,altri gruppi MMIO,
AUX parametrizzati,candidati codice/dati,BCR e implementazione reale del SoC.
La matematica dell’helper303A40 nel modello DSP provvisorio resta non verificata
indipendentemente. La mappa fisica completa non è ancora dimostrata.
