# Nikon S33: riconciliazione degli atlanti e restanti writer FF7 raw

25 ottobre 2026. Mappa fisica incompleta; obiettivo attivo. Nessun hardware,
nessuna modifica a GNU o firmware originali, stato NON_INSTALLARE invariato.

Il nuovo atlante contiene **931 voci: 64 posizioni core, 197 indici AUX,
670 indirizzi MMIO singoli**. Le posizioni core comprendono encoding opzionali,
riservati e speciali e non provano altrettanti registri fisici. Le 21 finestre
di trasferimento hanno **3.080 appartenenze di cella e 3.048 indirizzi distinti**.
Le 32 appartenenze ripetute tra finestre e il parametro FF74088 condiviso con
una finestra sono espliciti; le celle non sono nuove ammissioni a registri.
Due famiglie MMIO indicizzate conservano domini dei chiamanti irrisolti.

## Correzione del checkpoint precedente

L’atlante `20261025T152133Z` da 800 voci descriveva un ramo incompleto rispetto
alle prove già conservate. Il ramo `20261025T130721Z` da 892 voci comprendeva
129 indirizzi assenti dal checkpoint recente; quest’ultimo aveva invece
37 indirizzi FF7 iniziali assenti dal ramo più vecchio. Entrambi i ledger sono
integri: rispettivamente 183 e 196 file. L’unione verificata è di **929 voci**,
non la somma dei due cataloghi. Undici indirizzi comuni hanno documentazione
aggiuntiva conservata, senza sovrascrivere i contratti precedenti.

È un errore di selezione della linea di lavoro: un timestamp più recente non
garantisce maggiore copertura. I dati già verificati non erano stati cancellati.
Il nuovo integratore `Python_Trace_Scripts/s33_merge_register_atlas_branches.py`
riunisce record, fonti, contratti e tracce. Il controllo di copertura richiede
che nessuna chiave degli atlanti storici validati manchi nel risultato.
Le descrizioni fisiche sconosciute restano sconosciute.

Atlante di riconciliazione: `Risultati/Processor_Registers/20261025T153002Z/`,
929 voci, 18 finestre, 136 siti AUX run/PC, ledger di 220 file.
`coverage_lineage_audit.json` conserva il confronto con i 25 atlanti storici
validati, alias documentali delle finestre e sorgenti dei due rami.

I nomi differenti delle stesse finestre sono unificati soltanto per geometria
software: base, conteggio, stride e larghezza della scrittura. Nomi alternativi,
varianti e prove restano conservati. Ciò non dimostra un’identità periferica.
I 18 riferimenti a versioni precedenti di due sorgenti dell’osservatore sono
risolti contro copie conservate aventi esattamente lo SHA-256 richiesto;
nessuna sorgente corrente è riscritta per far corrispondere una vecchia prova.

## Riutilizzo delle prove esistenti

Quattro entry del censimento statico precedente (`2E0F30`, `2E0F70`, `2E0FB0`,
`2E0FF0`) disponevano già di prove CPU nel ramo recuperato. Non erano quattro
nuove lacune sperimentali. La prova e l’audit `ff7_raw_ffb_pairs.json` e
`ff7_raw_ffb_pairs_audit.json` sono riutilizzati con i loro limiti originali.

In particolare, raw33 da FF74044 attraversa 17 celle della prima finestra packed,
15 della successiva e l’indirizzo scalare FF74088. Le relazioni esplicite nel
JSON e nel grafo sono uguaglianze di indirizzi software; nessun alias fisico,
configurazione simultanea o nome di periferica viene dedotto.

Il precedente censimento statico resta una prova statica valida delle sette
routine selezionate; la sua assenza di tracce proprie non deve essere letta
come assenza di qualsiasi prova CPU nel progetto.

## Nuove esecuzioni delle tre routine rimanenti

| Entry originale | Base uscita | Celle | Parametri dopo la copia |
|---|---|---:|---|
| `2E10F0` | `FF760D0` | 9 | `FF760F4`=low16(r1), poi `FF760F8`=low16(r2) |
| `2E1298` | `FF76128` | 33 | Nessuno |
| `2E12D8` | `FF761AC` | 17 | Nessuno |

Tutte copiano halfword complete: passo input due byte, output quattro byte,
scrittura effettiva 16 bit. LP_START/LP_END e conteggi sono verificati sui byte
originali. Il writer raw9 scrive sempre i due parametri dopo le nove celle;
gli argomenti r1/r2 non sono flag di skip. Le altre due routine lasciano in r0
l’ultimo indirizzo scritto; raw9 lascia l’argomento r2. Sono risultati software
osservati nei chiamanti sintetici, senza attribuzione a un’API hardware.

Ogni routine è provata con quattro input: tutti zero, tutti FFFF, sequenza
variabile e suo complemento. **12 scenari / 24 run, 244 scritture completate**:
236 nelle finestre e otto nei parametri. Tutte le 12 coppie di tracce con
osservatore spento/acceso sono identiche byte per byte. Nessun fault o accesso
indefinito. SP e sentinelle r13..r16 sono conservati dopo ogni chiamata.

L’audit indipendente ricostruisce gli output dai byte d’ingresso e gli argomenti,
controlla l’ordine di tutte le scritture, larghezza halfword, byte delle istruzioni
e literal pool, backing finale e gap/guardie A5. Non usa la sequenza attesa del
verificatore come proprio oracolo. Il firmware originale è mappato invariato.

Fonte CPU: `outputs/gnu_arc700/20261025T153050Z_8e8899f3/verified_evidence.json`.
Copie nell’atlante finale: `evidence/ff7_remaining_raw_writers.json`,
`evidence/ff7_remaining_raw_writers_audit.json`, disassemblato e tre script.
Gli script correnti sono `Python_Trace_Scripts/s33_verify_ff7_remaining_raw_writers.py`,
`s33_audit_ff7_remaining_raw_writers.py` e
`s33_integrate_ff7_remaining_raw_writers.py`.

## Atlante finale e controlli di conservazione

`Risultati/Processor_Registers/20261025T153232Z/REGISTER_MAP.md`, con JSON,
CSV, grafo, `atlas_validation.json`, `coverage_lineage_audit.json` e ledger
SHA-256 di **226 file**. Due nuovi parametri portano 929 a 931 voci;
le 59 nuove celle restano finestre separate. Sono verificati **142 siti AUX
run/PC su 22 indici**, inclusi sei nuovi siti SR LP_START/LP_END. L’operando SR
non prova lo stato del registro dopo il setter o la presenza sul silicio Nikon.

Il controllo finale conserva tutte le chiavi dei **26 atlanti precedenti
validati**, inclusi entrambi i rami. I parent e i loro ledger restano immutati.
I registri fisici verificati sull’hardware rimangono zero: il totale fisico
sconosciuto impedisce una percentuale globale attendibile.

Input RAM `0x700000`, stack, backing e valori iniziali/guardie sono fixture del
modello, non RAM fisica libera o valori di reset. Originale firmware SHA-256:
`1d34e990a8f99019ffa53ca5de785399df863e942739a667ceb314ec6ce62a39`;
Main SHA-256 `06754a1f451f17b3047fe03cdb83fd08af11dac725638818254ef0de26a5ed29`.

Restano aperti gli altri controlli FF7 e blocchi FF7/FFB/FFC, i domini dei
chiamanti calcolati e runtime, i candidati AUX codice/dati, i BCR e la
configurazione reale del SoC. Permessi, reset, temporizzazione, interrupt,
effetti periferici e completezza fisica richiedono ulteriori prove.
