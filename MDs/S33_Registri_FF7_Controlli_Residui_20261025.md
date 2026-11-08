# Nikon S33: controlli FF7 residui e valori restituiti

25 ottobre 2026. Mappa fisica incompleta; obiettivo attivo. GNU e firmware
originali invariati, nessun accesso hardware, NON_INSTALLARE invariato.

L’atlante raggiunge **987 voci: 64 posizioni core, 197 indici AUX e 726 indirizzi
MMIO singoli**. Questo passo aggiunge 21 indirizzi e arricchisce due già noti.
Le 22 finestre restano separate dai registri: 3.118 appartenenze di cella,
3.086 indirizzi distinti, 32 appartenenze ripetute e il parametro FF74088
condiviso con una finestra. Nessun alias fisico dedotto e nessuna nuova cella
di finestra. Le 64 posizioni core includono encoding speciali/opzionali/riservati,
non 64 registri fisici verificati. Due famiglie indicizzate restano irrisolte.

## Prove nuove

`outputs/gnu_arc700/20261025T154319Z_27c63350/verified_evidence.json`:
PASS_FF7_RESIDUAL_SCALAR_CONTROLS. Otto scenari / 16 run osservatore spento e
acceso, 83 chiamate per run: **664 chiamate osservate, 1.328 includendo i replay**.
Le 26 entry originali selezionate completano il ritorno nel chiamante sintetico.
Gli otto input principali sono 0, 1, 2, 3, 80000000, FFFFFFFF, 12345678 e
A55A5AA5. I seed MMIO sono 0000, FFFF, A55A, 5AA5, 8001, 7FFE, 0020 e FFDF.
I flag dei nove setter condizionali sono provati con 0/1/2/3/80000000/FFFFFFFF.

Osservati **1.216 accessi halfword**: 736 su indirizzi nuovi e 480 sui due
esistenti. Tutte le otto coppie di tracce osservatore spento/acceso sono
identiche byte per byte. SP e sentinelle r13..r16 sono conservati dopo ogni
chiamata; i getter sono confrontati anche sul valore r0 restituito.

L’audit indipendente ricostruisce branch, bit e maschere dai byte originali,
argomenti e fixture iniziali, senza usare le sequenze attese del verificatore
come proprio oracolo. Controlla 113 istruzioni riallineate e legate al firmware,
ordine degli accessi e coppie begin/result dell’osservatore, backing finale,
larghezza halfword e gap A5. Esito:
PASS_FF7_RESIDUAL_CONTROLS_INDEPENDENT_AUDIT.

## Condizioni dei setter RMW

| Indirizzo | Bit | Entry | Condizione che imposta il bit; altrimenti lo cancella |
|---|---:|---|---|
| `FF74000` già noto | 0 | `2E050C` | argomento==1 |
| `FF74000` già noto | 7 | `2E0E94` | argomento!=0 |
| `FF74000` già noto | 8 | `2E0EC8` | argomento!=0 |
| `FF74000` già noto | 9 | `2E0EFC` | argomento==1 |
| `FF76008` nuovo | 2 | `2E0B9C` | argomento==1 |
| `FF76098` già noto | 0 | `2E0C70` | argomento==1 |
| `FF7000C` nuovo | 5 | `2E0DB4` | argomento!=0 |
| `FF70400` nuovo | 5 | `2E0E2C` | argomento!=0 |
| `FF70400` nuovo | 6 | `2E0E60` | argomento==1 |

Ogni operazione conserva gli altri bit della halfword nel modello. I due
indirizzi già noti conservano anche documentazione e prove precedenti:
nessuna voce duplicata o sostituzione dei contratti già catalogati.

## Getter mascherati e scrittura costante

`2E0DE8` legge `FF7000C` e restituisce (valore>>5)&1, quindi 0 oppure1.
È provato prima e dopo i sei valori del setter bit5 in ogni scenario.

`2E0E00` legge `FF70008` e restituisce valore&0x20, quindi **0 oppure32**.
Non restituisce un booleano normalizzato. `2E0E18` ignora l’argomento e scrive
la costante0x20 senza leggere prima. Il getter è provato prima e dopo tale
scrittura, compresa la maschera nel delay slot del ritorno originale.
Questo contratto non prova acknowledgment, W1C, azzeramento o reset hardware.

## FF760FC: bit incondizionati e campo bits2..7

- `2E1150`: imposta bit0, ignorando l’argomento.
- `2E116C`: cancella bit0, ignorando l’argomento.
- `2E1188`: imposta bit1, ignorando l’argomento.
- `2E11A4`: scrive (vecchio&FF03)|(argomento&FC).

L’ultimo setter sostituisce **bits2..7** con i bit già nelle stesse posizioni
nell’argomento; conserva bits0..1 e8..15. Non inserisce un campo low2 e non
sposta l’argomento. Sono provati 0, 3, FC, 100, FFFFFFFF e il valore variabile
dello scenario, oltre ai seed misti. Anche questi sono contratti software,
senza attribuzione di una funzione periferica reale.

## Parametri e argomenti divisi in due scritture

`2E0D64`, `2E0D78`, `2E0D8C`, `2E0DA0` copiano low16 di r0 rispettivamente
a `FF76088`, `FF7608C`, `FF76090`, `FF76094`.

`2E1030` copia low16 di r0 a `FF741D4`, poi low16 di r1 a `FF741D8`:
sono due argomenti distinti, non la divisione di un singolo argomento32.

Le cinque entry `2E11D0`, `2E11F8`, `2E1220`, `2E1248`, `2E1270` scrivono
low16 e poi high16 logico dello stesso r0, rispettivamente nelle coppie
`FF76100/104`, `FF76108/10C`, `FF76110/114`, `FF76118/11C`, `FF76120/124`.
Ordine low→high e troncamento sono verificati, senza inferire atomicità o
registri fisici a32bit.

I nuovi indirizzi sono quindi FF70008/00C, FF70400, FF741D4/D8, FF76008,
FF76088/8C/90/94, FF760FC e dieci celle singole FF76100..124. Nessuno ricade
nelle finestre di trasferimento già catalogate.

## Atlante, fonti e limiti

Risultato: `Risultati/Processor_Registers/20261025T154626Z/REGISTER_MAP.md`,
con JSON, CSV, grafo e `atlas_validation.json`. Ledger di **238 file**;
parent `20261025T153744Z`, 232 file, verificato e immutato.
`coverage_lineage_audit.json` conserva tutte le chiavi dei **28 atlanti
precedenti validati**. I manifest di finestre, sovrapposizioni e tracce AUX
sono byte-identici al parent. Non sono osservati nuovi SR nei run selezionati;
restano **146 siti AUX run/PC e 22 indici distinti**.

Copie di prove e audit: `evidence/ff7_residual_controls.json`,
`evidence/ff7_residual_controls_audit.json` e
`evidence/ff7_residual_controls_linear_navigation.txt`. Il listing lineare è
navigazione: le verifiche usano il disassemblato riallineato ai PC effettivi.
Script correnti: `Python_Trace_Scripts/s33_verify_ff7_residual_controls.py`,
`s33_audit_ff7_residual_controls.py`, `s33_integrate_ff7_residual_controls.py`.

Firmware SHA-256:
`1d34e990a8f99019ffa53ca5de785399df863e942739a667ceb314ec6ce62a39`;
Main SHA-256:
`06754a1f451f17b3047fe03cdb83fd08af11dac725638818254ef0de26a5ed29`.
Il frontend osservatore è esterno; GNU e originali sono in sola lettura.

Stack, MMIO iniziali e backing sono fixture; non sono reset, RAM fisica libera
o readback dalla Nikon. Funzione periferica, permessi, tempi, IRQ e semantica
fisica restano sconosciuti. Nessun accesso hardware/flash/NAND/vendor/resetUSB/SD.
Restano aperti la copertura fuori dai gruppi selezionati, i domini dei chiamanti,
i candidati AUX codice/dati, BCR e implementazione reale del SoC. La matematica
delle38uscite FFB dell’helper303A40 rimane non verificata indipendentemente.
Non è ancora possibile una percentuale globale dei registri fisici.
