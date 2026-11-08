# FF7: writer impacchettati e contratti della coda

25 ottobre 2026. Atlante `Risultati/Processor_Registers/20261025T150447Z/`:
763voci,64posizioni core /197AUX /502indirizzi MMIO catalogati singolarmente.
Le finestre sono ora12 con2930offset di cella; restano due famiglie parametriche
irrisolte separate. Mappa fisica incompleta, obiettivo attivo. Le posizioni
core includono slot opzionali/riservati, non64registri fisici dimostrati.
Nessun registro hardware verificato.

## Sette nuove finestre, dieci routine

| Finestra | Celle | Entry originali Main | Contratto input |
|---|---:|---|---|
| FF74044 | 17 | 2E06F0 | Coppie7bit da u16; coda u16 |
| FF7408C | 17 | 2E0774 | Coppie7bit da u16; coda u16 |
| FF740F0 | 17 | 2E0884 /2E0908 | Wideu16 /compactu8, code differenti |
| FF7413C | 17 | 2E098C /2E0A10 | Wideu16 /compactu8, code differenti |
| FF74188 | 17 | 2E0A94 /2E0B18 | Wideu16 /compactu8, code differenti |
| FF7600C | 12 | 2E0BD0 | Sequenza u16 grezza |
| FF76044 | 17 | 2E0C30 | Sequenza u16 grezza |

114offset nuovi, store16 con stride4. Sono rappresentati come finestre, non
come114registri di controllo indipendenti. Tipo fisico, permessi d’accesso,
reset ed effetti periferici restano sconosciuti. Stride4 non dimostra una
larghezza32bit del registro o gap riservati sul silicio.

## Impacchettamento e diciassettesimo elemento

Nei writer7bit, per i primi16elementi:
`(input_u16[2*i]&7Fhex) | ((input_u16[2*i+1]&7Fhex)<<8)`.
I bit7 e15 del valore trasferito sono zero. Il diciassettesimo elemento è
invece input_u16[32], senza quel mask: può contenere bit15 impostato.

Nelle tre varianti wide a coppie8bit, i primi16elementi combinano i byte bassi
di32campioniu16. Nelle varianti compatte combinano32byte consecutivi. I primi
16valori coincidono se i byte corrispondono, ma la coda è rispettivamente
u16[32] oppure u8[32]. La coppia di prove BEEF/EFhex dimostra la differenza.
Le due firme non vengono unificate, anche se condividono gli indirizzi target.

Sono verificati cinque casi metamorfici: cambiare tutti i bit ignorati dei
primi32input wide lascia invariati tutti gli outputMMIO della routine, coda
fissata compresa. Tre confronti wide/compact dimostrano primo blocco uguale
e coda di larghezza diversa. L’equivalenza riguarda gli outputMMIO, non le
tracce complete tra input diversi. Ogni coppia osservatoreoff/on conserva
invece la traccia guest identica byte per byte.

## Parametri singoli e argomenti dati

Dieci nuovi indirizzi parametro:
FF74088,FF740D0,FF74134/138,FF74180/184,FF741CC/1D0 eFF7603C/40.

I writer7bit trasferiscono a74088/740D0:
`uint16((r1<<10)|r2)`. r2 non viene mascherato preventivamente ai soli bit0..9:
può impostare anche i bit superiori. Non è corretto descrivere r1/r2 come due
campi indipendenti limitati dalla routine. È provato anche r1zero conr2FC00hex.
Il dominio consentito nei chiamanti Nikon reali resta ignoto.

Gli altri parametri copiano i low16 degli argomenti; nei writer a coppie il
parametror2 è scritto prima di r1. Queste routine eseguono sempre la copia:
r1/r2 sono dati, a differenza del flag skip delle cinque finestre precedenti.
Il valore r0 dopo il ritorno è verificato come effetto del codice; non ne viene
dedotto il tipo API o un significato di successo.

## CPU, mapper e audit

Prova: `outputs/gnu_arc700/20261025T145923Z_f67f3594/verified_evidence.json`.
25scenari/50run,25coppie di tracce identiche,455scritture completate:
415alle finestre e40ai parametri. SP e r13/r14/r15/r16 verificati dopo ogni
ritorno; input, Main originale, celle e padding controllati.

Il tentativo145815Z_ad4d3a4c è conservato come FAIL: il file di appoggio di
una base4mod8 non includeva il prefisso richiesto dal mapper GNU. La traccia
CPU aveva gli indirizzi attesi; è stato corretto il solo layout della fixture:
base%8byte di prefisso, dati, poi guardia8byte. Nessun indirizzo guest o byte
firmware è stato modificato. Questo padding è un requisito host, non una
traslazione fisica sul SoC.

`evidence/ff7_packed_writers_audit.json`:PASS. L’audit ridecodifica i byte
originali al PC guest, verifica mask/load, ricostruisce i valori dai buffer
raw senza usare l’oracolo del verificatore, confronta eventi e tracce in ordine,
prefissi/gap/guardie e gli otto controlli metamorfici. La cattura stdout/stderr
separata viene riusata dalla prova precedente. Nessuna misura di timing o
conteggio dimostrato delle istruzioni ritirate.

Venti siti run/PC SR LP_START/LP_END aggiunti: AUX guest sempre22indici,
siti ora104. Sono operandi dei setter, non stato AUX fisico o post-mask.

Ledger177file verificato; parent171file invariati. GNU installazioni/config/
sorgenti/build/copielab e originali preservati. Buffer700000 e backingMMIO
sono fixture, non RAM fisica libera o reset Nikon. Nessun hardware, flash,
NAND/vendor, resetUSB o scritturaSD. NON_INSTALLARE invariato.

Script in `Python_Trace_Scripts/`: `s33_verify_ff7_packed_writers.py`,
`s33_audit_ff7_packed_writers.py`, `s33_integrate_ff7_packed_writers.py`.
Restano writer FF7 precedenti e controlli scalari, FFB/FFC, domini indicizzati,
AUX parametrizzati/candidati codice-dati e configurazione reale/BCR/fisica.
