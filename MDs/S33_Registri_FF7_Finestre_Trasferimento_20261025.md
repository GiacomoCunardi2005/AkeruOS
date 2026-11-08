# FF7: cinque finestre di trasferimento e controlli associati

25 ottobre 2026. Atlante `Risultati/Processor_Registers/20261025T110846Z/`:
753voci,64posizioni core /197AUX /492indirizzi MMIO catalogati singolarmente.
Sono conservate separatamente due famiglie parametriche irrisolte e cinque
finestre di scrittura con2816celle. Mappa fisica incompleta, obiettivo attivo.
Le posizioni core includono codifiche opzionali/riservate, non64registri
fisici verificati. Nessun registro hardware verificato.

## Finestre delimitate dal codice originale

| Entry Main | Base | Elementi | Input per elemento | Trasferimento |
|---|---|---:|---:|---|
| 2E0574 | FF72000 | 1024 | 16bit | Store16,passo4 |
| 2E0CD8 | FF73000 | 1024 | 16bit | Store16,passo4 |
| 2E1318 | FF78000 | 256 | 8bit | Store16 con valore high8zero,passo4 |
| 2E13A4 | FF79000 | 256 | 8bit | Store16 con valore high8zero,passo4 |
| 2E1430 | FF7A000 | 256 | 8bit | Store16 con valore high8zero,passo4 |

Ogni base e conteggio è legato a byte originali, istruzioni e accessi CPU.
I2816offset osservati sono rappresentati in `mmio_transfer_windows`, non come
2816registri di controllo indipendenti. Il tipo fisico resta sconosciuto:
potrebbero essere array di registri o aperture di memoria. Stride4 e store16
non dimostrano registri32bit, né i gap non scritti dimostrano bit riservati.

Il flagr1==0 esegue il trasferimento completo. Il percorso nonzero salta sia
bulk sia RMW del controllo, ma scrive sempre tre parametri finali dal buffer.
Nei test sono esercitati i valori0/1 del flag; la condizione nonzero è statica.
Il valore inr0 dopo il ritorno viene verificato come ultimo parametro copiato,
senza dedurre il tipo API o il significato del valore di ritorno.

## Diciotto indirizzi singoli nuovi

Tre indirizzi di controllo osservati in RMW:

- FF74000: il primo writer imposta bit1 prima del bulk e lo azzera dopo.
- FF76098: lo stesso uso software bit1 nel secondo writer.
- FF760CC: i tre writer byte usano rispettivamente bit0/1/2.

Gli altri quindici sono destinazioni dei parametri finali:
FF74038/3C/40, FF7609C/A0/A4, FF760A8/AC/B0,
FF760B4/B8/BC eFF760C0/C4/C8.
Il firmware trasferisce il valore8/16bit di input mediante store halfword.
Nessuna funzione periferica, permesso d’accesso, reset, timing o effetto fisico
viene dedotto dall’uso software del controllo o dei parametri.

## Esecuzione CPU e separazione dei log

Prova: `outputs/gnu_arc700/20261025T110301Z_f8770caa/verified_evidence.json`.
Venti scenari: cinque writer, due pattern input, bulk/solo parametri.
Ogni scenario viene ripetuto con osservatore disabilitato e abilitato:
40run,20coppie di tracce identiche byte per byte.

5732eventi completati:5632scritture alle finestre e100accessi ai controlli/
parametri. Ogni cella delle cinque finestre è scritta con entrambi i pattern.
Nei casi byte il pattern percorre tutti i256valori8bit. I parametri finali
sono verificati anche quando la copia bulk è saltata.

I buffer a700000, i seed dei controlli5AA5/A55A e il backing delle finestre
sono fixture esplicite. Non provano caricamento/reset Nikon o RAM fisica libera.
SP e r13/r14/r15/r16 sono verificati dopo ogni ritorno. I file input e Main
rimangono invariati; le halfword e i gap/padding A5 sono verificati nel modello.

Il primo tentativo110138Z_ce61dccc è conservato come FAIL: diagnostica stdout
e JSON stderr si erano interlacciati nel log unificato. Il nuovo frontend di
orchestrazione cattura i due canali separatamente; il motore GNU e il guest
non sono stati modificati. Il file `.log` diagnostico concatena stdout e stderr,
non ne rappresenta l’ordine temporale; i canali grezzi restano disponibili.
L’audit degli eventi legge esclusivamente `.stderr.log`.

## AUX, audit e integrità

Dieci siti run/PC SR originali LP_START/LP_END sono aggiunti: due per writer,
nel caso bulk pattern0. Indici AUX con risultati guest rappresentativi ancora22;
siti verificati ora84. I valori SR sono operandi del setter, non misura dello
stato fisico o del valore AUX dopo mascherature/effetti.

`evidence/ff7_transfer_windows_audit.json`:PASS. Verifica byte al PC guest,
basi e conteggi loop, pool controlli, confronto input originale/indirizzo/
valore per ogni cella, parametri sempre scritti, gap/padding e raw JSON separati.
Una riga risultato per accesso nei run continui. Il profiler non è un contatore
dimostrato delle istruzioni ritirate.

Ledger171file verificato; parent164file invariati. GNU installazioni/config/
sorgenti/build/copielab e firmware originali preservati. Nessun hardware,
flash, NAND/vendor, resetUSB o scritturaSD. NON_INSTALLARE invariato.

Script in `Python_Trace_Scripts/`: `s33_verify_ff7_transfer_windows.py`
(con `SeparatedRunner` riusabile), `s33_audit_ff7_transfer_windows.py`,
`s33_integrate_ff7_transfer_windows.py`. Seguito: altri writer FF7 con campi
impacchettati, FFB/FFC, domini dei chiamanti indicizzati, AUX/BCR/fisica.
