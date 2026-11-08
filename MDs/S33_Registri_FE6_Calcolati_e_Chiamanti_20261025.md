# Registri FE6 con indirizzo calcolato e chiamanti originali

25 ottobre 2026. Atlante: `Risultati/Processor_Registers/20261025T102247Z/`.
579 voci: 64 posizioni core / 197 AUX / 318 MMIO. Mappa fisica incompleta,
obiettivo attivo. Nessun registro hardware verificato. Le posizioni core
comprendono codifiche opzionali/riservate, non64 registri fisici dimostrati.

## Nuovi indirizzi e ambito

96 nuovi indirizzi halfword risultano dall’esecuzione di sei accessor originali:
2C5D58,2C5DE8,2C5E80,2C5EE0,2C5F20,2C5F74. I primi cinque accettano i24
selettori20..33hex e40..43hex; l’ultimo scrive solo per29hex.
L’indirizzo è FE60000+16*selettore con offset0,4,8,C. I96 indirizzi coprono
FE60200..FE6033C eFE60400..FE6043C, esclusivamente quegli offset, non ogni byte.

Il chiamante sintetico esercita tutti i24 valori del dominio software.
Questo non dimostra che tutte96 le celle siano implementate sul SoC o usate
nella configurazione Nikon. Nessuna percentuale globale può essere derivata
senza il totale dei registri fisici. Famiglie e accessi oltre questa finestra
rimangono da seguire.

| Offset | Operazione software originale verificata |
|---|---|
| 0 | Scrittura dei bit0..1,2,4,6,10..11,12..13,14..15; altri bit azzerati. Un accessor separato sostituisce10..15 preservando0..9 |
| 4 | Setter modifica esclusivamente bit8; getter distinto restituisce value&0x200, bit9 senza normalizzazione |
| 8 | Scrittura del r2 basso16. Per selettore29 un’altra routine scrive r1 basso16 |
| C | Bit15 da r1 bit0, bit0..13 da r3, bit14 azzerato |

Il setterbit8 e getterbit9 non vengono unificati sotto un nome o significato
hardware. Nessuna deduzione di IRQ, W1C, reset, temporizzazione, stato cache,
nome fisico o permessi d’accesso.

## CPU emulata e audit

Prova: `outputs/gnu_arc700/20261025T101918Z_81203946/verified_evidence.json`.
Due scenari positivi, con seed di tutte le celle0 eFFFF, e uno negativo con
seedA55A. Ciascuno è ripetuto con osservatore esterno disabilitato e abilitato:
tre coppie di tracce identiche byte per byte. L’osservatore delega agli accessori
GNU esistenti; nessuna modifica al guest o al motore.

I positivi eseguono192 chiamate originali ciascuno e265 accessi MMIO ciascuno:
530 eventi osservati complessivi. Sono confrontati sequenza, PC, operazione,
indirizzo effettivo e valore; tutte96 le celle sono raggiunte.
SP e sentinelle r13/r14/r15 sono controllati dal chiamante dopo ogni ritorno.
Le celle finali e il padding A5 esterno a ciascuna halfword vengono verificati.

Il negativo esegue64 chiamate sui valori0,1F,34,3F,44,7FFFFFFF,80000000,FFFFFFFF:
nessun accesso MMIO osservato. Totale448 chiamate per i tre scenari distinti,
896 includendo i replay. Non si tratta di896 registri o di istruzioni ritirate.

Audit indipendente `evidence/fe6_computed_registers_audit.json`, PASS:
hash input, confronto byte istruzione con firmware originale, controlli di
intervallo, shift4, bit8/bit9, larghezza16, tracce in ordine e dominio degli
indirizzi effettivi. Ogni evento ha una riga risultato nei run continui;
non si applica la duplicazione del precedente frontend a passi.

## Chiamanti originali: evidenza statica

`evidence/fe6_original_callers.json` verifica otto chiamate condizionate,
con GNU e decoder BL indipendente, in quattro finestre di Main.

- 239FC8 e23A008 chiamano2C5DE8 con selettori2C e33, sotto gate modo2.
- 23A270 usa24 per setterbit8, getterbit9, scrittore completo e clearbit8.
- 239F2C conserva il parametro inr14, controlla modo e intervalli e lo inoltra
  ai medesimi accessor. Il percorso attende che il getterbit9 sia nonzero.

Sono valori presenti nel codice originale, non valori osservati durante
l’esecuzione della fotocamera. La raggiungibilità globale e la condizione di
modalità non sono dimostrate da questo audit. Gli altri selettori del dominio
sono esercitati dal chiamante sintetico.

## Integrità e passi aperti

Ledger137file verificato; parent128file invariati. AUX guest invariati:
22 indici con risultato rappresentativo,74siti run/PC verificati.
GNU, firmware e copie laboratorio preservati e montati in sola lettura.
Nessuna operazione dispositivo, flash, NAND/vendor, reset USB o scrittura SD.
NON_INSTALLARE invariato. Rapporto e checkpoint PMB aggiornati separatamente.

Riproduzione tramite `s33_verify_fe6_computed_registers.py`,
`s33_audit_fe6_computed_registers.py`, `s33_verify_fe6_original_callers.py` e
`s33_integrate_fe6_computed_registers.py` in `Python_Trace_Scripts/`.

Restano da seguire2C5D30 con selettore calcolato e il suo loop chiamante239F00,
le altre famiglie FE6/FF7/FFB/FFC, gli argomenti AUX parametrizzati e i candidati
codice/dati. Configurazione reale/BCR e semantiche fisiche rimangono aperte.
