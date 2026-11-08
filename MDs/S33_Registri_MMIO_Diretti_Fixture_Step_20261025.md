# Registri MMIO diretti: CPU emulata e fixture esplicite

Data: 25 ottobre 2026. Atlante: `Risultati/Processor_Registers/20261025T095212Z/`.

## Risultato e percentuale misurabile

L’atlante contiene 478 voci: 64 posizioni di codifica core, 197 indici AUX e
217 indirizzi MMIO. Le posizioni core includono codifiche opzionali/riservate;
questi conteggi non provano altrettanti registri fisici implementati.

Nel sottoinsieme iniziale di costanti basse con accesso memoria diretto,
43 indirizzi su 47 sono ora nell’atlante: 91,489%, arrotondato 91,5%.
Restano 0x0FEF000C, 0x0FEF0050, 0x0FEF00E8 e 0x0FEF00F8.
Il denominatore riguarda esclusivamente quel censimento ristretto.
La percentuale di completamento dell’intero processore non è calcolabile:
configurazione fisica/BCR, universo AUX/MMIO e semantiche hardware restano aperti.

## Prove aggiunte

Il firmware Main originale, funzione 0x178D08..0x1792F8, è stato eseguito con
un frontend esterno collegato alla libsim GNU esistente in sola lettura.
Nessuna modifica a firmware originale, installazioni, sorgenti o build GNU.

Sono stati aggiunti 22 indirizzi MMIO: 17 nella fascia bassa FE e cinque FFE.
Tre scenari completi producono 483 eventi memoria; due prefissi negativi
portano il totale osservato a 614. Le cinque coppie con osservatore disabilitato
e abilitato hanno tracce guest identiche byte per byte. Nei tre scenari completi
sono verificati ritorno, SP, sentinelle dei registri salvati, celle e padding.
I negativi si fermano intenzionalmente al budget, su attese controllate.

L’audit indipendente confronta parole istruzione con il firmware originale,
PC, tipo, larghezza halfword, indirizzi e valori degli eventi con le tracce.
Il frontend a passi duplica le righe di risultato: le coppie vengono trattate
come duplicati, non come due accessi. I contatori del profiler non sono un
conteggio dimostrato delle istruzioni ritirate.

Un risultato LR originale a 0x178D18 per AUX 0x48 porta i siti run/PC AUX
verificati a 66; gli indici AUX con risultato guest rappresentativo restano 21.
Il seed zero e il seed busy 0x100 sono fixture del chiamante, non reset Nikon.

## Limiti del modello

Le celle MMIO, i valori iniziali, gli argomenti e la tabella opzionale a
0x600000 sono fixture esplicite. La tabella non prova RAM fisica libera.
Il completamento del polling FE20008 e la transizione FFE2014C sono scritture
del frontend registrate separatamente dagli accessi CPU del firmware.
Le celle virtuali FE e FFE sono modellate separatamente; alias fisici ignoti.
Non sono dedotti funzione del periferico, tempi, frequenza, IRQ, W1C o reset.
Nessuna verifica hardware; nessuna operazione sul dispositivo. NON_INSTALLARE.

## Fonti riproducibili

- `outputs/gnu_arc700/20261025T094028Z_04f3a263/verified_evidence.json`
- `Risultati/Processor_Registers/20261025T095212Z/atlas_validation.json`
- `Risultati/Processor_Registers/20261025T095212Z/evidence/direct_mmio_step_audit.json`
- `Risultati/Processor_Registers/20261025T095212Z/REGISTER_MAP.md`
- `Python_Trace_Scripts/s33_verify_direct_mmio_sequence.py`
- `Python_Trace_Scripts/s33_audit_direct_mmio_sequence.py`

Audit e integrazione PASS. Ledger di 121 file; i 113 file del parent verificati
invariati. Obiettivo complessivo ancora attivo e mappa fisica incompleta.
