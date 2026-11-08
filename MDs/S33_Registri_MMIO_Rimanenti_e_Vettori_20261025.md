# Chiusura del censimento MMIO diretto iniziale e nuova evidenza sui vettori

Data: 25 ottobre 2026. Obiettivo complessivo attivo; mappa fisica incompleta.

## Esito

Atlante `Risultati/Processor_Registers/20261025T101456Z/`: 483 voci,
64 posizioni di codifica core / 197 AUX / 222 indirizzi MMIO.
Le posizioni core includono slot opzionali/riservati: non provano 64 registri
fisici. Nessun registro hardware verificato.

Sono stati aggiunti cinque indirizzi halfword da istruzioni Main originali.
I quattro candidati rimasti nel censimento iniziale basso diretto sono
ora supportati da accessi CPU: copertura di quel solo insieme 47/47.
Il quinto indirizzo, FEF0328, è emerso da una finestra riallineata che il
censimento lineare non aveva decodificato correttamente. Questo è anche una
prova concreta del limite del denominatore iniziale: 100% di quel sottoinsieme
non misura il totale del processore, degli MMIO o di tutto il firmware.

| Indirizzo | Accesso originale osservato | Relazione software verificata |
|---|---|---|
| 0x0FEF000C | Lettura16 a 17A872 e 17A8C4 | Valore incrementato in r10, mentre il conteggio del ciclo è fisso33 |
| 0x0FEF0050 | Lettura16 a 265214 | Bit6 seleziona il percorso opzionale seguente |
| 0x0FEF00E8 | Lettura16/scrittura16 a 265220/26522C | RMW che azzera bit0 quando FEF0050bit6 è impostato |
| 0x0FEF0328 | Lettura16 a 265F60 | Bit4 seleziona il percorso opzionale seguente |
| 0x0FEF00F8 | Lettura16/scrittura16 a 265F6C/265F78 | RMW che azzera bit0 quando FEF0328bit4 è impostato |

Non sono dimostrati nome fisico, semantica W1C, riconoscimento IRQ, valori
reset, tempi, frequenza o effetti delle cache.

## Esecuzione CPU e fixture

Prova: `outputs/gnu_arc700/20261025T101249Z_6f458338/verified_evidence.json`.
Dieci scenari, ciascuno eseguito con osservatore disabilitato e abilitato:

- Due wrapper originali 17A860 e 17A8A4, ciascuno con seed FEF000C pari a0 eFFFF.
  Il target halfword è RAM sintetica700400. Il contesto sintetico collegato da
  RAM369348 usa contatore iniziale1: le funzioni originali incrementano2 e
  ripristinano1. Sono verificati valore target, ritorno0, SP e r13/r14/r15.
- Percorso265214: bit6 basso, bit6 alto con SP salvato nullo, bit6 alto con SP
  salvato700F00. MMIO E8 iniziaA5A5 e diventaA5A4 solo nel percorso attivo.
- Percorso265F60: analoghi casi con bit4 di FEF0328 e cella FEF00F8.

Le due sequenze dei vettori sono entrate direttamente dal chiamante sintetico.
AUX25 è inizializzato a700800; ilink e RAM423B00..423B0F forniscono il ritorno e
lo SP salvato sintetici. Il firmware originale costruisce e salva la parola
nel vettore a base+24 o base+2C; valore e SP finale vengono verificati.
Non è un ciclo completo di ricezione/salvataggio/ripristino di un interrupt.
Nessuna regione RAM è dichiarata libera nel silicio sulla base di queste fixture.

L’osservatore esterno delega una sola volta agli accessori GNU esistenti.
18 eventi MMIO completati nei dieci run osservati, dieci coppie di tracce
identiche byte per byte. Qui il frontend esegue un run continuo: ogni evento
ha una sola riga risultato, a differenza della precedente prova a passi.
Gli operandi di store sign-extended vengono confrontati nei16bit solo dopo
prova indipendente della larghezza dell’istruzione e dell’accesso.
Nessuna transizione periferica iniettata durante questi run.

Sono state osservate otto nuove coppie run/PC AUX, quattro per percorso:
LR25 e SR47, SR10, SR200. Risultati guest rappresentativi ora su22indici e74siti.
SR47 è un nuovo indice con risultato originale osservato; l’operando1 non prova
stato cache o valore effettivo dopo mascherature/effetti del setter.

## Audit e conservazione

- Audit indipendente: `evidence/remaining_direct_mmio_audit.json`, PASS.
  Verifica hash, byte istruzione nel firmware originale, PC, opcode, indirizzo
  assoluto, larghezza, valori e ordine degli accessi contro le tracce.
- `aux_trace_site_verification.json`:74siti ridecodificati e confrontati con
  ELF di analisi e firmware originale, PASS.
- Ledger128file del nuovo atlante verificato; parent121file invariati.
- Firmware SHA256:1d34e990a8f99019ffa53ca5de785399df863e942739a667ceb314ec6ce62a39.
- Installazioni/configurazioni/sorgenti/build/copielab GNU e originali invariati,
  montati in sola lettura nei container. Nessun dispositivo, flash, NAND,
  reset USB o scrittura SD. NON_INSTALLARE invariato.

Il primo tentativo101231Z_2bf97bd1 è conservato come FAIL: il frontend precedente
non stampava il riepilogo richiesto dal verificatore, pur terminando con codice0.
Il nuovo frontend esterno aggiunge solo sim_info; nessuna modifica GNU.

## File riproducibili e passi aperti

- `Python_Trace_Scripts/s33_verify_remaining_direct_mmio.py`
- `Python_Trace_Scripts/s33_register_profile_observer.c`
- `Python_Trace_Scripts/s33_audit_remaining_direct_mmio.py`
- `Python_Trace_Scripts/s33_integrate_remaining_direct_mmio.py`
- `Risultati/Processor_Registers/20261025T101456Z/REGISTER_MAP.md`
- `Risultati/Processor_Registers/20261025T101456Z/completion_audit.json`

Restano da ampliare accessi diretti e calcolati nei percorsi originali,
risolvere famiglie AUX parametrizzate e candidati codice/dati, ottenere evidenza
reale BCR/configurazione del SoC e semantiche fisiche. La percentuale complessiva
non è calcolabile senza l’universo dei registri realmente implementati.
