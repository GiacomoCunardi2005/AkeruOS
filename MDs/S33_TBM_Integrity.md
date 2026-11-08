# AkeruOS — Integrità dei blocchi TBM

## Verifica eseguita
Tutti i 16 blocchi TBM estratti sono stati cercati integralmente nel firmware.bin Nikon V1.1.

**Risultato: 16/16 corrispondenze complete byte per byte.**

## Versioni
- Firmware analizzato: Nikon COOLPIX S33 V1.1
- Fotocamera reale interrogata via USB PTP: Nikon COOLPIX S33 V1.0
- Nessun aggiornamento previsto

## Architettura
- Blocchi 11–15: base condivisa 0x01044800
- Possibile sistema di overlay da verificare
- Gli indirizzi di caricamento sono ancora indicati come candidati nel manifest
- Gli identificatori di tipo TBM non hanno ancora semantica completamente verificata

## Tracciamento JPEG
- Caller A: 0x81B72E -> 0x126DD8
- Caller B: 0x81BDFE -> 0x126DD8
- Caller C: 0x81C1A0 -> 0x8116CC
- Possibili ingressi: 0x81B356, 0x81BB56, 0x81BF3C
- Gli ingressi devono ancora essere verificati come confini reali delle funzioni

## Priorità
Identificare i chiamanti superiori e risalire alla gestione fisica del pulsante S2.
