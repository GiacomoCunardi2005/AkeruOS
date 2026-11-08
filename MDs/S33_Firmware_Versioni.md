# AkeruOS — Provenienza firmware e versioni

## Firmware fisico
- Fotocamera: Nikon COOLPIX S33
- Versione PTP dichiarata: V1.0
- USB: 04b0:035d, protocollo PTP
- Nessun aggiornamento previsto o necessario per il RE statico

## Firmware analizzato
- Pacchetto Nikon: F-S33-V11W.exe
- File: ~/Scaricati/S33Update/firmware/firmware.bin
- Dimensione: 29602084 byte
- SHA256: 1d34e990a8f99019ffa53ca5de785399df863e942739a667ceb314ec6ce62a39
- I due firmware.bin estratti sono identici
- I campioni dei blocchi TBM corrispondono al firmware V1.1
- Verifica del19 ottobre: tutti i16 blocchi confrontati integralmente con le porzioni TBM del contenitore originale, oltre ai16 SHA-256; confrontati anche payload TBIB/TBM. [Rapporto](S33_Passaggio_TBIB_TBM_e_Ingresso_CPU.md)

## Architettura TBM
- Sono stati identificati 16 blocchi TBM
- I blocchi 11-15 condividono la base 0x01044800
- Possibile caricamento dinamico/overlay da verificare
- Non sovrapporre questi blocchi in Ghidra senza una strategia esplicita

## Compatibilità V1.0 / V1.1
- Gli indirizzi ottenuti dal firmware V1.1 non sono automaticamente validi sulla V1.0 reale
- Non aggiornare la fotocamera salvo necessità concreta e verificata
- Nessun comando PTP sconosciuto e nessuna scrittura firmware

## Prossima priorità
- Ricostruire i chiamanti superiori di 0x81B72E, 0x81BDFE e 0x81C1A0
- Individuare la normale acquisizione fotografica
- Risalire al pulsante fisico S2


## Ricontrollo offset contenitore — 19 ottobre 2026

Verifica diretta sul file locale `OriginalSoftware_NikonS33_V1.1/firmware.bin`, 29.602.084 byte, SHA-256 sopra confermato. Campo header `V2.0` a `0x4`, nome TBIB a `0x20`, payload TBIB da `0x6C`; `Sunny10-SK501` a `0x4804C`, nome TBM a `0x4806C`. La parola a `0x480B4` precede il payload: **firma RHIR a `0x480B8`**, primi descrittori a **`0x480C8`** (TBM+`0x10`), non a `0x480C0`. I 17 descrittori e i 16 blocchi estraibili sono descritti nel [capitolo3](Nikon_Coolpix_S33_Capitolo_3.md). Il campo `V2.0` dell'header non identifica la versione applicativa Nikon: il pacchetto analizzato resta V1.1.
