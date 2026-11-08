# Nikon COOLPIX S33 — evidenze USB reali

## Dispositivo fisico
- Modello: COOLPIX S33
- Versione firmware dichiarata: V1.0
- USB VID:PID: 04b0:035d
- Protocollo: PTP
- Vendor extension ID dichiarato: 0x6
- Vendor extension description: nikon.co.jp: 1.0;

## Differenza rispetto al firmware studiato
- Firmware analizzato staticamente: Nikon V1.1
- I 16 blocchi TBM corrispondono integralmente al firmware.bin V1.1
- Non assumere equivalenza di indirizzi con la V1.0 fisica

## Acquisizioni USB
- 01_ptp_trace.log: traccia diagnostica della comunicazione PTP
- 01_deviceinfo.txt: informazioni del dispositivo
- 02_ptp_operations.txt: operazioni rilevate nel debug
- 03_ptp_properties.txt: proprietà interrogate
- 04_ptp_events.txt: osservazione passiva degli eventi
- 05_object_info.txt: metadati PTP della fotografia
- DSCN0148_original.JPG: JPEG originale, se trasferito
- 07_exif_complete.txt: metadati EXIF, se ExifTool disponibile
- 08_jpeg_structure.txt: struttura JPEG, se disponibile

## Obiettivo per Codex
- Confrontare i codici PTP osservati con i gestori USB nel firmware V1.1
- Localizzare eventuali dispatcher dei comandi PTP Nikon
- Verificare il ruolo delle proprietà 0xD303 e 0xD407
- Confrontare le caratteristiche JPEG reali con la pipeline individuata
- Non interpretare le notifiche USB come eventi S1/S2 senza prova

## Sicurezza
- Nessun aggiornamento firmware
- Nessun comando vendor-specific sconosciuto
- Nessuna operazione di scrittura sulla fotocamera richiesta
