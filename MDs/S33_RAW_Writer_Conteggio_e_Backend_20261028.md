# S33 V1.1 — conteggio del writer RAW e collegamento al backend file

28 ottobre 2026. Prova offline GNU ARC700, firmware originale V1.1. Nessuna fotocamera, scheda o firmware modificati. **NON_INSTALLARE**.

## Risultato

Il writer RAW `0x28D4D4` esegue la scrittura con `0x12BCC4 → 0x18B0BC → 0x12DE3C`, passando anche il puntatore al conteggio effettivo. Il writer controlla lo stato ma non confronta il conteggio con la lunghezza richiesta. Nel nuovo banco, il servizio inferiore simulato restituisce stato 0 e conteggio 0 su 26.527.232 byte richiesti: il writer chiama close e ritorna 0. La stessa sequenza con conteggio completo ritorna 0; gli errori simulati write, open e close sono distinti.

La precedente prova del filesystem originale aveva osservato `0x12DE3C` con stato 0 e conteggio 0 o parziale in scenari di guasto della scheda **modellata**. Questo nuovo raccordo mostra che l'esito sintetico della scrittura è compatibile con le convenzioni dei wrapper RAW originali, ma i due banchi non sono concatenati: non prova che il writer RAW su hardware abbia incontrato quel guasto, né che il file sia stato creato o persistito. Il nuovo banco non legge i 26 MB: il servizio inferiore è sostituito da una fixture.

## Prove

Lo [script](../Python_Trace_Scripts/s33_verify_raw_writer_count_bridge.py) deriva dal banco `s33_verify_raw_writer_errors.py` e sposta la fixture di write da `0x12BCC4` a `0x12DE3C`. Lascia eseguire originali `0x12BCC4` e `0x18B0BC`; verifica al confine inferiore handle `0x1234`, buffer sintetico `0x2040000`, lunghezza richiesta, selettore 0 e puntatore conteggio non nullo. Nome, open, write inferiore e close restano fixture. Il test verifica anche ritorni, numero chiamate e conservazione stack.

| Caso sintetico | Conteggio riportato | Stato write | Close chiamata | Ritorno writer |
|---|---:|---:|---:|---:|
| completo | 26.527.232 | 0 | sì | 0 |
| corto | 0 | 0 | sì | 0 |
| errore write | 0 | 77 | no | 77 |
| errore open | — | — | no | 78 |
| errore close | 26.527.232 | 0 | sì | 79 |

[Casi e indirizzi](../Risultati/HiddenMenu_RAW_Firmware/writer_count_bridge_20261028T143403Z/cases.json), [fixture](../Risultati/HiddenMenu_RAW_Firmware/writer_count_bridge_20261028T143403Z/fixture_patches.json) e `verified_evidence.json` nella stessa cartella. Le patch sono trampolini nelle sole immagini di laboratorio; sorgenti, build GNU e firmware sono immutati. In caso di errore write, l'assenza di close nel wrapper osservato non dimostra cosa facciano livelli inferiori o altre parti della macchina.

Il banco separato [filesystem FAT12 originale con controller e scheda modellati](S33_Dumper_RAM_SD_File_FAT_Creazione_Scrittura_Close_e_Riapertura.md) usa `0x12DE3C` direttamente: nei guasti PIO descritti, stato 0 accompagna 0/1024 byte e, in un caso frammentato, 1024/2048. La geometria, i guasti e la scheda sono sintetici; non dimostrano lo stesso esito su SD reale o con richiesta RAW di 26 MB.

Per un futuro salvataggio RAW robusto occorrono controllo dell'esito, conteggio esatto, chiusura, eventuale file-error e verifica di rilettura; ciascuno è distinto. Per preservare anche JPEG occorre risolvere proprietà e durata del buffer, senza dedurre integrità o successo dalla sola chiusura del RAW.
