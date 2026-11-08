# HiddenMenu: questioni aperte e prove successive

Verifica statica locale del 19 ottobre 2026. Campione **Nikon S33 V1.1**: 29.602.084 byte, SHA-256 `1d34e990a8f99019ffa53ca5de785399df863e942739a667ceb314ec6ce62a39`. Indirizzi CPU della mappa candidata dei payload, salvo esplicita indicazione «offset file». Nessun risultato è una prova di esecuzione sulla S33 V1.0 dei log hardware.

Fonti riproducibili: [catalogo strutture](../S33-sections/analysis_codex/evidence/ui_catalog.json), [traccia e modelli locali](../S33-sections/analysis_codex/evidence/hiddenmenu_trace.json), [audit integrità](../S33-sections/analysis_codex/evidence/patch_audit.json). Esecuzione complessiva dalla radice: `python3 S33-sections/analysis_codex/run_analysis.py`, senza `-O`. GNU `-m arc:ARC700 -EL`, payload verificati e conversioni ELF temporanee ricontrollate byte per byte. Le finestre di contesto possono includere pool/tabelle: le righe che li interpretano come istruzioni non costituiscono flusso eseguibile; per i salti di selezione usare le finestre `case_…` riancorate.

## Priorità1 — prima di qualsiasi esecuzione diagnostica

1. **Backend di scrittura e supporto fisico.** Chiudere `1EEA4C→1EE730→1EDED8/1EDFDC`, `1695D0→169564`, `3014C0→1EEF6C`, `3016EC→1EEAEC`, partizionamento `29E8F0/29EFC4`. Il nome “NAND” e un bufferFF non dimostrano un comando erase nativo. Nel simulatore intercettare gli endpoint e registrare richieste senza dispositivo reale.
2. **Reset e SD Life.** Il root0480 apre84 ResetCameraConfirmMenu; il suo evento2180 arriva aC9D84/CBDF8/177030. SKY caso0 chiama7D58D8, poi apre87 AutoSceneLiveView. Non trattare questi percorsi come consultazione innocua. Verificare in isolamento ogni richiesta di acquisizione, file e cambiamento di modalità.
3. **Recupero R4 e compatibilità.** Checksum del contenitore e istruzione corretta non provano aggiornamento accettato, boot, rollback, integrità delle calibrazioni o compatibilità con la macchinaV1.0. Nessuna prova di flash è autorizzata da questo dossier.

## Priorità2 — apertura e comportamento UI nel simulatore

4. **Condizioni di attivazione.** Eseguire lo slice1353F2..135426 con stub129920/CDA24/1453E4, stati0/1/2/3, sonde0/1 ed errori. Il modello copre1.024 combinazioni e assume stato stabile fra le due letture. Con la patch, stato3 non apre più20 attraverso il primo ramo. Controllare che il delay slot passi38FF2F e che il bit attributo0x10 sia richiesto.
5. **Origine dello stato.** Payload366880=1 e writerC5DE8(1) sono provati; non è esclusa una modifica via chiamata indiretta, alias o altri blocchi. Cercare tutti gli scrittori effettivi prima di assumere sempre1 al boot.
6. **Manager e ciclo vita.** Inizializzare manager366E94, tabella3F5900 e risorse; simulare descrittore nullo, bit0, busybyte+39, hook367808 e sentinel55AA5AA5. Verificare ritorno e stato corrente, non soltanto l'istruzione di call. Residenza dei payload non è provata dal solo elenco di pointer.
7. **Eventi e input fisici.** Confermare selezione5000+indice e rotte0480/0580 nel contesto delle liste. Solo le stringhe originali nominano Right/REV; tastiera fisica, pressione/rilascio e ripetizione restano da collegare ai produttori. Testare gli alias low8 e gli indici fuori lista: SKY fallback0, NAND senza azione100..128.
8. **Errori e quiescenza.** Intercettare ciclo7D4840 e polling16F920(62), verificare quando si libera guard899B8C. Controllare conferma+8 e annullamento. L'assenza di timeout locale può bloccare la UI anche con backend stub.

## Priorità3 — completezza del grafo e risorse

9. **Chiusura transitiva.** La tabella197/196 e192 wrapper sono inventariati, con52 collegamenti locali. Non è un CFG globale esaustivo. Espandere i quattro wrapper1/7E/87/B1, default20E814, debug36, calibrazione26, ripristino/calibrazione e scritture secondarie. Le categorieU/F candidata nell'audit sono il confine esplicito attuale.
10. **Ownership e mutazioni.** Le voci4A/4B vengono copiate/preparate in RAM e le etichette cambiano aitem+0C; verificare il pointer runtime in899B88/899B9C prima di usare i record statici come lista effettiva. Nessuna RAM è assegnata ad AkeruOS da questi indirizzi.
11. **Rendering.** Rettangoli e testi sono disponibili; font, palette, immagini, scaling e testi localizzati/dinamici non sono ricostruiti. Non convertire le coordinate memorizzate in una risoluzione hardware dedotta.
12. **Integrità ulteriori formati.** Valutare l'XOR12B060 soltanto con parser/argomenti corretti; identificazioneC7694, INFO/sentinella e controlli di capienza sono distinti da RHIR/KHIR. Non estendere a tutto il file un controllo trovato in un solo ramo.

## Prove già svolte e confine della consegna

La consegna contiene cinque rapporti, script riproducibili, dati con versione/hash, contesti GNU e casi riancorati. Verificati: confronto integrale dei due input, identità16payload, somme RHIR/KHIR/TBIB, catalogo197indici,29+17+39case,2.048predicati di selezione e1.024di attivazione. I modelli confrontano formule locali con predicati ricavati dalle istruzioni, non sono esecuzione del firmware o test hardware.

Non sono state modificate immagini firmware, compilato l'emulatore, apertoUSB o scritto SD/NAND/flash. Nessun avvio AkeruOS o nuova fotografia: avanzamento funzionale circa10% invariato. Prossimo punto utile: harness del solo slice di attivazione con sonde e apertura sostituite da stub; poi inizializzazione UI e verifica delle selezioni, mantenendo lo storage intercettato.

## Aggiornamento salvato e stop

Vedere [nuove prove e punto di arresto](HIDDENMENU_FOLLOWUP.md): SD Life classificata P per scritture file; store MMIO verificati; ricerca nei16payload; hash firmware invariati. Analisi sospesa su richiesta dell’utente. Restano aperti backend2018, effetti transitivi e completamento fisico.
