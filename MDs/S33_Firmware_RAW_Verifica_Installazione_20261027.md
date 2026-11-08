# S33 — verifica del candidato RAW prima di un'eventuale installazione

27 ottobre 2026. L'utente ha chiesto di verificare il più possibile il
[candidato RAW forzato](S33_Firmware_RAW_Forzato_Offline_20261027.md), con
l'intenzione di installarlo. **Esito: NON INSTALLARE.** Le nuove verifiche
chiudono alcuni passaggi locali in emulazione, ma non dimostrano sicurezza di
installazione, avvio completo, spazio e durata del buffer RAW, scrittura SD o
recupero fisico. Nessun firmware è stato installato in questa attività.

Candidato esaminato: `Risultati/HiddenMenu_RAW_Firmware/20261027T110219Z/`
`firmware_RAW_FORZATO_OFFLINE_NON_INSTALLARE.bin`, SHA256
`56c9457646be23bde6e1bda47c6cefaada5bf52657ba299f83339306debf4cbf`.
La verifica riguarda esattamente questi byte e la base V1.1 indicata nel
rapporto precedente.

## Updater originale: checksum e validatore Main

[Prove](../Risultati/HiddenMenu_RAW_Firmware/updater_20261027T110419Z/verified_evidence.json),
[verificatore](../Python_Trace_Scripts/s33_verify_raw_candidate_updater.py).

Il codice V1.1 originale eseguito nella CPU del laboratorio ricalcola l'XOR
dell'intero pacchetto con `0x12B060` e valida il TBM Main con `0x12AEA0`.
Il pacchetto valido restituisce 0; lunghezza oltre la capacità della partizione
modellata restituisce `0x01C00114`; firma, payload 0 e payload 1 alterati
separatamente restituiscono `0x01C00111`. Stack preservato. Le due prove
eseguono rispettivamente 37.002.693 e 5.036.047 istruzioni.

La tabella di partizione deriva dal dump locale `NANDP1.dmp`; RAM e geometria
sono fixture. L'engine GNU DSPv7 di laboratorio è usato in sola lettura per la
moltiplicazione supportata nel dominio indicato. Non sono stati eseguiti UI
updater completa, cancellazione/programmazione/rilettura NAND, updater
attualmente residente o recupero dopo interruzione. L'esito 0 è solo il
risultato delle funzioni originali nei confini del banco.

## Loader originale e primo tratto di avvio

[Prove](../Risultati/HiddenMenu_RAW_Firmware/loader_20261027T110501Z/verified_evidence.json),
[verificatore](../Python_Trace_Scripts/s33_verify_raw_candidate_loader.py).

Il loader TBIB originale legge header e payload 0, 1 e 8 del candidato,
verifica i checksum e li carica nelle destinazioni del laboratorio. Nel caso
valido i byte caricati corrispondono al candidato e le guardie restano intatte.
I casi di firma alterata, checksum alterato ed errore del lettore restituiscono
rispettivamente 11, 13 e 7. Cinque scenari, compreso il tratto successivo.

Nel quinto scenario l'avvio raggiunge `0xBB540`, esegue l'azzeramento originale
`[0x42D140,0x5DA5DC)` e si arresta prima del kernel. Lo SP osservato è
`0x5DADC4` e GP `0x423844`. Per questo tratto due servizi sono sostituiti in
RAM **dopo** il controllo del loader: configurazione CPU restituisce e l'ingresso
kernel termina la prova. Il lettore settori è una fixture basata sul file; il
codice descriptor, checksum e copia del TBIB resta originale.

Non sono stati verificati boot ROM, NAND fisica, completa inizializzazione,
scheduler, display, alimentazione, cattura o persistenza. Il simulatore DSPv7
è una build di laboratorio letta in sola lettura, non una certificazione CPU
generale. Concludere che la fotocamera si accenderà sarebbe oltre la prova.

## Ramo acquisizione con scrittura registrata

[Prove](../Risultati/HiddenMenu_RAW_Firmware/capture_gate_20261027T110543Z/verified_evidence.json),
[scenari](../Risultati/HiddenMenu_RAW_Firmware/capture_gate_20261027T110543Z/cases.json),
[verificatore](../Python_Trace_Scripts/s33_verify_raw_candidate_capture_gate.py).

Sei casi eseguono il tratto originale `0x1B9292` fino alla chiamata del writer:

| Caso | Buffer modello | Scrittura registrata |
| --- | --- | ---: |
| Originale, flag 0 | Presente | Nessuna |
| Originale, flag 1, modo 0 | Presente | 13.263.616 byte richiesti |
| Originale, flag 1, modo 3 | Presente | 26.527.232 byte richiesti |
| Candidato, flag RAM 0, modo RAM 0 | Presente | 26.527.232 byte richiesti |
| Candidato, flag RAM 1, modo RAM 3 | Presente | 26.527.232 byte richiesti |
| Candidato | Puntatore nullo | Nessuna |

La routine file `0x28D4D4` è sostituita da un registratore degli argomenti;
la continuazione `0x1B933A` termina la prova. Descriptor, puntatore buffer,
RAM e chiamante sono sintetici. Il test conferma il comportamento del ramo e
la lunghezza **richiesta**, non che un buffer reale contenga 26.527.232 byte
validi o che tali byte siano scritti su una scheda.

## Scrittura RAW: errori e conteggio

[Prove](../Risultati/HiddenMenu_RAW_Firmware/writer_20261027T110631Z/verified_evidence.json),
[scenari](../Risultati/HiddenMenu_RAW_Firmware/writer_20261027T110631Z/cases.json),
[verificatore](../Python_Trace_Scripts/s33_verify_raw_writer_errors.py).

Cinque scenari eseguono il wrapper originale `0x28D4D4`; nome, open, write e
close sono servizi simulati espliciti. Quando la fixture write restituisce
successo ma conteggio **zero**, il wrapper chiama close e restituisce comunque
successo. Quando la fixture write restituisce errore 77, il wrapper lo
propaga ma non chiama il servizio close locale. Errore open e close sono
anch'essi propagati nei rispettivi casi. Questi risultati mostrano il contratto
locale del wrapper, **non dimostrano che il backend fisico possa restituire
successo con conteggio parziale**, né che l'handle rimanga necessariamente
aperto dopo un errore: il comportamento dei livelli inferiori non è eseguito.

Il tratto precedente `0x28D5BC` può inoltre modificare bit meno significativi
del buffer. Dimensioni, packing, integrità e contenuto fotografico del RAW
restano da misurare con un frame reale.

## Stato hardware e limiti per l'installazione

Enumerazione USB e sysfs in sola lettura in questa attività non mostrano un
dispositivo Nikon collegato. Le foto storiche riportano MAIN 1.1100, ma non
dimostrano il contenuto corrente della flash o il percorso di recovery.

Mancano prove del normale avvio con il candidato, dell'effettiva capacità e
proprietà del buffer, di SD piena/errori reali, dell'integrità delle foto e
di un ripristino verificato di firmware e dati specifici della macchina.
Il candidato forza anche il dump CFA aggiuntivo e i relativi controlli non
possono essere spenti normalmente dal menu. Per questi motivi le prove
positive offline non giustificano la rimozione dello stato **NON INSTALLARE**.

Firmware originale, candidato e strumenti GNU sono stati conservati invariati;
nessuna scrittura su fotocamera o SD, né accesso NAND, è stata eseguita.
