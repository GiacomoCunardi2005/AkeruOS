# S33 V1.1 — fattibilità RAW puro e JPEG originale

28 ottobre 2026. Sintesi delle evidenze locali e nuova esecuzione di due verificatori esistenti. Nessuna acquisizione o scrittura su fotocamera o SD. **NON_INSTALLARE**.

## Risultato

Non è ancora disponibile una procedura dimostrata per ottenere un RAW puro e il JPEG dello stesso scatto. La pista più concreta è conservare il percorso originale di scatto e JPEG e prelevare una copia del buffer candidato RAW prima del marcatore diagnostico, rispettando proprietà, capacità e durata del buffer. È un progetto condizionale, non una patch pronta: non è dimostrato che il buffer contenga dati sensore non elaborati né che una copia prima del marcatore sia realizzabile senza interferire con gli altri consumatori.

## Evidenze e incertezze

* Nel V1.1 la voce diagnostica `Take12BitCCDRawImage` imposta il flag `0x36C26E` e il selettore `0x366F90` a 3. Il ramo individuato chiede 4208 × 3152 × 2 = 26.527.232 byte. La dimensione e il nome non dimostrano 12 bit utili, packing, CFA, linearità o provenienza dal sensore. [Analisi originale](S33_HiddenMenu_RAW_Massimo_20261027.md).
* `SaveCCDRawOnTake` condivide il flag con la voce 12 bit ma non aggiorna il selettore; azionare entrambe può spegnere il flag. Due sequenze CPU con eventi e RAM sintetici ripetute il 28 ottobre sono PASS: [evidenza](../Risultati/GUI_S33/raw_menu_toggle_cpu_20261028T143212Z/). Non dimostrano il funzionamento del menu fisico.
* Nel ramo specifico con flag esattamente 1 e contesto+0x0C diverso da 0x0B, il marcatore può sostituire il bit basso di fino a 32 byte del buffer. Con `r16=0` e stesso puntatore successivo, le posizioni appartengono all'intervallo richiesto dal writer modo 3. La nuova verifica statica condizionale è [PASS](../Risultati/HiddenMenu_RAW/marker_positions_static_20261028T143212Z/); [analisi e ipotesi](S33_Mono_RAW_Integrita_Buffer_20261027.md). Evitare questo marcatore non dimostra da solo purezza o innocuità.
* Il percorso CaptureImage stato 0x0A raggiunge staticamente l'acquisizione contenente il writer RAW e, sotto altre condizioni, pubblica descrittori verso il lavoro immagini 0x0C, che ha un ramo JPEG. È una pista per RAW e JPEG dello stesso scatto, non prova di attivazione contemporanea, ordine runtime, stesso frame o persistenza. [CaptureImage](S33_CaptureImage_Completamento_e_ImgMgr.md), [lavoro JPEG](S33_PTP_Acquisizione_e_JPEG.md).
* Lo scatto riferito il 27 ottobre ha prodotto JPEG e nessun RAW visibile. Il firmware effettivamente eseguito, il raggiungimento del ramo, il buffer e l'esito file non sono noti. Il writer può ignorare l'errore del servizio nome e il chiamante sovrascrive il ritorno del writer; un ritorno favorevole non basta a provare la persistenza. [Diagnosi](S33_Diagnosi_RAW_Assente_20261027.md).
* La prova CPU sul pool usa regioni e code sintetiche e non dereferenzia i dati; non definisce RAM fisica, capacità o durata del frame. [Prova](S33_Mono_RAW_Pool_Descrittore_Prova_CPU_20261028.md). Non è stato identificato un frame S33 reale di provenienza verificata nell'inventario delimitato. [Inventario](S33_Mono_RAW_Inventario_Locale_20261028.md).

## Passi necessari

1. Stabilire su quale firmware e percorso di scatto reale si trova il dispositivo, con evidenza di provenienza; separare stato della partizione e codice effettivamente eseguito.
2. Collegare il normale scatto al ramo e verificare buffer, formato, capacità, proprietà e sincronizzazione, inclusa l'ultima lettura del JPEG; individuare un punto antecedente a eventuali modifiche senza indovinare indirizzi RAM.
3. Solo dopo definire una copia separata e un salvataggio con nome associabile al JPEG, verificando errori, conteggio scritto, chiusura e rilettura di entrambi. Il flusso JPEG originale e i suoi controlli devono rimanere intatti.
4. Su un frame di provenienza verificata caratterizzare geometria, stride, bit, endian, CFA, livelli neri e possibili elaborazioni, confrontando più esposizioni; la sola estensione `.raw` non prova purezza né rende il file un NEF/DNG valido.

Questi passaggi richiedono ulteriori prove offline e, per concludere, osservazioni hardware autorizzate nell'ambito specifico. La richiesta di ricerca non autorizza dumper, flash, comandi NAND/vendor, reset USB o scritture SD. Nessun candidato esistente è promosso a installabile.
