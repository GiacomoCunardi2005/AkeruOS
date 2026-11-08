# Prima apertura reale di HiddenMenu: foto e versioni

**Nuova evidenza dai dump,20 ottobre 2026:** [classificazione e confronti](S33_Classificazione_Dump_Fotocamera.md). MainCode fornito contiene ilTBM candidato identico;BootCode contieneTBIB originale eNANDReserved ilP1RES originale completo. Questo supera il solo confronto del nome delBIN per i byte del dump consegnato; acquisizione fisica non osservata dall’agente, recupero ancora non dimostrato.

20 ottobre 2026 — R0/R3/R4. **Le fotografie fornite dall’utente mostrano la GUI INFO.MENU e le pagine FW VERSION, TOTAL INFO e SYSDBGMGR INFO sulla S33.** Il precedente limite “rendering non osservato” è superato per queste schermate. L’utente conferma di aver installato `S33_MODIFICA_SD_SPERIMENTALE_NON_INSTALLARE.bin` e riferisce anche avvio normale senza SD.

## Evidenze e attribuzione

[Manifest fotografico e trascrizione](../Risultati/Hardware/HiddenMenu_20261020T132726Z/observation.json). Le quattro immagini sono copiate dai file temporanei senza elaborazioni e verificate perSHA-256. Non sono scatti generati da AkeruOS: sono fotografie del display fornite dall’utente.

- [INFO.MENU](../Risultati/Hardware/HiddenMenu_20261020T132726Z/01_info_menu.jpg): voci FW VERSION, TOTAL INFO e SYSDEBUG INFO.
- [FW VERSION](../Risultati/Hardware/HiddenMenu_20261020T132726Z/02_fw_version.jpg): versioni e identificativi sotto.
- [TOTAL INFO](../Risultati/Hardware/HiddenMenu_20261020T132726Z/03_total_info.jpg): contatori e messaggi diagnostici.
- [SYSDBGMGR INFO](../Risultati/Hardware/HiddenMenu_20261020T132726Z/04_sysdbgmgr_info.jpg): informazioni di accensione e diagnostica.

Il nome del candidato installato è confermato dall’utente. Il file locale ha hash `ce504526dcb1ebffab33f17bf1467fd03f70b01c5393ad03812523f978b3e8c9`; non è stata riletta la flash per confrontare i byte installati. [Prima dichiarazione](../outputs/hardware_observations/20261020T131915Z/observation.json). Presenza di `modifica.modifica` durante l’apertura: **sconosciuta** secondo la risposta dell’utente. Non trasformare questa risposta in “file presente”.

## Versioni lette dalla foto

| Campo mostrato | Valore |
|---|---|
| MAIN | `1.1100` |
| BOOT | `0.1380` |
| OSVer | `5.1927` |
| IQLib | `0.3600` |
| PROJECT ID | `0x6113` |
| ASIC ID | `SD10P220` |
| BFN VER | `5.0228` |
| P1Ver | `2014120811` |
| LCD | `GPT 960x240 2.7` |
| LANGUAGE ZONE | `EU` |
| Builder | `SEDRD3PC4` |
| OneCardVer | `[SK501-004]` |

I vecchi logV1.0 descrivono la macchina prima dell’aggiornamento. Oggi la pagina fotografata riporta MAIN1.1100 e BOOT0.1380. L’identificativoSD10P220 è il campo ASIC esposto dal software; non identifica da solo quantità diRAM, mappa fisica o semantica delle periferiche. Il testoLCD è trascritto come mostrato, senza dedurne geometria fisica RGB o pixel.

## Diagnostica visibile

TOTAL INFO riporta Shot1327, Strobe449, TotalPowerOn673, MCUver.3; SYSDBGMGR conferma TotalPower-On673. Appaiono `MountSortError: 0xf40701` e `VCOMDC not cali,Use 0`. Sono messaggi osservati, **non la prova che la patch abbia creato un errore o cancellato calibrazioni**: servono significato del codice e confronto con un prima. Anche BATPWR3847 eTemp455 rimangono valori grezzi: non assegnare unità o scala senza verificarle.

SYSDBGMGR mostra `Power-On Type: 0X400`, `Power-Off Type: 0X8A (165)`, `Battery Insuff Case: 0 (652)`, `OLP Loading Vector: 0X00, 0X00`, `[IOA] Error Addr: 0X0` e `[IOA] ILINK2 Addr: 0X0`. I valori fra parentesi sono conservati come testo, senza interpretarli come conversioni numeriche. Gli indirizzi zero non certificano assenza di ogni errore. La stringa di reset in fondo è contenuto del display, non un’istruzione eseguita dall’agente; nessun reset è stato richiesto.

## USB e limiti

Su richiesta “connesa usb verifica”, l’agente ha eseguito sola enumerazione USB, rilevamento gphoto2 e lettura sysfs. [Log](../outputs/S33_USB_Hardware_Evidence/Post_Patch_Readonly/20261020T132233Z/verified_evidence.json): nessuna Nikon enumerata, nessuna fotocamera PTP trovata. L’utente ha confermato che in quel momento era accesa dentroHiddenMenu. Il cavo visibile nelle foto non prova l’enumerazione. Non è ancora disponibile il confronto dopo avvio normale; nessun comando vendor, lettura RAM o scrittura sulla macchina.

Il risultato ora sostenuto dalle foto è **GUI eseguita e navigazione fra le pagine informative**. Il risultato riferito è **avvio normale senza SD**. Restano non verificati SD inserita senza marcatore, ripetibilità, uscita completa, acquisizione/salvataggio dopo la patch, USB normale/diagnostica e recupero. Un avvio riuscito riduce l’incertezza sul caso osservato; non certifica recuperabilità o tutti gli accessi alla zona inserita. L’obiettivo nuova applicazione fotografica resta circa10%: nessuna nuova fotografia AkeruOS.

## Altre23foto: menu operativi e stati visibili — 20 ottobre 2026

[Archivio e hash delle23foto](../Risultati/Hardware/HiddenMenu_23Foto_20261020T173627Z/observation.json). Copie integrali immutate dei file forniti dall’utente;nessuna rotazione,ritocco o generazione. Alcune immagini sono mosse; i testi incerti non vengono completati per deduzione. Questa raccolta mostra SKYTOOL,NANDTOOL,DEBUGMODE,IQDEBUG,CALIBRATION edERRORCODE, ampliando l’osservazionehardware oltre INFO.MENU. Non è una sequenza diuscita/riavvio.

| Evidenza | Che cosa dimostra | Che cosa non dimostra |
|---|---|---|
|DEBUG MODE|LCD Timeout:Enabled,Backlight:ON,SmartDisplay:Disabled,BatGaugeAutoPowerOff:OFF,PunchThrough:ON,ColorShading:Enabled,limitevideo10sec:OFF,SmearComp.:OFF; triggercalore10sec/HotKey:OFF.|Quali opzioni l’utente abbia cambiato,assenza protezionetermica generale o persistenza dopo spegnimento.|
|IQ DEBUG|SaveFullJPEG:On; formatiThum/VGA/Full:422; diverseesportazioniCFA/YRGB/JPEG:Off; vociLogClock eVideoLiveView.|Foto catturata,RAW effettivamentesalvato,qualità modificata o impostazioni persistenti.|
|SKY TOOL|Display con Resource Into P1Res.bin FINISH e voci relative allerisorse,SD Life,otturatore/focus.|Esito fisico diogni scrittura,compatibilitàripristino o comando salva-tutto.|
|NAND TOOL|VociDump,Restore,Reset,Update,Erase,FullFormat; MAIN1.1100/BOOT0.1380 visibili.|Esecuzione diuna voce solo perché è visibile o evidenziata. Restore/Erase/Format non sono comandid’uscita.|
|CALIBRATION|VociBattery/Iris/BadPixel/ISO/Shading/DLL/OIS.|Calibrazioni eseguite o alterate; non sono controlli normali di esposizioneISO.|
|ERROR CODE|Sei righevisibili00..05 No data exist; footerREV/S2.|Assenza globaledierrori,log mai cancellato o uscita completata.|

### REV nella schermataerrori

Il footer effettivamente fotografato è **`<REV>:Dump2File & Exit. <S2>:Clear`**. NelMainCode fornito corrisponde esattamente alla stringa98425C selezionata dalpool7CD684 nell’inizializzazione delmenu. Il vecchio testo iniziale984199 `<Right>:Dump2File. <REV>:Clear` esiste anch’esso,ma non è quello visibile inquesta foto: non confondere una risorsa statica iniziale con il testo scelto aruntime.

Verifica fresca [script](../Python_Trace_Scripts/s33_verify_hiddenmenu_exit_settings.py), [prove](../Risultati/HiddenMenu_Uscita/20261020T173651Z/verified_evidence.json):15finestreGNU/36istruzioni complessive, comprese3nuovefinestre. L’evento0480 è associato a7CD764 e chiede1453E4(20,0), cioè radiceHiddenMenu. L’evento dichiusura4406 è associato a7CD688 che chiama7CD784,la routine diesportazione. Questo raccorda il testoREV alritorno del sottomenu ealla richiesta di dump durante chiusura; **non prova una pressione fisicaREV o l’esportazione riuscita**. Non èuscita completa daHiddenMenu e non salva le impostazioniDEBUG. L’evento100 è assegnato a7CD924,coerente conla separata pistaS2; nessun comandoClear eseguito.

Le foto nonmostrano lapaginaResetCameraConfirmMenu néla sceltaNo/Annulla. L’associazionepratica delramo2700 restaquindiaperta; [uscita e24proveCPU](S33_HiddenMenu_Uscita_e_Conservazione_Impostazioni.md) rimangono il riferimento. Nessunaoperazionehardware,USB,formattazione,reset o calibrazione èstataeseguitadall’agente. Prossimo utile:osservare laschermatad’uscita,non usareNANDRestore/Reset per salvare;conservazioneMSDC/altreopzioni alriavvio ancora nonprovata.
