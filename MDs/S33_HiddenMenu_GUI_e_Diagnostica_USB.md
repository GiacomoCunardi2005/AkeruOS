# HiddenMenu: interfaccia grafica e diagnostica USB

**Nuovo collegamento,20 ottobre 2026:** [DEBUG MODE → MSDC Card](S33_USB_MSDC_e_Accelerazione_Analisi_OS.md) modifica366B9D, consumato dal ramoUSB. È distinto da366B9F diagnostico; scheda/disco suggerita dall’etichetta, RAM/debugger e comportamento sulPC non dimostrati.

**Continuazione hardware,20 ottobre 2026:** [foto dell’utente e stato corrente](S33_HiddenMenu_Hardware_Foto_e_Versioni.md) confermano GUIINFO e pagine informative; utente conferma installazione del candidatoSD e riferisce avvio normale senzaSD. Le precedenti frasi “rendering mai visto” e “nessun hardware” descrivono la fase di analisi. Marcatore all’apertura sconosciuto,USB/uscita/recupero non certificati.

20 ottobre2026 — R0/R3/R4. **Nel firmwareV1.1 è definito un vero oggetto di interfaccia HiddenMenu**, con titolo, lista di sette voci, geometria e callback. Le prove precedenti hanno raggiunto anche la sua callback di inizializzazione. Non è ancora stata completata la visualizzazione della schermata o osservata sulla fotocamera. L’abilitazione della diagnosticaUSB segue invece un controllo distinto; aprire la radice non è dimostrato sufficiente per abilitarla.

[Verificatore appena eseguito](../Python_Trace_Scripts/s33_verify_hiddenmenu_gui_usb.py), [manifest](../outputs/hiddenmenu_gui_usb/20261020T125110Z/verified_evidence.json), [6finestre GNU](../outputs/hiddenmenu_gui_usb/20261020T125110Z/gnu_verified.txt). Comando: `python3 Python_Trace_Scripts/s33_verify_hiddenmenu_gui_usb.py`, senza-O. Strumenti GNU eseguiti in lettura; ELF temporanei fuori dalle loro cartelle. Nessuna scrittura in configurazioni, sorgenti, build o installazioni GNU.

## Prove della componente grafica

Il lookup oggetti3F5900[20] punta al descrittore9827DC, con IDinterno20, tre risorse e main7CC6DC. La risorsa98266C è di classe7, contiene il testo letterale **HIDDEN MENU** a982860 e un rettangolo di impaginazione. La risorsa982780 è di classe4 e contiene una lista di7record da32byte. La terza risorsa ha classe0A e una geometria laterale; non viene attribuito qui un significato hardware specifico.

I testi riletti dai byte originali sono:

- INFO. MENU
- ERROR CODE
- CALI. MENU
- IQ DEBUG
- DEBUG MODE
- NAND TOOL
- SKY TOOL

Le callback7CC8AC..7CC98C passano al manager1453E4 gli IDdei discendenti; i collegamenti sono già raccolti nella [mappa](HIDDENMENU_MAP.md). Il nuovo controllo conferma byte, risorse e codice senza basarsi solo sulla presenza delle stringhe.

Le [prove differenziali precedenti](MENU_DIFFERENTIAL.md) eseguono manager e dispatch fino a main7CC6DC e inizializzazione7CC714; si fermano sulla DSP3342B4 prima di completare l’inizializzazione. Questi risultati sono letti dalle evidenze storiche, non rieseguiti in questa verifica. Nel prototipo fileSD più recente lo stop è ancora precedente, all’ingresso del manager1453E4: non gli va attribuito un rendering riuscito.

È quindi fondato dire **“esiste una GUI HiddenMenu nel software”**. Rimane non verificato **“la nuova patch la visualizza e la rende usabile sul display della Nikon”**. Le coordinate interne non vengono usate per dedurre dimensioni o risoluzione fisica del display.

## Prove e limiti della diagnostica USB

Il flag diagnosticoUSB è il byte366B9F, letto nel ramo139348 dell’inizializzatore1392CC. Se vale esattamente1, e sono soddisfatti gli altri controlli precedenti, il codice chiama i registratori1DBD98 e222348. Il setter138FB0 scrive quel byte e aggiorna una copia normalizzata366BB1. Le finestre pertinenti sono state nuovamente disassemblate.

Nel rapporto [attivazione diagnostica](S33_Attivazione_Diagnostica.md) sono verificati due percorsi che richiedono1: combinazione degli stati dei tasti logici9/11 durante inizializzazione e un ramo dell’oggetto **Calibration,ID5C**, evento4405. Non sono identificati i pulsanti fisici né una sequenza USB utilizzabile sulla macchina.

**CALI.MENU ID26 e Calibration ID5C sono oggetti diversi:** descrittori984580 e40AB08. Non possiamo trasferire all’uno gli effetti dell’altro per somiglianza dei nomi. Nel grafo locale storico non c’è un collegamento letterale verso5C; quel grafo non è esaustivo e non esclude collegamenti indiretti o dinamici.

Lo stato usato dal selettore HiddenMenu è invece366880. La distinzione delle celle e degli oggetti dimostra che i controlli non sono lo stesso byte o lo stesso oggetto; non dimostra indipendenza di tutti gli effetti transitivi.

ConclusioneUSB: ci sono funzioni diagnostiche correlate alla famiglia di servizi/manutenzione, ma **non è dimostrato che basti aprire HiddenMenu per cambiare modalità o rendere disponibili nuovi comandiUSB**. Non sono provati nuovi descrittoriUSB, opcode utilizzabili, lettura/scrittura RAM daUSB o sblocco automatico. I23opcode storicamente osservati sullaV1.0 restano distinti dalle registrazioni staticheV1.1 del [dossier PTP](S33_PTP_USB_Audit_Ghidra.md).

## Nuova regola sulle cartelle GNU

Per richiesta dell’utente, da questo checkpoint le cartelle GNU, comprese le copie di laboratorio, vengono trattate come **sola lettura**: niente nuove configurazioni, sorgenti modificati, build o file di appoggio al loro interno. Gli script e i risultati del progetto rimangono fuori da quelle cartelle; l’uso di un binarioGNU in lettura non richiede modificarle.

Le modifiche precedenti ai modelli sono conservate nelle copie `work/gnu_arc700_*`; questa verifica non le sposta, cancella o aggiorna. Il binario GNU originale a `/home/jack/opt/arc700-legacy/install/bin/arc-elf32-run` conserva l’hash atteso7d6ccd1bc2291f377201e8cd1027c6ecf94d30901f13251c1c6bf647aa8a43dc. Non è stato svolto un audit completo di tutte le configurazioni dell’installazione; è stato controllato quel binario e gli strumenti objcopy/objdump usati, rimasti invariati.

Verificati nuovamente firmware originaleV1.1 e16payload, titolo/lista/classi/coordinate, descrittori26/5C, literal dei flag e6finestreGNU. Nessuna nuova prova di emulazioneUI o hardware. Prossimo: completare il percorso di inizializzazione/disegno e seguire gli effetti delle singole voci prima di attribuire modalitàUSB. Sicurezza flash e recupero non cambiano: NO-GO e circa10% funzionale invariati.
