# Ritorno ISO verso un descrittore sintetico di esposizione

Il 29 ottobre 2026 ho combinato la [richiesta ISO del modello](S33_GUI_Modello_Apertura_ISO_Manager_CPU_20261029.md) con il [precedente esperimento di ritorno contestuale](S33_GUI_ISO_Ritorno_Consumo_Dopo_Transizione_CPU_20261029.md). La destinazione speciale è ora un descrittore sintetico a `0x2050000`: copia di CaptureMenu con risorse azzerate e callback che ritorna zero. Rappresenta un oggetto di laboratorio per il futuro sottomenu esposizione; non disegna e non contiene ancora la logica del menu.

Nel [banco](../Python_Trace_Scripts/s33_verify_gui_model_iso_return_exposure_cpu.py), il tasto logico 14 genera `0x700`, consegnato dal banco al modello C in schermata esposizione; la richiesta ISO viene tradotta in apertura dell'ISO originale `0x3F`. Per i casi speciali, il banco arma il flag sintetico solo se azione, risultato di apertura e descrittore ISO coincidono con i valori attesi. Per confrontare la diagnostica ordinaria, altri casi impongono flag 0 oppure 2.

La copia di laboratorio del callback ISO contiene un trampoline sperimentale: con flag 1 apre direttamente il descrittore sintetico tramite `0x145180`, e cancella il flag solo se il manager restituisce 1, il descrittore corrente è quello sintetico e il flag resta 1. Negli altri casi usa il percorso originale verso il menu diagnostico `0x36`. Non è una modifica del firmware originale o una patch installabile.

| Caso | Prima conferma: destinazione / flag | Seconda conferma imposta dal banco |
|---|---|---|
| ISO 125 o Exit, flag 0 | menu diagnostico / 0 | riapertura ISO → diagnostico / 0 |
| ISO 125 o Exit, flag 1 | descrittore sintetico / 0 | riapertura ISO → diagnostico / 0 |
| ISO 125, flag 2 | diagnostico / 2 | riapertura ISO → diagnostico / 2 |
| ISO 125, flag 1 e guardia manager forzata | ISO rimane corrente / 1 | guardia rimossa e conferma ripetuta → descrittore sintetico / 0 |

[Sei sequenze PASS](../Risultati/GUI_S33/model_iso_return_exposure_cpu_20261028T234717Z/verified_evidence.json), 155.870 istruzioni: controllati richiesta modello, apertura ISO, valori software ISO, descrittore e flag dopo le due conferme, stack. [Casi](../Risultati/GUI_S33/model_iso_return_exposure_cpu_20261028T234717Z/cases.json), [modifiche e fixture](../Risultati/GUI_S33/model_iso_return_exposure_cpu_20261028T234717Z/fixture_patches.json) e [traccia](../Risultati/GUI_S33/model_iso_return_exposure_cpu_20261028T234717Z/cases.trace). Un [tentativo precedente](../Risultati/GUI_S33/model_iso_return_exposure_cpu_20261028T234657Z/verified_evidence.json) è FAIL perché l'assert del numero di chiamate era sbagliato; non è presentato come successo.

Il flag e la sua attivazione sono nel banco, senza proprietario o ubicazione RAM fisica verificati; il confronto della guardia riguarda il **ritorno**, non il fallimento dell'apertura ISO iniziale. Lifecycle, controlli e vari servizi sono fixture; selezioni ed eventi di conferma sono iniettati. La prova non dimostra concorrenza, annullamento, disegno, tasti fisici, AE, scatto o persistenza, né la conservazione del comportamento diagnostico per tutti i contesti. **NON_INSTALLARE**.
