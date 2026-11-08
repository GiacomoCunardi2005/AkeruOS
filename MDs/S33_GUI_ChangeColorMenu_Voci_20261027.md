# S33 V1.1 — voci candidate di ChangeColorMenu

27 ottobre 2026. Analisi statica offline dei payload originali V1.1 e confronto
con `DUMPS/MainCode.dmp`. La mappa degli indirizzi è quella del progetto per
V1.1; non si trasferisce automaticamente alla fotocamera V1.0. Nessun accesso
alla fotocamera o scrittura su SD.

L'oggetto interno `ChangeColorMenu` (ID `0xBB`) ha una risorsa di classe
`0x15`, ID `0x4800`, con quattro record da 28 byte a partire da `0x981FBC`.
Applicando a ciascun campo testo `+12` il percorso di lookup e i blocchi di
lingua già studiati, si ottengono i seguenti **testi candidati**. I campi
`+20` e `+16` indicano rispettivamente destinazione e argomento nel percorso
condizionale dell'handler di classe descritto nel [rapporto precedente](S33_GUI_ChangeColorMenu_Ritorno_CaptureMenu_20261027.md).

| Indice | Record | ID testo | Testo candidato italiano | Testo candidato inglese | Destinazione interna | Argomento |
| ---: | --- | ---: | --- | --- | --- | ---: |
| 0 | `0x981FBC` | 26 | Cambia colore | Change colors | `CaptureMenu` (`0x02`) | 5 |
| 1 | `0x981FD8` | 62 | Più chiaro/più scuro | Brighter/darker | `EVMenu` (`0x06`) | 0 |
| 2 | `0x981FF4` | 63 | Più vivace/meno vivace | More vivid/less vivid | `EVMenu` (`0x06`) | 1 |
| 3 | `0x982010` | 11 | Seleziona colore | Highlight colors | `EVMenu` (`0x06`) | 2 |

Il primo record ha flag iniziale `8`; i tre successivi hanno flag iniziale
zero. I descrittori per gli ID `2` e `6` sono rispettivamente `0x9802AC` e
`0x98056C`, con nomi `CaptureMenu` ed `EVMenu`. I campi grafici grezzi e gli
indirizzi delle stringhe sono conservati nel JSON di prova: non attribuiamo a
questi numeri una specifica icona visualizzata.

La verifica confronta i 112 byte dei record, descrittori, nomi, tabella dei
blocchi e interi blocchi di lingua 1 e 5 con il dump. Verifica inoltre gli
ID, gli argomenti e le sequenze byte dei testi. Il byte `F9` nelle due stringhe
italiane è riportato qui come «ù» assumendo la corrispondenza Latin-1; non è
una verifica generale della codifica o del font. La geometria del lookup e la
scelta condizionale dei blocchi sono documentate in [testi CaptureMenu](S33_GUI_CaptureMenu_Testi_Italiani_20261027.md).

Questi record non dimostrano che un evento fisico raggiunga la lista, quale
valore di impostazione cambi nell'ISP, né che sia disponibile il monocromatico
RAW richiesto. `EVMenu` e le sue tre varianti vanno analizzati separatamente;
il nome «Seleziona colore» non prova una conversione monocromatica. La proposta
[Mono RAW Luminance](S33_Mono_RAW_Luminance.md) rimane una pipeline da studiare,
non una funzione dimostrata in questo menu.

Riproduzione: `python3 Python_Trace_Scripts/s33_verify_gui_changecolor_items.py`.
Esito **PASS_STATIC_CONDITIONAL**; [risultati e hash](../Risultati/GUI_S33/changecolor_items_20261027T213701Z/evidence.json),
[verificatore](../Python_Trace_Scripts/s33_verify_gui_changecolor_items.py).
Non sono verificati selezione della lingua, provenienza runtime dei dati,
recapito dell'evento, valori modificati, rendering o comportamento hardware.
I candidati restano **NON_INSTALLARE**.
