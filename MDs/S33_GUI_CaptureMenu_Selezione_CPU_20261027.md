# S33 V1.1 — handler delle voci CaptureMenu in CPU emulata

27 ottobre 2026. Prova offline sulla CPU ARC700 GNU, con firmware originale e
MainCode verificati; nessuna operazione su fotocamera o SD. Gli indirizzi sono
quelli della mappa candidata dei payload V1.1.

## Risultato

In 15 scenari l'handler originale `0x631878` ha ricevuto direttamente un
contesto sintetico: byte `+47 = 1`, conteggio e puntatore a una copia di record
scelti. In questo ramo l'indice calcolato è sempre **zero**. I sette record
originali delle due liste sono stati copiati uno alla volta in posizione zero,
con i loro flag iniziali intatti; il servizio di attributi ha restituito `2`.
Con queste premesse l'handler ha chiamato la fixture di apertura `0x1453E4`
con i seguenti argomenti:

| Lista e posizione nel payload | ID richiesto | Argomento |
| --- | ---: | ---: |
| `0x4800`, 0 | `0x87` | 0 |
| `0x4800`, 1 | `0x9D` | 2 |
| `0x4800`, 2 | `0x9D` | 3 |
| `0x4801`, 0 | `0x87` | 0 |
| `0x4801`, 1 | `0x07` | 0 |
| `0x4801`, 2 | `0x0A` | 0 |
| `0x4801`, 3 | `0xBB` | 0 |

Le posizioni indicano la provenienza dei record, non l'indice passato
all'handler durante questa prova. I nomi degli oggetti sono identificati dai
descrittori nel [rapporto statico](S33_GUI_CaptureMenu_Destinazioni_20261027.md).

Negli altri otto scenari, costruiti modificando la copia del record `0x980188`
o i valori delle fixture:

- Conteggio zero, flag `+24` bit 0 o bit 1 impostato: ritorno 1, nessuna
  chiamata alla fixture di selezione `0x631E00` né a quella di apertura.
- Attributi 0 o 1: selezione chiamata, nessuna apertura, ritorno 0. Il controllo
  usa bit 1 del risultato della fixture `0x1450D8` con selettore `0x14`.
- ID zero: selezione chiamata, nessuna apertura, ritorno 0.
- Flag bit 10 (`0x400`): selezione e apertura avvengono, ma il codice salta
  le fixture `0x14503C`, `0x145150`, `0x817BA8`, `0x171C30` e `0x145C3C`
  del percorso precedente alla verifica attributi.
- ID sintetico `-1` e argomento `0x12345678`: apertura chiamata con ID
  `0xFFFFFFFF`, coerente con l'estensione del mezzo word con segno. Questo
  esperimento non prova l'esistenza di un tale record nel firmware.

Quando la fixture di apertura ritorna zero, l'handler restituisce comunque 1
nei casi in cui essa viene chiamata. Il significato applicativo dei codici di
ritorno non è stato stabilito. In tutti i casi lo stack è stato preservato.

## Metodo e limiti

La tabella eventi collega staticamente `0x0580` a `0x631878`; il dispatcher
non è stato eseguito. La CPU ha eseguito handler e prologo/epilogo originali;
le otto destinazioni esterne sono fixture di laboratorio che registrano le
chiamate o restituiscono valori sintetici. Le loro patch sono applicate solo
a copie temporanee dei payload mappate nel banco, mai ai sorgenti o firmware.
I campi della copia del record sono alterati soltanto negli scenari dichiarati.

Il ramo con byte contesto `+47 = 0`, che impiega `MULUDW` per calcolare un
indice dipendente dalla pagina, non è stato eseguito: il simulatore GNU fissato
in questo laboratorio non decodifica quell'istruzione. La prova non dimostra
quale record sia selezionato nelle liste reali, né inizializzazione dei flag,
recapito dei tasti, comportamento dei servizi reali o visualizzazione. Non è
una prova hardware; candidati firmware **NON_INSTALLARE**.

Riproduzione: `python3 Python_Trace_Scripts/s33_verify_gui_capture_item_cpu.py`.
Risultato **PASS**, [casi](../Risultati/GUI_S33/capture_item_cpu_20261027T175154Z/cases.json),
[fixture](../Risultati/GUI_S33/capture_item_cpu_20261027T175154Z/fixture_patches.json),
[disassemblaggio](../Risultati/GUI_S33/capture_item_cpu_20261027T175154Z/handler_disassembly.txt),
[verificatore](../Python_Trace_Scripts/s33_verify_gui_capture_item_cpu.py).
