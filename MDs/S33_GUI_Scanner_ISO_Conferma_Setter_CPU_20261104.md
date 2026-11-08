# Scanner → ISO → conferma e setter software — CPU emulata

Data 2026-11-04, firmware campione 1.1. [Verificatore](../Python_Trace_Scripts/s33_verify_key_scanner_iso_confirm_cpu.py), [evidenze 10/10 PASS](../Risultati/GUI_S33/key_scanner_iso_confirm_cpu_20261104T111202102037Z/verified_evidence.json), [regressione apertura/lifecycle 4/4 PASS](../Risultati/GUI_S33/key_scanner_lifecycle_real700_cpu_20261104T111208995265Z/verified_evidence.json). **NON_INSTALLARE**.

## Sequenza e fixture

La prova estende il [banco di apertura ISO](S33_GUI_Scanner_ISO_Transizione_Lifecycle_CPU_20261104.md). Lo scanner originale genera pressione `0x700` e rilascio `0x701`; il banco estrae entrambi, consegna la pressione al dispatcher e verifica l'inizializzazione originale del descrittore diagnostico ISO 0x989FCC. Poi consegna esplicitamente il rilascio estratto alla finestra ISO, estrae la notifica `0x4409` rimasta in coda e la consegna a uno **stub** del suo handler 0x16A29C. Questa verifica non esegue il rendering.

Il banco impone poi il controllo sintetico come controllo attivo, imposta la posizione selezionata, **inietta** il post `(0, 0x4801, 0)`, lo estrae e lo consegna al dispatcher originale. Non è provato che una pressione fisica o la navigazione della lista generino quel post. La callback ISO originale 0x7D252C seleziona l'handler originale 0x7D25B0, che usa getter originale 0x6410F4, record originali e, dove previsto, setter 0xD03B8 → convertitore 0x17C320 → setter parametro 0xDE78C. I byte delle finestre caricate sono confrontati con i payload verificati dopo il link.

CAD5C=2, CD9C8=0x3F, indice ISO software iniziale 6, controllo e selezione sono fixture; restano simulati enumerazione, focus, selezione, filtro post speciale, lock e segnale. Prima della conferma il banco imposta a zero il count della tabella finestre: la richiesta di uscita `0x1453E4(0x36,0)` emessa dall'handler non trova una destinazione e non esegue la transizione di ritorno. Questo è un limite deliberato del banco, non il comportamento dimostrato della camera. Due ordini delle callback sono testati.

## Valori osservati

Ogni riga è provata con entrambi gli ordini. Prima della conferma il byte debug a 0x365787 è inizializzato a 88, l'indice software a 0x367BC8 a 6 e la halfword a 0x37FBF2 a 555. L'indice della tabella e il parametro convertito sono valori software; i nomi derivano dai record originali.

| Posizione sintetica | Voce/condizione | Byte debug | Indice software | Halfword parametro |
|---:|---|---:|---:|---:|
| 0 | Exit | 88 | 6 | 555 |
| 1 | Auto | 0 | 0 | 0 |
| 7 | ISO 125 | 6 | 6 | 125 |
| 20 | ISO 1600 | 19 | 19 | 1600 |
| 24 | Fuori dal count 24 | 0 | 0 | 0 |

La traccia verifica il percorso dei setter per Auto/125/1600 e per il caso fuori intervallo; verifica anche che i setter non vengano chiamati per Exit. Il caso fuori intervallo è avverso e sintetico: il getter restituisce zero, che conduce al valore Auto nel banco; non si afferma che lo stato sia raggiungibile nella GUI reale. La traccia verifica inoltre la consegna degli eventi `0x701`, `0x4409`, `0x4801`, due ingressi nel wrapper 0x1453E4 e la richiesta di ritorno ID 0x36; la richiesta non risolve una finestra con count zero.

## Limiti e seguito

Non sono dimostrati la navigazione dell'utente, la produzione reale dell'evento di conferma, la consegna reale del segnale, il completamento del ritorno, il rendering, il guadagno del sensore o la persistenza. I valori osservati sono RAM del simulatore e non una misura della fotocamera. Prossimo passo: verificare la produzione della conferma e il ritorno con manager/lifecycle appropriati, quindi seguire i valori software fino ai consumatori di esposizione e confrontare gli altri parametri richiesti.
