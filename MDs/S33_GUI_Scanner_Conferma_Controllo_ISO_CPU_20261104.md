# Scanner 0x580 → controllo lista → conferma ISO — CPU emulata

Data 2026-11-04, firmware campione 1.1. [Verificatore](../Python_Trace_Scripts/s33_verify_key_scanner_control_confirm_cpu.py), [evidenze 16/16 PASS](../Risultati/GUI_S33/key_scanner_control_confirm_cpu_20261104T111558876989Z/verified_evidence.json); [regressione conferma iniettata 10/10 PASS](../Risultati/GUI_S33/key_scanner_iso_confirm_cpu_20261104T111607874346Z/verified_evidence.json). **NON_INSTALLARE**.

## Percorso e fixture

Il banco apre prima la schermata ISO tramite lo [scanner 0x700 e il manager](S33_GUI_Scanner_ISO_Transizione_Lifecycle_CPU_20261104.md), consegna il rilascio e intercetta 0x4409 come nel [banco precedente](S33_GUI_Scanner_ISO_Conferma_Setter_CPU_20261104.md). Imposta quindi come controllo attivo un **controllo sintetico** in RAM e ne impone la posizione selezionata. Lo scanner originale riceve uno snapshot sintetico con bit 12 alto e poi zero: genera `0x580`/`0x581`, che sono inseriti, estratti e consegnati esplicitamente dal banco.

Con C9BF8=0 e le altre guardie imposte, la consegna passa per 0x16A6E4, lookup classe originale 0x145020, tabella classi 0x77F728, callback classe 9 0x6406D8, tabella 0x77F97C e handler pressione 0x640F60. I byte di codice e tabelle sono verificati rispetto ai payload dopo il link. Il controllo sintetico usa flag iniziali `0x37`, ID/classe `0x00094801` e attributi `0x002D0000`, confrontati con il descrittore originale 0x989F84; il puntatore al genitore ISO, il controllo attivo, il flag di inoltro al controllo e lo stato della lista sono imposti. Per il confronto negativo l'attributo viene modificato a `0x000D0000`, togliendo solo il bit `0x00200000`. Gli altri campi del controllo non sono dimostrati equivalenti a un controllo realmente inizializzato.

Il ramo con bit attivo chiama direttamente il dispatcher 0x169D78 verso il genitore ISO usando **ID controllo 0x4801** ed evento selezionato come argomento: questa conferma non viene iniettata né posta in coda dal banco. Il ramo con bit spento invia invece `0x5000 + posizione` al genitore. L'estrazione e il dispatch dei record tasto restano espliciti; enumerazione risorse, focus, selezione iniziale, aggiornamento 0x633868, segnale, lock e 0x4409 sono stub. Come nella prova precedente, il count della tabella finestre è posto a zero prima della conferma: la richiesta di ritorno ID 0x36 non viene risolta.

## Risultati

Due ordini delle callback × quattro posizioni imposte × bit conferma spento/acceso = 16 casi. Le tracce verificano 0x640F60/0x640FD8, l'evento inoltrato e la presenza o assenza dei setter. Il conteggio e gli argomenti del controllo 0x17C150, i record coda `0x580`/`0x581` e i risultati software sono verificati.

| Posizione imposta | Voce | Bit acceso: byte debug / indice / parametro software | Bit spento |
|---:|---|---|---|
| 0 | Exit | 88 / 6 / 555, invariati | invariati |
| 1 | Auto | 0 / 0 / 0 | invariati |
| 7 | ISO 125 | 6 / 6 / 125 | invariati |
| 20 | ISO 1600 | 19 / 19 / 1600 | invariati |

I valori iniziali sono debug=88, indice=6, parametro=555. Nel caso Exit l'handler ISO viene raggiunto ma non invoca i setter; con bit spento la callback di conferma ISO non viene raggiunta. Lo stub 0x633868 è chiamato una volta nel ramo acceso e zero nel ramo spento. Il rilascio 0x581 raggiunge l'handler originale 0x640FD8 nei casi testati.

## Correzione di banco e limiti

Un primo tentativo non inoltrava al controllo: la trace mostrava che il pool originale 0x16A63C, contenente 0x367800, non era stato caricato e il codice leggeva zero dal gap. Il banco finale carica e verifica quel pool originale. La correzione è necessaria per il percorso con controllo attivo; le prove precedenti con controllo nullo o evento 0x4801 direttamente consegnato non dimostravano questo inoltro.

La prova dimostra la produzione della conferma dal **controllo sintetico e dagli eventi logici generati dallo scanner**, nelle fixture indicate. Non dimostra quale pulsante fisico corrisponda al bit 12, l'inizializzazione reale del controllo, la navigazione che sceglie la posizione, il ritorno, il rendering, l'effetto sul sensore o la persistenza. Prossimo passo: verificare navigazione/selezione effettive e ritorno, quindi seguire il parametro software nel percorso esposizione.
