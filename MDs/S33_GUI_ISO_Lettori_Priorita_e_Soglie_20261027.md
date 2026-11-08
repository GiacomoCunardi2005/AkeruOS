# S33 V1.1 — lettori e precedenza dei valori ISO diagnostici

27 ottobre 2026. Analisi statica del firmware V1.1; gli indirizzi sono candidati di caricamento dei payload verificati per questa versione. Il nome ISO deriva dal percorso della schermata diagnostica già ricostruito, non dalla dimostrazione che il sensore riceva un guadagno preciso.

## Precedenza dell'indice

Il setter diagnostico `0xD03B8` scrive l'indice byte in `0x365787`, poi chiama il convertitore `0x17C320`. Il convertitore conserva l'indice in `0x367BC8` e tramite `0xDE78C` scrive il valore numerico come halfword in `0x37FBF2`. Il getter `0xD03D8` legge il primo byte, mentre `0x17C3F0` legge il secondo. La conversione dei singoli indici era stata verificata in CPU emulata nella [prova diagnostica](S33_GUI_Debug_Valori_ISO_Tempo_CPU_20261027.md).

Un altro percorso, `0xCA654`, riceve un puntatore a un record e, solo se non nullo:

1. legge `0x365787` con `0xD03D8`; se il primo risultato è nonzero, richiama il getter e scrive il secondo risultato come halfword nel record a `+8`;
2. legge il **byte basso** di quel campo e chiama `0x17C320`, che riconverte e riscrive `0x37FBF2`.

Con getter stabile durante il ramo, un indice diagnostico nonzero ha dunque precedenza sul campo del record. Se la prima lettura è zero, il campo del record rimane invariato e viene convertito il suo byte basso. Le due letture sono distinte: in presenza di modifiche concorrenti non è dimostrato che restituiscano lo stesso valore. È un esempio concreto di possibile riscrittura, non prova che questo percorso si esegua dopo ogni scelta GUI o scatto. Il caller a `0x65BDF4` lo invoca, ma il lifecycle e l'ordine delle chiamate rimangono da chiarire.

Esiste anche il setter a tre argomenti `0xDE736`, che scrive byte `+0x21`, halfword `+0x22` e word `+0x24` del medesimo contesto. Non è stato dimostrato quando sia invocato né che il suo secondo argomento rappresenti un ISO valido: è un potenziale altro writer da tracciare.

## Due letture del valore numerico

- `0xD8CA4` ottiene una tabella da `0xE309C`. Se il byte `+4` del contesto restituito da `0x103F70` è zero e il byte `+0` della tabella è nonzero, `0xD8D2A` confronta la halfword `0x37FBF2` con la halfword tabella `+2`. Se il primo valore supera la soglia, carica il correttivo signed dalla halfword tabella `+4`; altrimenti il correttivo resta zero. Il valore viene sommato nella successiva espressione a `0xD8D66`. Significato e unità del correttivo e contenuto runtime della tabella non sono ancora identificati.
- Nel percorso `0xFE2B2`–`0xFE47E`, il ramo a `0xFE37A` legge la stessa halfword in `r24`, a condizione che il predicato `0x18D7D8` e il flag locale `[fp−88]` siano nonzero. A `0xFE406` verifica se `r24` è zero; nel ramo nonzero, se è inferiore a `r23`, `0xFE46E` la copia nel campo halfword `0x3663DC` (`0x3663B0 + 0x2C`). Il percorso contiene ulteriori guardie e calcoli; non si afferma che venga attivato in una modalità particolare sulla fotocamera.

`0x18D7D8` ritorna zero per gli input `0`, `2`, `3`, `0x5B`, `0x5C`; sugli altri passa per `0x18D7C0`, che nel codice originale esaminato ritorna zero, e quindi ritorna uno. La seconda lettura analoga `0xFE3AE` è preceduta da una chiamata diretta a `0x18D7C0` e da un controllo del risultato nonzero: **nel percorso originale esaminato il ramo non viene preso**. Questa conclusione non descrive eventuali modifiche, esecuzioni fuori dal normale ingresso della funzione o lo stato fisico.

## Evidenze e limiti

Il [verificatore statico](../Python_Trace_Scripts/s33_verify_iso_consumers_static.py) ha controllato i byte dei blocchi con il dump e le ancore del disassemblatore GNU, inclusi i letterali dei puntatori. Finestre e snapshot sono in [iso_consumers_static_20261027T214111Z](../Risultati/GUI_S33/iso_consumers_static_20261027T214111Z/). Ripetizione: `python3 Python_Trace_Scripts/s33_verify_iso_consumers_static.py`.

Questa prova non esegue CPU, coda eventi, ciclo AE, acquisizione, sensore o display. Gli indirizzi del contesto sono derivati dai getter originali e dalle ipotesi di caricamento verificate; non costituiscono una mappa RAM fisica. Non sono stabiliti persistenza, sincronizzazione, range valido, identità degli algoritmi, effetto sulla fotografia o sicurezza di una modifica. Nessuna operazione su fotocamera, NAND o SD. Candidati **NON_INSTALLARE**.
