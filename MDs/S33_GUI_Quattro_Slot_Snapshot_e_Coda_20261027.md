# S33 V1.1 — quattro slot GUI: snapshot e percorso condizionale

Analisi statica offline del 27 ottobre 2026. Il percorso candidato, quando le
registrazioni, le guardie e la selezione della GUI lo consentono, collega lo
snapshot degli ingressi ai quattro eventi gestiti dalla classe `0x15`. Non
identifica i quattro pulsanti fisici né il loro ordine sulla fotocamera.

## Da snapshot a evento

Il monitor `0x242104`, in condizioni specifiche, chiama `0x2B7190`: questo
usa `0x2D62D8` per costruire lo snapshot
`(read16(0x0FE70224) << 10) | read16(0x0FE70228)`. Il callback registrato può
inoltrarlo a `0x1406D0`, che passa il complemento a `0x16EC38`. Il
normalizzatore `0x16E6E0` può rifiutare la coppia: solo se restituisce 1,
`0x16EC38` chiama `0x16F86C` con emissione abilitata. Quando il gate di
quest'ultimo è attivo, il consumatore confronta la coppia con lo stato
precedente e, per i record modificati, chiama `0x16F72C`. Per i quattro indici
qui sotto, tutti inferiori a `0x61`, il valore nonzero produce l'evento
`indice << 7`; il valore zero produce lo stesso evento con bit 0 impostato.

La tabella seguente è una dipendenza dei **bit dello snapshot**, prima del
complemento, dal codice che usa due letture a 16 bit. Le posizioni 12 e 13
sono sovrapposte: ciascuna è l'OR di due bit, perché il codice non maschera
le letture prima dell'OR. Non è dimostrato che tutti questi bit siano sorgenti
fisiche indipendenti o che la loro polarità corrisponda a premuto/rilasciato.

| Slot classe | Bit snapshot | Sorgenti del bit snapshot | Tasto logico | Evento nonzero dopo complemento | Callback classe |
| ---: | ---: | --- | ---: | ---: | ---: |
| 0 | 12 | `0x0FE70224` bit 2 **OR** `0x0FE70228` bit 12 | 11 | `0x0580` | `0x631878` |
| 1 | 7 | `0x0FE70228` bit 7 | 14 | `0x0700` | `0x63195C` |
| 2 | 8 | `0x0FE70228` bit 8 | 67 | `0x2180` | `0x631A38` |
| 3 | 13 | `0x0FE70224` bit 3 **OR** `0x0FE70228` bit 13 | 78 | `0x2700` | `0x631B14` |

I quattro bit sopravvivono alla maschera `0xFE31B188` nel normalizzatore.
Nel ramo ordinario, esso conta otto bit fra cui questi quattro e rifiuta la
coppia quando più di uno è impostato. Esistono eccezioni: il gate
`[0x367898+10] == 1` salta tale verifica e anche la coppia particolare
`(0xFE003000, 0)` la evita. Queste condizioni riguardano la coppia
**dopo** il complemento e la normalizzazione, non dimostrano il comportamento
di pressioni simultanee reali. Il percorso è descritto e verificato più in
dettaglio nello [studio del normalizzatore](S33_Iride_Scrittori_Coppia_Stato_64bit.md)
e nello [studio del monitor](S33_GUI_Menu_Origine_Registro_20261027.md).

## Verso il controllo

La continuazione condizionale ricostruita per questo produttore è:

```text
0x16F72C → 0x16F6B0: fino a 10 hook e filtri
  → 0x17BC7C: ring da 128 posizioni, record destinatario / evento / argomento
  → 0x17BD4C: estrazione da WindowMgr 0x15AF0C
  → 0x169E1C → 0x169D78 → callback dell'oggetto selezionato
  → se il percorso arriva alla classe 0x15: tabella 0x77F664 → handler dello slot
```

Il ring ha una posizione riservata per distinguere pieno da vuoto: quando
l'indice successivo coincide con quello di lettura, il produttore non scrive
il record. Gli hook possono anche modificare l'ID o fermare l'inoltro;
registrazione, filtri e oggetto corrente sono variabili. Un evento generato
non è quindi una prova che venga selezionata una voce o aperto un menu.
`CaptureLiveview` usa la propria tabella e il suo comportamento non è
automaticamente quello della classe `0x15`. Il dettaglio del dispatch e delle
guardie di pagina è nel [rapporto classe](S33_GUI_Classe15_Paginazione_20261027.md).

## Verifica e limiti

Il [verificatore](../Python_Trace_Scripts/s33_verify_gui_four_slot_snapshot.py)
confronta le finestre originali e le tabelle con `MainCode.dmp`, controlla
istruzioni e destinazioni essenziali, deriva le sorgenti dei quattro bit e
verifica gli handler nella tabella delimitata. Esito **PASS statico**:
[evidenza](../Risultati/GUI_S33/four_slot_snapshot_20261027T214054Z/evidence.json),
[finestre GNU](../Risultati/GUI_S33/four_slot_snapshot_20261027T214054Z/gnu_windows.txt).
Le interpretazioni del normalizzatore e del routing completo si appoggiano
anche alle analisi citate, non a una nuova esecuzione CPU. Non sono stati
osservati registri, scheduler, display o pulsanti fisici; il mapping alto-basso
rimane sconosciuto. Firmware e GNU originali sono rimasti invariati;
candidati **NON_INSTALLARE**.
