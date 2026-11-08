# AkeruUSB — evento close e attese originali

27 ottobre 2026. Ricerca offline del dump RAM. **NON_INSTALLARE**.

La notifica di classe `19199C`, eseguita su CPU GNU ARC700, raggiunge il
resolver e il setter originali dell'evento USB `02200001`. Un secondo banco
esegue anche il wait originale con le maschere dei trasferimenti. Record e
scheduler sono preparati dal banco: non è un boot Nikon.

Il bit close `00010000` soddisfa entrambe le attese in modalità *any*:
`00019000` per TX e `001DA000` per RX. Con auto-clear disattivato la query
successiva legge ancora il bit; con auto-clear attivato dal banco, il wait
lo rimuove e la query non lo vede. La configurazione runtime sulla
fotocamera rimane da verificare.

## Evidenze riproducibili

```sh
PYTHONDONTWRITEBYTECODE=1 python3 Python_Trace_Scripts/s33_verify_akeru_usb_class_event.py
PYTHONDONTWRITEBYTECODE=1 python3 Python_Trace_Scripts/s33_verify_akeru_usb_class_event_wait.py
```

- [Banco notifica e setter](../AkeruOS/tests/usb_class_event_gnu_test.c),
  [verificatore](../Python_Trace_Scripts/s33_verify_akeru_usb_class_event.py),
  [manifest CPU](../Risultati/AkeruUSB_RAM_Debug/Class_Event/20261027T105705Z/verified_evidence.json):
  6 scenari, 4.312 istruzioni, uscita 0, nessun fault.
- [Banco con wait](../AkeruOS/tests/usb_class_event_wait_gnu_test.c),
  [verificatore](../Python_Trace_Scripts/s33_verify_akeru_usb_class_event_wait.py),
  [manifest CPU](../Risultati/AkeruUSB_RAM_Debug/Class_Event_Wait/20261027T105845Z/verified_evidence.json):
  6 scenari di notifica e 8 attese immediate, 12.964 istruzioni, uscita 0,
  nessun fault. SHA256 manifest:
  `01d7b99480cec7fd5f76e9ee3ff67007ab9ba5c0d9d55359294e3830a6686720`.

Il verificatore confronta le sezioni dell'ELF con i byte originali V1.1,
controlla le entrate nella traccia e ricontrolla gli input. In seguito sono
stati verificati tutti i 57 e 60 file dei due manifest e i rispettivi 17
input. Le esecuzioni iniziali `105754Z` e `105803Z` restano FAIL: il controllo
di memoria definita aveva rilevato fetch del decoder oltre le sezioni del
banco. Sono state estese le sole sezioni originali copiate; nessun byte
firmware è stato modificato.

## Record e notifica

Nel payload V1.1 il record originale è alla posizione 40 della tabella a
`372A48`, indirizzo `373308`: magic `45564E4C`, ID `02200001`, flags iniziali
`2`. Il costruttore `158C30` passa il bit 0 dei flags al costruttore inferiore;
il valore iniziale seleziona 0. Questo dato statico non dimostra che l'oggetto
sia inizializzato o mantenga tale configurazione a runtime: nel banco il
bit 31 di attivazione e l'oggetto sono preparati.

I sei scenari combinano record valido, inattivo o magic alterata con close
abilitato/disabilitato. `19199C → 1910C4 → 158CBC → 158C8C`:

| Record preparato | Ritorno diretto da `19199C` | Campo bit evento |
|---|---:|---|
| Valido e attivo | `0` | `A5000002 → A5010002` |
| Inattivo | `00200304` | invariato |
| Magic alterata | `00200307` | invariato |

Con close abilitata, l'endpoint fixture viene chiamato prima dell'evento e
restituisce -7; il contesto viene comunque azzerato. La notifica è chiamata
direttamente: la prova precedente separata mostra che il wrapper pubblico
`278B0C` restituisce comunque 0. Gli errori sono iniettati nel record e non
descrivono uno stato osservato su hardware.

Per il record valido `23C758` esegue l'OR conservando gli altri bit. La query
`158E28` legge il risultato e `158CE0 → 23C8AC` cancella il bit richiesto.
La coda waiter è vuota; endpoint, logger e stato kernel/task sono fixture.

## Wait immediato e interpretazione

Per ogni combinazione TX/RX e auto-clear 0/1, ripetuta nei due casi di close
iniziale, il banco pubblica nuovamente il bit tramite `19199C` originale e
chiama `158D04(HANDLE, mask, 0, 0)`. La catena originale
`158D04 → 23C938 → 2C9994` ritorna 0 nelle 8 prove, senza accodamento:

| Maschera | Auto-clear | Bit `00010000` letto dopo il wait |
|---|---:|---|
| TX `00019000` | 0 | presente |
| TX `00019000` | 1 | assente |
| RX `001DA000` | 0 | presente |
| RX `001DA000` | 1 | assente |

Il valore è osservato anche tramite la query originale `158E28`. Con
auto-clear 1 viene applicata la maschera di wait, non solo il bit close;
nel banco non erano presenti altri bit corrispondenti.

La [prova precedente dei trasferimenti](../Risultati/AkeruUSB_RAM_Debug/Transfers/20261024T145936Z/verified_evidence.json)
esegue separatamente i consumer TX/RX con servizi evento simulati: quando
la loro query restituisce bit 16, entrambi mappano il risultato a `02200341`.
La disassemblazione originale mostra query dopo wait e test di bit 16 a
`1909DA`/`190868`. **Inferenza:** con auto-clear 1 e senza nuova pubblicazione
intermedia, la query non vedrebbe il bit close. Consumer completo e nuovo
wait originale non sono ancora stati eseguiti nello stesso scenario: non
si afferma un falso successo hardware o comportamento normale Nikon.

## Limiti e prossimi passi

La prova riguarda un evento già presente e una lista waiter vuota. Non
verifica task realmente sospeso, risveglio, competizione fra eventi, IRQ,
trasferimenti fisici, controller o arresto DMA. I 128 MiB sono RAM sintetica,
il modello DSP GNU è provvisorio e non costituisce una mappa fisica.
Integrazione completa dei consumer TX/RX con wait/evento originali, binding
al task, cache e whitelist RAM fisica restano aperti, insieme a residenza,
boot e recupero. Nessun accesso alla fotocamera o installazione eseguiti.
