# S33 — ordine dei callback TBIB e confine della pulizia

Analisi statica V1.1, 19 ottobre2026. Continuazione dell'[uscita kernel TBIB](S33_Uscita_Kernel_TBIB_e_Ripristino_Contesto.md). Nessun accesso hardware.

## Risultato

Nelle quattro registrazioni originali di `0x0103FE30`, le liste di callback sono ordinate per una chiave numerica: la lista0 in ordine decrescente, la lista2 in ordine crescente. **Nella lista finale2 il trasferimento al TBM, chiave1, precede il callback di rilascio risorse runtime, chiave120.** Non esiste un callback di questa seconda lista iniziale che debba completare quel rilascio prima del salto.

Inoltre, se il runtime TBM ritorna normalmente al suo prefisso, entra nel ciclo locale `0x000BB5E0` anziché ritornare al TBIB. Il rilascio successivo della lista2 e il secondo hook di uscita non possono quindi essere considerati passi della normale transizione osservata.

Questo attribuisce l'ordine software delle registrazioni note. Non prova che non esistano altre registrazioni durante l'esecuzione, né che cache, DMA o controller siano già fermi.

## 1. Le quattro registrazioni originali

Il corpo `0x0103FE30` passa questi record ai due registrar e poi chiama il consumatore della lista0:

| Record | Chiave decimale | Callback | Registrar | Lista con campo+8 iniziale0 |
|---|---:|---|---|---:|
| `0x01042610` | 1 | `0x01000C10`, trasferimento TBM | `0x0103E028` | 2 |
| `0x01043AE4` | 121 | `0x0103B4D0` | `0x0103E018` | 0 |
| `0x0104444C` | 120 | `0x0103BE1C`, rilascio condizionale | `0x0103E028` | 2 |
| `0x01044458` | 120 | `0x0103BE48` | `0x0103E018` | 0 |

Ogni record ha tre parole: chiave, indirizzo del callback e campo inizialmente0. La chiave non viene identificata come priorità dei task o degli interrupt.

Il terzo campo ha un uso legato alla fase: prima dell'inserimento il registrar ne legge il byte basso per scegliere la lista; poi il servizio inferiore lo sovrascrive con il puntatore al record successivo. Non va trattato come parametro immutabile o come selettore da riusare liberamente dopo l'inserimento.

Le quattro teste a `0x01044BA0` e la guardia a `0x010417B8` sono0 nei byte originali. I modelli partono da quello stato iniziale e da una sola registrazione per record.

## 2. Regole di inserimento verificate

Entrambi i registrar raggiungono `0x0103DFE0`. Con i quattro record sopra:

- Il registrar `0x0103E018` passa indice0 e direzione0; l'inserimento continua mentre chiave nuova < chiave corrente: ordine **decrescente**.
- Il registrar `0x0103E028` passa indice2 e direzione1; l'inserimento continua mentre chiave corrente < chiave nuova: ordine **crescente**.

I confronti `brlo` sono senza segno. Le chiavi uguali non fanno proseguire la ricerca: il nuovo record viene inserito prima di quello uguale già presente.

Ordini ricostruiti interpretando le istruzioni di inserimento:

```text
lista0: 121 / 0x0103B4D0 → 120 / 0x0103BE48
lista2:   1 / 0x01000C10 → 120 / 0x0103BE1C
```

La verifica confronta512 liste sintetiche, lunghezze0..16, entrambe le direzioni, chiavi duplicate e bordi32bit. Il risultato è confrontato con un ordinamento indipendente che tiene conto dell'inserimento prima delle chiavi uguali. Non vengono eseguiti i callback reali.

## 3. Inizializzazioni e rilasci individuati

Il consumatore `0x0103E090` stacca la testa della lista0 e invoca il callback di ogni record nell'ordine collegato. Nei corpi noti:

| Callback | Chiamate osservate |
|---|---|
| `0x0103B4D0` | passa un puntatore originale al servizio `0x0103DECC` |
| `0x0103BE48` | chiama `0x0103DECC` con `0x010967A0`, `0x010967A4`, `0x010967A8` |
| `0x0103BE1C` | sotto tre guardie byte, chiama `0x0103DF0C` con le stesse tre celle |

Il servizio `0x0103DF0C`, quando trova un handle interno nonzero nel percorso esaminato, richiama un servizio inferiore, modifica i collegamenti e azzera l'associazione del chiamante. La verifica conserva quel confine: non assegna a tutti gli oggetti un tipo pubblico, né prova la riuscita o l'effetto fisico di ogni rilascio.

L'accoppiamento delle tre celle collega i callback di preparazione e di pulizia delle risorse runtime. Non dimostra una procedura generale di spegnimento SD, sensore o altri controller.

## 4. Guardia e distacco prima del trasferimento

Il consumatore finale `0x0103E06C`:

1. legge la guardia `0x010417B8` ed esce se nonzero;
2. la imposta a1;
3. legge la testa della lista2 e azzera la testa pubblicata;
4. invoca il callback del primo record, quindi avanza al successivo se ritorna.

Il modello verifica tre casi: entrambi i callback simulati ritornano; il primo termina la simulazione come trasferimento senza ritorno; un secondo ingresso dopo il consumo non esegue callback. **Guardia e testa sono già modificate prima del trasferimento.** Un nuovo ingresso nel consumatore non è quindi un meccanismo automatico di retry della transizione.

I callback simulati servono a controllare il dispatcher. Non dimostrano che un callback reale conservi qualsiasi stato arbitrario o che una lista modificata concorrentemente resti valida.

## 5. Ritorno del runtime TBM: ciclo locale

Estesa anche l'evidenza del [prefisso TBM](S33_Passaggio_TBIB_TBM_e_Ingresso_CPU.md):

```text
0x000BB5D0  chiama 0x000AD890
0x000BB5D8  salta a 0x000BB5E0
0x000BB5E0  flag 1
             tre nop
0x000BB5F0  salta a 0x000BB5E0
```

Il tratto è decodificato ripartendo dagli ingressi corretti e separando il pool a `0xBB5DC`. Non viene attribuito un effetto hardware completo a `flag1`; è provato il ciclo di controllo locale.

Con l'ingresso originale `0xBB540`, il ritorno ordinario del runtime non riprende dunque il callback TBIB. Il caso in cui tutti i callback del modello ritornano resta una prova astratta del dispatcher, non il comportamento del prefisso TBM del campione.

Di conseguenza il callback `0x0103BE1C`, successivo al trasferimento nella lista2 nota, e il secondo hook di uscita a `0x0104176C` non possono essere usati come prova di una pulizia già completata prima del TBM. Ciò descrive l'ordine originale; non viene classificato come un difetto del firmware.

## Evidenze e continuazione

[Script ordine](../Python_Trace_Scripts/s33_trace_tbib_callback_order.py), [JSON ordine](../Ghidra_Results/ghidra_reports/tbib_callback_order/verified_evidence.json), [GNU ordine](../Ghidra_Results/ghidra_reports/tbib_callback_order/gnu_verified.txt). Riproduzione: `python3 Python_Trace_Scripts/s33_trace_tbib_callback_order.py`.

Verificati identità contenitore/TBIB, checksum, roundtrip ELF, **11 finestre, 30 istruzioni chiave, 10 parole, 4 record e 512 ordinamenti**, oltre ai tre casi del consumatore. La verifica del passaggio TBM è estesa a **16 finestre e48 istruzioni**, conservando i16 blocchi identici, i2 roundtrip e i512 casi di propagazione.

Restano da censire registrazioni successive o indirette e da verificare il protocollo dei controller prima della transizione. La residenza delle regioni, il punto d'inserimento AkeruOS e il recupero restano aperti; nessuna nuova esecuzione hardware.

## Continuazione — chiamate precedenti all’uscita kernel

Il [rapporto sul task MCU e INFO](S33_Handshake_MCU_TBIB_e_Dati_INFO.md) risolve il protocollo bit30/31 e la copia di48byte nel blocco condiviso prima dell’uscita kernel. Il timer viene chiamato senza confronto dell’esito prima dell’ack; il ritorno0 del wrapper non prova arresto hardware. Produttori delle coppie INFO e consumatori TBM ancora aperti.
