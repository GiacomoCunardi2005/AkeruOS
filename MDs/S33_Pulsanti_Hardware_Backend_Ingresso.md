# S33 — backend di ingresso dei pulsanti hardware

Analisi statica del 21 ottobre 2026 sul firmware V1.1. Nessuna esecuzione del firmware, nessun accesso USB o alla fotocamera, nessuna scrittura. Continuazione dell'[ingresso MMIO del tasto 2](S33_S2_MMIO_e_Coda_Eventi.md) e dell'[attivazione diagnostica](S33_Attivazione_Diagnostica.md). La macchina osservata resta V1.0: gli indirizzi non sono portabili senza prova.

## Risultato

Il sottosistema che trasforma i livelli fisici in tasti logici è ricostruito: inizializzazione `0x16E838`, due sorgenti evento a interruzione, tre timer di polling, una scansione a differenze e un dispatcher `0x16EB80`. I tasti logici alimentati con sorgente identificata sono 1, 2, `0x0C`, `0x62`, `0x63`, `0x65`, `0x66` e `0x77`. La catena verso WindowMgr e gli oggetti era già documentata; qui manca ancora l'identità dei pulsanti fisici sulla V1.0 e i produttori dei tasti 9 e 11. Avanzamento complessivo invariato: circa 10%.

```text
init input manager → 0x16E838
  ├─ registra sorgenti evento 0xFFFF800C (tasto 1) e 0xFFFF800D (tasto 2) su tabella 0x424F00
  ├─ registra 3 timer via 0x14905C/0x1491B8 (periodi 100, 50, 500)
  ├─ sincronizza lo stato iniziale dei tasti (0x16F72C con flag 0)
  → timer 50: callback 0x16EAF8 (scansione a differenze di 4 sorgenti)
      → cambio: contatori e dispatcher 0x16EB80 → 0x16F72C → evento
  → timer 100: callback 0x16EE30 (tasto 0x62 / evento diretto 0x3101)
  → timer 500 ID 0xFFFF9007: callback 0x16F124 (tasto 0x77)
  → IRQ sorgente 0x800C/0x800D: fronte + verifica differita (tasti 1 e 2)
```

## 1. Inizializzazione e registrazioni

L'inizializzatore chiamante (finestra `0x16E340..0x16E354`) registra prima `0x16ECB4` e `0x16EC88` su due slot tramite `0x1405F8`, poi chiama `0x16E838`, poi servizi successivi (`0x210644`, `0x148D0C`, `0xC68B4`, `0xCF5E0`). `0x16EC88` è un produttore del tasto logico `0x0C` (sezione 4).

`0x16E838` esegue, con letterali verificati dal pool `0x16E90C..0x16E974`:

| Tratto | Operazione |
|---|---|
| `0x16E848..0x16E85E` | timer 1: `0x14905C(0x3678B6, 2, 100, 0, cb 0x16EE30)` poi `0x1491B8` |
| `0x16E866..0x16E880` | timer 2: `0x14905C(0x3678B5, 3, 50, 0, cb 0x16EAF8)`; chiamata iniziale `0x16EB80(-6, 0)` |
| `0x16E884..0x16E8B0` | registra sorgente `0xFFFF800C` con callback `0x16E988` (tasto 1) via `0x16D898` |
| `0x16E8AA..0x16E8D0` | registra sorgente `0xFFFF800D` con callback `0x16E9E8` (tasto 2) via `0x16D898` |
| `0x16E894..0x16E8A6` | legge il livello (tasto 1) e aggiorna lo stato `0x16F72C(255,1,livello,0)` |
| `0x16E8BA..0x16E8CA` | idem per il tasto 2 |
| `0x16E8D0..0x16E8EA` | timer 3: `0x14905C(0x3678F7, 0xFFFF9007, 500, 0, cb 0x16F124)`; chiama `0x210BE4` |
| `0x16E8EA..0x16E8F6` | `0x16F72C(255, 0x77, livello, 0)` per il tasto 0x77 |

Le tre basi di contesto sono `0x367898`, `0x3678B4` e `0x3678D0`; i byte di livello dei tasti 1/2 sono `0x3678C0`/`0x3678C1` (già noti come contesto+40/+41).

## 2. Tabella backend evento 0x424F00

Lettura diretta dei byte (blocco 1): header `{0x0FEF0048 pending, 0x0FEF0324 abilitazione, conteggio 16}` e 16 righe da 8 byte: `ID(16) | idx_pending(8) | idx_abilitazione(8)` più callback a +4, tutte nulle nell'immagine (riempite a runtime).

| Riga | ID sorgente | bit pending/abilitazione |
|---|---:|---:|
| `0x424F0C..0x424F8B` (16) | `0x8010` → `0x8001` | 15 → 0 |

Tasto 1 = sorgente `0x800C` (bit 11), tasto 2 = sorgente `0x800D` (bit 12), coerente col rapporto MMIO. Nel blocco 0 esistono anche letterali `0xFFFF8001` (0xF666C), `0xFFFF8008` (0x2331AC), `0xFFFF800B` (0x238B68), `0xFFFF800F` (0x32E10C, 0x3311CC, 0x331248): appartengono ad altri sottosistemi e non sono attribuiti qui.

## 3. Lettori di livello identificati

| Ingresso | Lettura | Destinato a |
|---|---|---|
| `0x17B5D4` | `ldh.di` halfword `0x0FF04020`, bit 15 | tasto logico 1 |
| `0x17B5EC` | `ldh.di` halfword `0x0FF04024`, bit 0 | tasto logico 2 |
| `0x210BC8` | `ldh.di` halfword `0x0FF04020`, bit 0 | tasto logico 0x65 |
| `0x210BE4` → `0x180A68` | `ldh.di` halfword `0xFFEF037C`, bit 6 | tasto logico 0x77 |
| `0x17B5BC` | risultato di `0x16AD38`, bit 1 | tasto 0x0C e, via `0x17B53C`, tasto 0x62 |
| `0x137774` | confronto indiretto sul byte puntato da `0x366B24`; chiamate anche `0x138D58` | tasto logico 0x63 |
| `0x18AAB4` | salto a `0x263DDC` (non seguito) | tasto logico 0x66 |
| `0x1784F4` | ritorna costante 0; il tratto successivo `0x1784F8` classifica un valore a soglie (0x5D..0x35) in livelli 0..0xC | nessun tasto: solo confronto + evento 0x7CE9 |

`0x137798` scrive il bit 4 del halfword `0x0FF04008` (`bset` su `ldh.di`): stesso blocco registro, uso non approfondito.

## 4. Produttori dei singoli tasti

| Tasto logico | Sorgente | Percorso |
|---|---|---|
| 1 | `0x0FF04020` bit 15 | callback fronte `0x16E988` + verifica differita `0x16EA3C` (timer `0x4E20` = 20000 via `0x145F28`) |
| 2 | `0x0FF04024` bit 0 | callback fronte `0x16E9E8` + verifica differita `0x16EAAC` (stesso timer) |
| `0x0C` | `0x17B5BC` | produttore `0x16EC88`, registrato dall'init chiamante via `0x1405F8` |
| `0x62` | `0x17B53C` | produttore `0x16EDDC` (chiamato all'init con 0 e dal timer 0x16EE30); il timer emette anche l'evento diretto `0x3101` via `0x169EB4` |
| `0x63` | `0x137774` | scansione a differenze + dispatcher (sorgente `0xA18`) |
| `0x65` | `0x0FF04020` bit 0 | scansione a differenze + dispatcher (sorgente `0xA16`) |
| `0x66` | `0x18AAB4` | scansione a differenze + dispatcher (sorgente `-6`); anche gestore combinato |
| `0x77` | `0xFFEF037C` bit 6 | timer `0xFFFF9007` con callback `0x16F124`; gestore combinato; produttore isolato nell'area WindowMgr `0x144A52..0x144A86` |

Il callback fronte del tasto 1 (`0x16E988`) commuta il byte di livello, registra la verifica differita e, se il byte di contesto +42 è zero, chiama `0x16F72C(255,1,stato,1)`; la verifica differita rilegge il livello e corregge. Il tasto 2 è simmetrico (già documentato). La semantica dell'unità 20000 non è risolta: polarità, antirimbalzo e numero di transizioni reali restano aperti.

## 5. Scansione a differenze e dispatcher

Il callback del timer 50 `0x16EAF8` legge le quattro sorgenti `0x210BC8`, `0x137774`, `0x18AAB4`, `0x1784F4` e le confronta con i byte memorizzati `[0x3678B4+52]`, `[0x3678B4+56]`, `[0x3678B4+53]`, `[0x3678B4+57]`. A ogni cambiamento: incrementa un contatore (`0x3678A4`/`0x3678A8`/`0x3678AC`), aggiorna il byte di livello (`0x3678CC`, `0x3678D0+0`, `0x3678B4+25`, `0x3678D0+1`) e passa al dispatcher; per la quarta sorgente chiama anche `0xD10FC` ed emette l'evento diretto `0x7CE9` via `0x169EB4` (helper `0x16E978`).

Il dispatcher `0x16EB80` seleziona per primo argomento:

| Argomento | Lettore | Tasto logico |
|---|---|---|
| `0xA16` | `0x210BC8` | `0x65` |
| `-6` | `0x18AAB4` | `0x66` |
| `0xA18` | `0x137774` | `0x63` |
| `0x9007` | `0x210BE4` | `0x77` |

Con secondo argomento non zero e stato invariato il dispatch salta; altrimenti per `0x65/0x66/0x77` passa al gestore combinato `0x16EED8`, per gli altri chiama `0x16F72C(tasto, stato, ...)`. Il gestore combinato rilegge le tre sorgenti insieme (più `0xCBEA0` e `0x138EC0`), aggiorna i byte di contesto `[0x3678D0+58..68]` e chiama `0x16F72C` per `0x65`, `0x66` e `0x77` in combinazioni condizionate dai livelli reciproci: coerente con un organo a più posizioni (es. leva ON/OFF o selettore di modalità), ma l'etichetta fisica non è provata.

## 6. Stato tasto, ID evento e formula

`0x16F72C` scrive il livello nel byte `0x446808 + 4*tasto` e, con flag di emissione, produce gli ID:

- tasti minori di `0x61`: stato non nullo → `tasto << 7`; zero → `(tasto << 7) | 1` (tasto 1 → `0x80/0x81`, tasto 2 → `0x100/0x101`);
- tasti maggiori o uguali a `0x61` (ramo `0x16F7FA`): emissione condizionata dal halfword a entry+12 della tabella stato, con uscite multiple; non ricostruito interamente, resta un confine.

Il getter `0x16F920` per gli stessi tasti legge il byte `+1` della cella di stato, non il byte `+0`: la condizione dei tasti 9/11 dell'[attivazione diagnostica](S33_Attivazione_Diagnostica.md) usa questo getter, ma in questo sottosistema non c'è alcun produttore dei tasti 9 e 11. Oltre ai 19 chiamanti qui censiti, esistono scrittori di massa della tabella stato (`0x16F86C`, ciclo `0x16F8A4..0x16F8D4`): l'elenco non è esaustivo.

## 7. Cosa apre effettivamente un pulsante

La discesa successiva è già verificata altrove: `0x16F6B0` (filtri e fino a dieci hook, byte globale `0x3678F9`, bit di abilitazione) → ring `0x17BC7C` (destinatario, ID, argomento) → task WindowMgr `0x15AF0C` → `0x169E1C`/`0x169D78` → callback dell'oggetto corrente. Quale oggetto o menu si apra dipende dall'oggetto corrente e dalla sua tabella: per il tasto 2 con CaptureLiveview selezionato, `0x100 → 0x654CD4` (marcatore S2). Nessun legame diretto tasto→menu è dimostrato senza lo stato di registrazione degli oggetti.

## Riproduzione

```bash
python3 Python_Trace_Scripts/s33_trace_button_input_backend.py
```

Lo script verifica hash e dimensioni dei 16 blocchi, i letterali del pool, i 16 halfword del registro `0x0FF040xx`/`0xFFEF037C`, l'intera tabella backend `0x424F00`, e conserva **24 finestre radicate GNU ARC700** in [gnu_verified.txt](../Ghidra_Results/ghidra_reports/button_input/gnu_verified.txt). Il [JSON](../Ghidra_Results/ghidra_reports/button_input/verified_evidence.json) registra hash, finestre, mapping sorgenti→tasti, timer e limiti. Nessun firmware eseguito.

## Limiti e prossimo confine

- Analisi statica V1.1: identità, polarità e rimbalzo dei pulsanti fisici non provati; nessuna equivalenza V1.0.
- Lettori indiretti (`0x137774`, `0x18AAB4` → `0x263DDC`, `0x16AD38`) non seguiti fino al registro periferico finale.
- Righe backend `0x8001/0x8008/0x800B/0x800F` di altri sottosistemi non attribuite; abilitazione runtime dinamica non provata.
- Produttori dei tasti 9 e 11 (gate diagnostico) non trovati in questo sottosistema: punto aperto, candidato per la prossima sessione insieme alla formula completa dei tasti ≥ `0x61` e al gestore combinato `0x16EED8`.
- Nessuna esecuzione, nessun accesso hardware, candidato firmware invariato NON_INSTALLARE. Avanzamento complessivo: circa 10%.
