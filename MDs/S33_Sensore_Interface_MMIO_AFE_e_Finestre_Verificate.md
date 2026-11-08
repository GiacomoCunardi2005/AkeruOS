# Come il software parla con il sensore: registro MMIO 0x0FF98xxx, impulsi su 0x0FF98074 e gate di clock

**Data:** 21 ottobre 2026 · **Tappe:** R0/R1 · **Esito:** PASS statico, nessun hardware toccato · **Stima complessiva: circa 10% invariata**

- Script riproducibile: [Python_Trace_Scripts/s33_verify_sensor_mmio_dialog.py](../Python_Trace_Scripts/s33_verify_sensor_mmio_dialog.py)
- Evidenze: [Risultati/Sensore_Interface_MMIO/latest.json](../Risultati/Sensore_Interface_MMIO/latest.json), finestre GNU `gnu_windows.txt` nella stessa cartella datata.
- Campione: firmware V1.1, SHA-256 `1d34e990…e62a39`; blocchi TBM verificati via `verified_payloads` (hash del manifest).

## 1. Domanda e metodo

Volevamo capire **come il firmware dialoga con il sensore d'immagine**: quale bus, quali registri, con quale protocollo. Non esisteva un rapporto dedicato; la mappa MMIO nota copriva USB/SD/clock/interrupt ma dichiarava esplicitamente «Non è stata ricostruita una mappa MMIO completa per USB, SD, sensore, LCD, DMA o clock».

Metodo, interamente statico e riproducibile:

1. **Inventario dei letterali MMIO.** Scansione di ogni istruzione `ld* rX,[pcl,off]` del listato GNU lineare dei blocchi 0, 2 e 4; per ogni pool letterale indicizzato si legge la word reale nel payload e si tengono i valori in `[0x0FE00000, 0x10000000)` (spazio periferiche ARC700 di questo SoC). Questo separa le costanti MMIO **davvero caricabili da codice** dalle coincidenze di byte grezze.
2. **Finestre GNU allineate.** Le cinque finestre decisive sono ridisassemble con allineamento verificato all'ingresso della funzione (non il solo listato lineare, che slitta di 2 byte nelle zone di pool).
3. **Stringhe di conferma.** I nomi dei registri AFE/sensore compaiono come stringhe nel modulo di tuning (payload4, `CCD_Tune_DVT.c`): verificati byte-esatti a offset fissi del contenitore.

Risultato della scansione (siti `ld [pcl]` con valore MMIO, candidati):

| Blocco | Base | Siti MMIO | Banchi rilevanti |
|---|---|---|---|
| 0 (Main) | 0x0AD800 | 9171 | 0xFE0…0xFFF (inventario completo in evidenza) |
| 2 (driver runtime) | 0x5FE800 | 347 | **0x0FF9: 149**, 0x0FFC: 158, 0x0FF0: 31, 0xFE800F4, 0xFEF014C |
| 4 (tuning) | 0x796800 | 138 | **0x0FF9: 116** (0x0FF90000–0x0FF900E0), 0xFF1, 0xFF6, 0xFFC |

Il blocco 1 (stringhe `CAPCTRL_*`, tabelle DLL, dati "ME") **non presenta pool MMIO**: è lato dati/tabelle del percorso cattura, coerente con i rapporti precedenti sull'assenza di riferimenti eseguibili.

## 2. Il dialogo runtime: registro 0x0FF98000–0x0FF98128 (payload2)

Il driver runtime del sensore/AFE vive nel payload2 e parla con un **file di registri mappato in memoria a 0x0FF98000–0x0FF98128** (47 registri distinti con siti verificati; `0x0FF98074` usato in 18 siti). Accessi sempre in **halfword con `.di`** (bypass cache, tipico MMIO) e in **read-modify-write a bitfield**: `ldh.di` → `bset`/`bclr`/`bmsk` → `sth.di`.

Due funzioni di ingresso verificate in finestra allineata:

**`0x60EDEC` — impulsi di reset/attivazione.** Carica da pool `0x0FF98074` e genera, in ordine, coppie *set+clear* sui bit **8, 3, 6, 7** (sequenza `bset`,`bclr` × 4 verificata: ogni bit viene alzato e poi riabbassato, un impulso). Poi carica `0x0FF98000` e vi scrive: `0x0100`, `0x0200`, e alza i **bit 11 e 12**. Queste sono linee di controllo a impulso, non scritture di parametri: la forma è quella di un'interfaccia seriale/pin di comando pilotata in bit-banging (clock/dati/reset/standby), ma **l'attribuzione elettrica bit↔pin non è provata**.

**`0x60EED0` — stato iniziale.** Sugli stessi registri: `bset` (senza clear) dei bit **8, 3, 6, 7** su `0x0FF98074`, poi alza su `0x0FF98000` i bit 0, 12, 8, 9, 11, 13, 14 (finestra 0x60EED0–0x60EFA0).

**Scrittore di modalità `0x60FA40+`.** Un tratto esteso (siti 0x60FA48–0x6105xx) applica parametri presi da una struct a campi a 12 bit con la stessa idiomatica RMW, distribuiti su `0x0FF9801C/20/30/34/74/90/94/…` fino a `0x0FF98124/28`: è il candidato punto in cui i parametri di scenario (guadagno AD, esposizione, timing) diventano registri. La struct è la sorgente dei parametri, non il registro stesso; provenienza e caller restano aperti.

## 3. Il dialogo di tuning: registro 0x0FF90000–0x0FF900E0 (payload4)

Il modulo di tuning (sorgente `CCD_Tune_DVT.c`, stringhe verificate) usa un **secondo file di registri a 0x0FF90000–0x0FF900E0** (34 costanti con siti). La funzione d'ingresso del payload4 (finestra allineata `0x796800`) è un writer RMW identico nell'idioma: `ldh.di` → bitfield → `sth.di`, con strobe ripetuto del bit 0 del registro 0.

Le stringhe del modulo nomino i registri lato AFE/sensore, e confermano la semantica del dialogo:

- `DeepSleep(0x00)`, `Input Buffer(0x21)`, `GPIO Mode(0x30)`, `g_uwAFE_0x74_Steps`, `0x0056==…`, `0x0057==…` e la sequenza `0x6F/0x70/0x71/0x72/0x73/0x75/0x76/0x77/0x78/0x79` con `0x7C` e `0x7D` — un indirizzamento a sotto-registri con registro dati (`0x7C`) e strobe/comando (`0x7D`).
- `IO_SetRegisterBitField(0xFEF014C,0x0003,%d)` e `IO_SetRegisterBitField(0xFE800F4,0x000f,%d)`: **clock del sensore**.

## 4. Clock del sensore: 0xFE800F4 (divisore) e 0xFEF014C (gate)

Finestra allineata `0x6515A2` (payload2): il codice scrive direttamente `0x0FEF014C`, poi su `0x0FE800F4` esegue `ldh.di` → `bclr bit0` → `sth.di` (strobe), quindi `and r0,r0,-16` e `bmsk …,3` per installare un **divisore a 4 bit nei bit 0–3 di 0x0FE800F4** — esattamente la fieldmask `0x000f` stampata dalla stringa di tuning. `0x0FE800F4` è quindi il gate/divisore di clock del sensore nel banco già noto 0xFE8 (lo stesso di `FE800F8` del rapporto bit7). `0x0FEF014C` (bit 0–1, mask `0x0003`) è il gate abilitazione associato. Coerente con le etichette BFN `Clock_Syn_Mem_Sensor_Variable_09` e con `Sensor: %d.%02dMHz(Take: …)` del menu MISC.

## 5. Architettura complessiva del dialogo

```
Applicazione (MainCode, payload0)  ──CAPCTRL_*──▶  modulo cattura (payload1: stringhe/tabelle, ME/DLL)
                                                        │ parametri di scenario
                                                        ▼
                              driver runtime (payload2) ── RMW halfword .di ──▶  registro MMIO 0x0FF98000–0x0FF98128
                                                        └─ impulsi bit su 0x0FF98074; comandi su 0x0FF98000
                              tuning (payload4, CCD_Tune_DVT.c) ── RMW ──▶     registro MMIO 0x0FF90000–0x0FF900E0
                              gate/divisore clock sensore: 0x0FE800F4 bit0-3 + strobe bit0; 0x0FEF014C bit0-1
```

In sintesi: **il sensore/AFE non ha un bus I2C software visibile nel Main**; il dialogo avviene tramite due file di registri MMIO interni al SoC con accesso halfword `.di` e RMW a bitfield, più una manciata di bit pilotati a impulsi (probabile serial/pin di controllo) e due registri di gate/divisore di clock. Il modello esatto del sensore non è identificato dai byte («By COMS Sensor», `ASICSD10P220`); il percorso dati pixel (TG/DMA, payload6/DSP) non è toccato da questa verifica.

## 6. Limiti

- Tutto è statico: nessun MMIO, sensore o fotocamera accessa; nessuna esecuzione; il candidato resta NON_INSTALLARE.
- I pool letterali sono candidati: un sito non prova raggiungibilità (senza CFG/dataflow); le finestre allineate sono decodifiche GNU, con slittamento di 2 byte nelle zone di pool segnalato nel metodo.
- Il significato elettrico dei bit (8/3/6/7 su `0x0FF98074`, 11/12 su `0x0FF98000`) è inferito dalla forma degli impulsi, non da un datasheet.
- Il ruolo di payload1 (tabelle/ME) e payload6 (DSP) nel sequenziamento resta aperto; i caller delle funzioni 0x60EDEC/0x60EED0 e della struct di 0x60FA40 non sono ancora risaliti.
- Le versioni si separano: binario V1.1 analizzato, macchina osservata V1.0; nessun indirizzo è portabile senza prova.

## 7. Prossimi passi

1. Xref/caller delle due funzioni di ingresso (0x60EDEC/0x60EED0) e della struct dello scrittore di modalità, per collegare CAPCTRL (`CAPCTRL_AFE_SetADGain`, `EnableAndWaitFieldChange`) ai registri `0x0FF98xxx`.
2. Decodifica semantica dei singoli registri `0x0FF980xx` contro i parametri noti (usADGain, usOBClamp, ulExposureTime, line count) e contro le stringhe di tuning.
3. Ruolo di payload6/DSP nel percorso dati e verifica di eventuali mirror 0x0FE9xxxx (Main) rispetto a 0x0FF9xxxx.
4. Solo dopo 1–3: eventuale prova di esecuzione con l'harness CPU del progetto, con backend registratore per i registri MMIO.
