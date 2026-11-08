# AkeruOS: piano per esposizione manuale (diaframma, ISO, otturatore) e modalità Av/Tv

**Data:** 21 ottobre 2026 · **Tappe:** R0/R1 (progetto di integrazione) · **Esito:** studio di fattibilità su ancore statiche verificate · **Stima complessiva: circa 10% invariata** (nessuna nuova funzione dimostrata)

- Script di verifica ancore: [Python_Trace_Scripts/s33_verify_manual_exposure_anchors.py](../Python_Trace_Scripts/s33_verify_manual_exposure_anchors.py)
- Evidenze: [Risultati/AkeruOS_Esposizione_Manuale/latest.json](../Risultati/AkeruOS_Esposizione_Manuale/latest.json)
- Prerequisiti di lettura: [sensore/AFE](S33_Sensore_Interface_MMIO_AFE_e_Finestre_Verificate.md), [obiettivo/zoom e porta MCU](S33_Obiettivo_Zoom_MCU_Interface_e_BCIP.md), [diaframma](S33_Diaframma_Iride_Stati_Big_Small_e_Comando_BCIP.md).

> **Aggiornamento 27 ottobre 2026:** questo documento è un piano storico, non dimostra la selezionabilità delle priorità AE. La proposta di trasporto dell’apertura via MCU `0x0FF05000` è superata dall’[analisi GPIO del 22 ottobre](S33_Iride_Attuazione_GPIO_0FF04024_e_Chiusura_Wrapper.md). Il manuale Nikon S33 indica la selezione di un filtro ND elettronico, con due valori f/3.3 e f/6.6 a grandangolo; non dimostra un diaframma continuo né una mappatura fisica provata tra quei valori e gli indici software. Non considerare “ND solo fabbrica” una conclusione dimostrata.

## 1. La scoperta principale: Av e Tv esistono già nel 3A Nikon

La tabella dei nomi di «scena/typo AE» del modulo 3A (payload1) contiene, accanto a `e_Program` e alle scene (`e_Action`, `e_HighISO`, `e_Night_Landscape`, …), **`e_Aperture_Priority` e `e_Shutter_Priority`**: il motore AE interno prevede già le due priorità. Poco sotto compare anche il marcatore `========P CURVE========` (curva programma AE). Questo cambia il progetto: **non serve reinventare l'Av/Tv, serve trovare come entrare nella selezione del tipo AE e nei vincoli**.

Completano il quadro i servizi già documentati nelle sessioni precedenti:

| Controllo | Meccanismo Nikon esistente | Stato |
|---|---|---|
| Tempo di esposizione | `BCIP_SET_EXPOSURE_TIME` **0x9210** (P1 in µs, `SP2=0:LV 1:FR`, container 20/16): servizio interno di imposizione documentato; voci `Exposure Time`/`Frame Rate` nel menu tuning; il 3A registra `ExpTime` | documentato; **funzione interna da localizzare** |
| ISO/guadagno | `BCIP_SET_ISO_GAIN` **0x9212** (ISO_Gain, 16/12) + API `CAPCTRL_AFE_SetADGain` + comandi debug `SetAdGain`, `SetIsoSpeed`, `SetIsoStartDigiGain`, `ImgCap_SetISO100Gain`, `ImgCap_SetISOSpeed` | API multipla documentata; ingresso runtime da localizzare |
| Diaframma | `BCIP_Aperture` **0x9208** (Set/Get, 1:Big 9:Small) via porta MCU `0x0FF05000`; `SetIrisIndex` | binario Big/Small: **Av = due sole scelte** |
| Telemetria AE | `CAPCTRL_3AGetAEAWBData`, report `AE ConLop`/`FillPara` (Iris, Aper, ExpTime, ISO, BV, Gain), `ucSceneMode` | stringhe verificate; contratto da mappare |
| Fuoco manuale (adiacente) | `Manual Focus`, `Focus mode: MF/AF` già presenti a livello debug | esiste già un precedente di controllo manuale |

34 ancore verificate a offset fissi (evidenza JSON).

## 2. Architettura proposta

```
UI AkeruOS minima (P | Av | Tv | M, selettore valori)
        │
Livello "exposure policy" AkeruOS  ── sceglie CHI comanda ogni parametro
        │
        ├─ P  : nessuna imposizione → AE Nikon intatto (e_Program)
        ├─ Av : iris fissato Big/Small ──▶ AE Nikon su tempo+guadagno
        ├─ Tv : tempo fissato (µs)   ──▶ AE Nikon su guadagno (+iride)
        └─ M  : tempo+guadagno(+iris) imposti ──▶ AE congelata
        │
Adattatore ai servizi Nikon (da costruire, si aggancia a):
        ├─ selezione tipo AE: e_Program / e_Aperture_Priority / e_Shutter_Priority  [da localizzare: come si imposta]
        ├─ imposizione tempo: funzione interna dietro BCIP_SET_EXPOSURE_TIME (µs, LV/FR)
        ├─ imposizione guadagno: CAPCTRL_AFE_SetADGain-equivalente / servizio dietro BCIP_SET_ISO_GAIN
        └─ imposizione iride: wrapper comando ottico (transazione 0x25F338 → porta MCU)
```

Principi, coerenti con l'obiettivo AkeruOS: riusare i servizi Nikon; non pilotare MMIO direttamente dall'applicazione; ogni imposizione passa per le API originali così che attese (`CAPCTRL_EnableAndWaitFieldChange`), cambio campo e gestione errori restino quelli Nikon.

## 3. Scelte di progetto da decidere (con i trade-off)

1. **Come ottenere Av/Tv — tre strade, in ordine di preferenza:**
   - **(a) Modo AE interno:** selezionare `e_Aperture_Priority`/`e_Shutter_Priority` e passare il vincolo. Massimo riuso, minimo rischio di conflitti con l'AE; oggi **non sappiamo come si seleziona il tipo** (aperto). Nota: le `e_*` potrebbero essere classificazioni *automatiche* di scena, non voci selezionabili: da chiarire.
   - **(b) Imporre e congelare:** chiamare i servizi interni di imposizione (tempo/guadagno/iride) e impedire che l'AE li sovrascriva. Serve un modo per **congelare l'AE** (non ancora verificato: nessun servizio AE-disable trovato finora).
   - **(c) Loop proprio:** telemetria `CAPCTRL_3AGetAEAWBData` → calcolo AkeruOS → imposizione come in M. Piu controllo, più onere: dobbiamo riprodurre target/mean, saturazioni e anticipo flash.
2. **Av con iride binaria:** l'Av fisico ha **due sole aperture** (Big/Small; ND solo fabbrica). Il selettore AkeruOS mostrerà 2 voci, non una scala Fno: da dichiarare nell'UI per non promettere ciò che l'ottica non fa.
3. **ISO manuale in tutti i modi:** ISO come override separato in Av/Tv (l'AE compensa sul parametro libero) oppure ISO solo in M. Da decidere dopo aver visto il contratto del servizio guadagno (unità: ISO speed vs AD gain vs digital gain — i comandi debug distinguono `SetIsoSpeed`, `SetAdGain`, `SetIsoStartDigiGain`).
4. **LV vs FR:** il servizio tempo ha due destini (`SP2=0:LV 1:FR`): il selettore AkeruOS deve imporre il valore sul percorso giusto (inquadratura e scatto hanno range diversi).

## 4. Rischi concreti

- L'AE Nikon può **combattere** le imposizioni (le sovrascrive al ciclo successivo): senza congelamento provato, Av/Tv/M non sono stabili.
- `BCIP_*` è documentazione del vocabolario: le **funzioni interne non sono ancora localizzate**; chiamarle richiede l'ABI esatta (il tool chiama servizi interni di payload2/Main).
- Le attese di cambio campo e i timeout della transazione ottica (attenzione 0xFF, 1e6 iterazioni) impongono di non bloccare l'UI: le impostazioni vanno applicate in un task cooperante, non nel gestore dei tasti.
- Il flash e i profili macro/red-eye interpolano iris e ISO (stringhe di preflash): in M il flash va gestito o disattivato esplicitamente.
- Granularità/range del tempo in µs (P1 di BCIP default 240) da verificare: i limiti minimi/massimi non sono noti.

## 5. Ordine di lavoro (ogni passo chiude con rapporto + evidenze)

1. **Statico:** localizzare la funzione interna dietro `BCIP_SET_EXPOSURE_TIME` e `BCIP_SET_ISO_GAIN` (il tool BCIP è in payload2: risalire dal comando documentato al chiamato interno) e il selettore del tipo `e_*` nel 3A (payload1); verificare se `ucSceneMode` arriva fino al 3A.
2. **Statico:** stabilire se `e_Aperture_Priority`/`e_Shutter_Priority` sono selezionabili o solo classificazioni automatiche (chi scrive quel valore, chi lo legge).
3. **CPU-lab:** contratto dei servizi localizzati con backend registratore (ingressi, uscite, attese), senza hardware.
4. **Integrazione R1:** aggancio al percorso CaptureImage già mappato (S2 → acquisizione → JPEG → SD): in M/Av/Tv la foto finale è il collaudo funzionale.
5. **Hardware (solo su richiesta esplicita e con recupero pronto):** foto di confronto P vs Av vs Tv vs M a soggetto fisso.

## 6. Limiti di questo studio

- Tutto statico: 34 ancore di stringa verificate, nessuna funzione eseguita, nessun hardware toccato; NON_INSTALLARE invariato.
- La presenza di un comando documentato non prova il percorso chiamante runtime; `e_Aperture_Priority`/`e_Shutter_Priority` potrebbero essere tipi interni non selezionabili.
- Niente misura di range/granularità di tempo e guadagno; niente prova che l'AE possa essere congelata.

Prossimo passo utile: il punto 1 (localizzare le funzioni interne dietro `BCIP_SET_EXPOSURE_TIME`/`SET_ISO_GAIN` e il selettore `e_*`): è la verifica che sblocca la scelta fra le strade (a), (b), (c).
