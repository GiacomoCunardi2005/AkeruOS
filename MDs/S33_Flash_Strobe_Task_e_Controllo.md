# S33 — flash/strobe: FlashChargerTask e controllo hardware

Analisi statica del 21 ottobre 2026 sul firmware V1.1. Nessuna esecuzione del firmware, nessun accesso USB o alla fotocamera, nessuna scrittura. Continua la serie ingresso/uscita (pulsanti, schermo, shutter) con il sottosistema flash. La macchina osservata resta V1.0: gli indirizzi non sono portabili senza prova.

## Risultato

Il flash/strobe ha un **task dedicato**, **FlashChargerTask `0x165C84`** (record a `0x372988`: id `0x5800001`, stack 0x1000, priorità 2, nome nei byte originali), un protocollo a eventi con mailbox, un servizio comandi/scatto con lock e **tre registri MMIO identificati: `0x0FED18A0` (bit 3 commutato), `0x0FED18AC` (campo tempo a bit 8..11), `0x0FED18B0`** — prima attribuzione della fascia `0x0FED1xxx` al dominio strobe.

```text
servizi strobe (0x16589C comandi, 0x165640 scatto con parametri, lock 0x1593AC)
  → eventi bit 0x10/0x20 sulla mailbox 0x5800002
FlashChargerTask 0x165C84 (registra 0x5800002, maschera 1023, richiesta 0x30)
  → 0x16589C / 0x165BC4 secondo i bit; risposte 256/512 via 0x158CBC
  → bit 0x06 = spegnimento: 0xB2C74(0x80) e uscita
controllo hardware: 0x165C0C..0x165C82 read-modify-write bit 3 di 0x0FED18A0
  + campo tempo in 0x0FED18AC: (x & 0xFFFFF0FF) | ((t<<8) & 0xF00)
```

Avanzamento complessivo invariato: circa 10%.

## 1. Il task e il suo protocollo

All'avvio il task registra la sorgente evento `0x5800002` con `0x158CE0` (maschera 1023), invia la richiesta `0x30` con `0x158D04` e attende con `0x158E28`. Su ogni risveglio esamina i bit:

| Bit | Effetto |
|---|---|
| 0x10 | servizio `0x16589C`, risultato in `[0x36778C+0x28]` o nella cella `0x3677B4`, risposta 256 |
| 0x20 | servizio `0x165BC4`, risultato in `[ctx+0x2C]` o in `0x3677B8`, risposta 512 |
| 0x10+0x20 | dispatch sul byte `[ctx+0x24]`: `0x10` → `0x16589C`, `0x20` → `0x165BC4`, altro → `0x165BC4` |
| 0x06 | `0x158CBC`, `0xB2C74(0x80)`, uscita dal loop |

Contesto strobe in RAM: `0x36778C`; seconda mailbox `0x5800003` usata dal dispatcher a sei casi `0x165D40` (byte di contesto ≤ 5, salti su tabella halfword a `0x165D6E`) e dai lock.

## 2. Servizi e controllo hardware

- `0x16589C` (comandi): lock `0x1593AC`, tabella casi, servizi `0x1786E8`/`0xAD920`/`0x179354`/`0x145D1C`, e **due chiamate al servizio di scatto `0x165640`** con campi del contesto (tempi a `ctx+80/100/0x54/0x58/0x5C/0x60`).
- `0x165640` (scatto): ingresso con salvataggio registri via `0x335B34`; corpo non ricostruito.
- `0x165C0C..0x165C82` (controllo GPIO): `ldh.di`/`sth.di` con `bclr`/`bset` del bit 3 su `0x0FED18A0` (sequenza clear→set→clear), servizi `0x1786E8`/`0x179354(0)`/`0x179354(1)`, poi `stb 1` su un byte di contesto.
- `0x165982..0x16599A`: costruisce `(x & 0xFFFFF0FF) | ((t<<8) & 0xF00)` e scrive la halfword `0x0FED18AC`: campo a 4 bit, coerente con un tempo strobe quantizzato.

I tre registri sono attribuiti dall'uso nei pool del codice strobe (`0x16596C`, `0x1659A4`, `0x165C30`, `0x1660B8`, `0x1661A8`); la semantica esatta dei bit (carica contro scarica) resta da provare.

## 3. Comandi di collaudo e script

Il dizionario dello script di servizio (già [documentato per l'LCD](S33_Schermo_Catena_Uscita_Display.md)) contiene i comandi flash: **`FlashFire`**, `StrobeReady`, `ImgCap_SetFlashTime`, `KeyFlash`, `FE_FlashFire`, `FE_SetFlashMode4Script`, `FE_WriteStrobeTypeToNANDCali`, `FlashChargerCalibration`, `SetFlashTime`, `RedEyePreflash`, `Flash_CheckCover`, `StrobeScript_SetType` (tutti verificati byte per byte dallo script). Il modello temporale è esplicito nelle stringhe: `flash time(us): redeye:%d pf1:%d pf2:%d` (preflash anti-occhi-rossi, preflash 1/2, flash principale) e `Flash Time : %d us`.

Il DebugMode ha un pannello strobe completo: `Strobe Charge:Enabled/Disabled`, `Strobe Charge Status:Empty/Charging/Done/Timeout/NA`, `Trigger Strobe`, `Strobe Fire! (Wait More Than: %2d sec)`, `Fire full strobe.(ENABLE/DISABLE)`.

## 4. Calibrazione persistente

Il tipo di strobe è un dato **calibrato e persistente**: `Strobe Type : PKI / NK / 3rd Party`, `Save strobe type to calibration fail` (salvataggio nei dati di calibrazione), `-----Flash Charger Cali-----`, `B:\StrobeCaliData.csv` con `2nd TypicalChargingTime, StrobeTime, TonOffset, CalibrateTime…`. Coerente con `FE_WriteStrobeTypeToNANDCali`: il tempo di carica/scarica dipende dal tipo di lampada montata e viene tarato in fabbrica. Il che collega al dato osservato dall'utente in TOTAL INFO (`Strobe449`, un contatore).

## Limiti e prossimo confine

- Statico V1.1: nessuna esecuzione; l'attivazione runtime del task non è provata, il record esiste nella tabella `0x372388`.
- Il corpo di `0x165640` non è ricostruito; la provenienza dei tempi (tabelle di calibrazione) non è tracciata.
- Il collegamento fra il percorso di scatto S1/S2 (oggetto CaptureImage → CapMgr) e il servizio strobe non è ancora ricostruito: la sequenza redeye/preflash/main è oggi sola evidenza di stringa.
- `0x0FED18A0/AC/B0`: attribuzione per uso; senza datasheet la polarità dei bit resta aperta.
- Prossimo confine utile: chi chiama `0x16589C` dal percorso CapMgr, e il contenuto delle tabelle `B:\StrobeCaliData.csv`/calibrazione tipi strobe.
- Circa 10% invariato, candidato firmware NON_INSTALLARE, nessuna azione hardware.

## Riproduzione

```bash
python3 Python_Trace_Scripts/s33_trace_flash_strobe.py
```

Verifica hash/dimensioni dei 16 blocchi, il record del task, i pool del task e dei servizi, le stringhe strobe byte per byte, 12 comandi del dizionario script e conserva **5 finestre radicate GNU ARC700** in [gnu_verified.txt](../Ghidra_Results/ghidra_reports/flash_strobe/gnu_verified.txt); il [JSON](../Ghidra_Results/ghidra_reports/flash_strobe/verified_evidence.json) registra hash, protocollo, MMIO e limiti. Nessun firmware eseguito.
