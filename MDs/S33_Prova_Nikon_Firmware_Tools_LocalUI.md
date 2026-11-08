# S33 — prova del decoder Nikon Firmware Tools / LocalUI

20 ottobre 2026. Prova locale richiesta dall'utente, senza accesso alla fotocamera.

## Risultato

Il decoder `Package` usato dal pulsante **Decode Firmware** di LocalUI, nella revisione provata, **non estrae il firmware originale S33 V1.1**. La trasformazione XOR produce un file, ma il successivo riconoscimento dell'archivio restituisce `false`, senza eccezioni e senza blocchi estratti. Il file trasformato non è un firmware installabile né una nuova decodifica valida della S33.

| Verifica eseguita | Esito |
|---|---|
| Archivio sintetico valido nel formato atteso dal decoder | Un blocco estratto, byte `01 02 03 04` verificati |
| Archivio sintetico con lunghezza intestazione fuori limite | Rifiutato |
| S33 originale, selezione intestazione come in LocalUI | Nessun header a spazi riconosciuto, offset 0 |
| `Package.LoadData` sulla S33 | `true`: indica solo trasformazione completata |
| `Package.TryOpen` sulla S33 | `false`, zero blocchi |
| Parser specifico S33 sul medesimo input | TBIB, TBM e P1RES riconosciuti, XOR contenitore verificato |
| Hash dei payload TBM rispetto al manifest esistente | Tutti i 16 coincidono; record 16 escluso perché non è un payload disponibile |
| Originale e copia dopo la prova | Identici all'input verificato |

## Causa osservata

`Package.LoadData` applica tre tabelle XOR e restituisce sempre `true` quando termina. `ExactFirmware`, chiamato da `TryOpen`, legge invece campi big endian a offset `0x20` del risultato e verifica le dimensioni prima dell'estrazione.

Sulla S33 il risultato XOR contiene:

- numero di record: **70.285.491**;
- lunghezza intestazione: **585.040.625 byte**;
- dimensione effettiva: **29.602.084 byte**.

La lunghezza dell'intestazione supera quella del file; anche `count * 30` supera il file. Il controllo originale rifiuta l'archivio. La stringa `V2.0` del contenitore S33 non coincide con il riconoscimento `v2Header` di LocalUI: quest'ultimo cerca 32 byte tutti uguali a spazio a offset `0x20`.

Questa prova stabilisce il rifiuto del campione da parte di questo percorso del decoder. Non stabilisce l'inutilità di tutto il repository, che contiene altri strumenti e studi.

## Metodo, fonti e riproduzione

Sorgente upstream: [nikon-firmware-tools](https://github.com/simeonpilgrim/nikon-firmware-tools), commit **`de8019ee30db7fe7bc61e520da289078ae82dcaa`**, recuperato dalla copia Git locale. Il [README](https://github.com/simeonpilgrim/nikon-firmware-tools/blob/de8019ee30db7fe7bc61e520da289078ae82dcaa/firmware%20decode/README.md) rimanda esplicitamente a LocalUI.

La GUI originale usa Windows Forms/.NET Framework 4.8. Su Linux è stato compilato un programma console .NET 8 con `Package.cs`, `IPackage.cs` e `CRC.cs` **inalterati**, più la classe `Sys` estratta testualmente da `PatchControl.cs`. La selezione dell'intestazione riproduce `Form1.DecodeAndExtractFirm`. Il programma sostituisce finestre e scritture della GUI; non invoca patch, ricomposizione o aggiornamento CRC. Se riconoscesse blocchi, li scriverebbe con nomi numerici nella cartella della prova, senza usare nomi presi dal firmware come percorsi.

- [Script riproducibile](../Python_Trace_Scripts/s33_try_nikon_localui_decoder.py).
- [Evidenze complete](../Risultati/Nikon_Firmware_Tools/20261020T175946Z/verified_evidence.json).
- [Indice ultima prova](../Risultati/Nikon_Firmware_Tools/latest.json).
- [Snapshot upstream con hash e URL nel manifest](../Risultati/Nikon_Firmware_Tools/20261020T175946Z/fonti/).
- [Programma console e progetto](../Risultati/Nikon_Firmware_Tools/20261020T175946Z/probe/).
- [Log compilazione](../Risultati/Nikon_Firmware_Tools/20261020T175946Z/build.log), [log esecuzione](../Risultati/Nikon_Firmware_Tools/20261020T175946Z/run.log).

Comando dalla radice del progetto:

```bash
python3 Python_Trace_Scripts/s33_try_nikon_localui_decoder.py
```

Input: `OriginalSoftware_NikonS33_V1.1/firmware.bin`, SHA-256 `1d34e990a8f99019ffa53ca5de785399df863e942739a667ceb314ec6ce62a39`.

Output XOR di analisi `decoded_NON_INSTALLARE.out.bin`, SHA-256 `13f012e796607a4e69c1a16e6fabf498528f53a87d4d61515bd341a50c8b78f5`. Conservato soltanto localmente. Nessuna distribuzione del firmware Nikon.

Due tentativi preliminari restano nelle cartelle vicine con i rispettivi log: il primo si arresta per componenti .NET non presenti, risolto usando soltanto il runtime disponibile; il secondo esegue già il decoder ma il controllo Python finale tenta di leggere un hash dal record 16 del manifest. Lo script definitivo controlla esplicitamente i 16 payload presenti e separa quel record. Questi tentativi non sono nuove prove firmware indipendenti.

## Limiti e continuazione

Non eseguita la GUI Windows; nessuna prova su altri modelli, firmware modificati o varianti arbitrarie dell'offset XOR. I controlli sintetici verificano l'esecuzione dell'estrattore e il rifiuto dimensionale, non compatibilità hardware o CRC Nikon.

Nessuna scrittura a fotocamera, USB, SD o alberi GNU. Nessun avanzamento funzionale AkeruOS: circa **10%** invariato. Per la S33 continuare con il parser specifico e con caricamento/residenza dei payload già individuati; questo decoder non ha aggiunto nuovi payload.
