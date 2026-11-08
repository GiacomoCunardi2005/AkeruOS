# S33 — candidato firmware RAW forzato, solo offline

27 ottobre 2026. L'utente ha chiesto un `firmware.bin` con i controlli RAW
attivi. È stato creato un **esperimento offline NON INSTALLARE** a partire
dal contenitore originale Nikon S33 V1.1. Non è un firmware validato per
l'uso sulla fotocamera.

La [verifica successiva per l'installazione](S33_Firmware_RAW_Verifica_Installazione_20261027.md)
ha eseguito updater, loader, ramo di cattura e writer entro confini simulati;
restano problemi e limiti per cui il candidato è ancora **NON INSTALLARE**.

## Artefatto

- [Firmware RAW forzato, NON INSTALLARE](../Risultati/HiddenMenu_RAW_Firmware/20261027T110219Z/firmware_RAW_FORZATO_OFFLINE_NON_INSTALLARE.bin)
- [SHA256](../Risultati/HiddenMenu_RAW_Firmware/20261027T110219Z/firmware_RAW_FORZATO_OFFLINE_NON_INSTALLARE.bin.sha256):
  `56c9457646be23bde6e1bda47c6cefaada5bf52657ba299f83339306debf4cbf`
- Dimensione: 29.602.084 byte.
- Sorgente: `OriginalSoftware_NikonS33_V1.1/firmware.bin`, SHA256
  `1d34e990a8f99019ffa53ca5de785399df863e942739a667ceb314ec6ce62a39`.

È una variante **separata** dai candidati USB e HiddenMenu precedenti: non
include le loro patch. Le foto storiche del 20 ottobre mostrano MAIN 1.1100;
non stabiliscono da sole il contenuto attualmente residente nella fotocamera.

## Che cosa modifica

Il progetto aveva individuato un'inizializzazione che può scrivere zero nel
flag CFA: modificare semplicemente i valori iniziali dei dati non dimostrerebbe
che i controlli restino attivi. Il candidato sostituisce invece i primi quattro
byte di tre getter originali con `mov_s` seguito da `j_s [blink]`:

| Getter CPU | Offset nel contenitore | Prima → dopo | Ritorno forzato |
| --- | --- | --- | ---: |
| `0x28D48C`, SaveCCDRawOnTake | `0x227F44` | `02d00088` → `01d8e07e` | 1 |
| `0x14A2D8`, modalità RAW | `0x0E4D90` | `fc1700f0` → `03d8e07e` | 3 |
| `0x13AF18`, SaveCFARawOnIRP | `0x0D59D0` | `ced0e07f` → `01d8e07e` | 1 |

Sono ricostruiti checksum del payload 0, header TBM e XOR del contenitore.
Gli altri 15 payload coincidono con gli originali; 27 byte dell'intero file
cambiano includendo i checksum. Il delta inverso ricostruisce esattamente la
base V1.1 come file: **non dimostra recupero fisico della fotocamera**.

La scelta forza i **valori letti dai getter**, non i contenuti delle tre celle
RAM. I setter originali continuano a scrivere la RAM; chiamare i getter
restituisce comunque 1, 3 e 1. Di conseguenza i comandi HiddenMenu associati
non possono spegnere normalmente tali letture e potrebbero mostrare stati
non corrispondenti alla RAM. L'opzione CFA può inoltre attivare esportazioni
aggiuntive e quindi altre scritture su SD. È una variante *sempre forzata*,
non una modifica che preserva il normale interruttore On/Off.

## Verifiche eseguite

- I byte originali dei tre punti coincidono con i payload V1.1 e MainCode.dmp.
- Contenitore rianalizzato con parser esistente; verifica checksum su tutti i
  16 payload e uguaglianza completa per i 15 non modificati; delta delimitato
  e rollback file byte per byte.
- GNU ARC700 invariato esegue i getter e setter originali e quelli del
  candidato estratti dal contenitore. Per ciascun input RAM 0, 1, 3 e 255:
  originale restituisce il valore scritto, candidato restituisce sempre
  `1, 3, 1`; entrambe le varianti scrivono in RAM il valore richiesto.
  213 istruzioni originali e 201 del candidato, nessun fault, stack conservato.
- [Prove JSON](../Risultati/HiddenMenu_RAW_Firmware/20261027T110219Z/verified_evidence.json),
  [casi CPU](../Risultati/HiddenMenu_RAW_Firmware/20261027T110219Z/cpu_cases.json),
  [delta contenitore](../Risultati/HiddenMenu_RAW_Firmware/20261027T110219Z/container_delta.json).
- [Builder e verificatore riproducibile](../Python_Trace_Scripts/s33_build_raw_always_on_offline.py).

La CPU ha eseguito soltanto gli accessor con chiamante, RAM e stack sintetici.
Non sono stati eseguiti un boot completo, il menu, la cattura, l'ISP, una
scrittura SD o il recupero fisico. Non è stato dimostrato che ogni possibile
percorso usi questi getter. Il ramo RAW individuato richiede fino a
26.527.232 byte, ma il file realmente prodotto, la profondità effettiva e il
packing non sono verificati. Il percorso include anche una funzione che può
modificare bit del buffer: [analisi precedente](S33_HiddenMenu_RAW_Massimo_20261027.md).

Nessun comando hardware, modifica dei firmware originali o scrittura su SD è
stato eseguito. **NON INSTALLARE**: compatibilità, avvio, acquisizione e
recupero non sono dimostrati.
