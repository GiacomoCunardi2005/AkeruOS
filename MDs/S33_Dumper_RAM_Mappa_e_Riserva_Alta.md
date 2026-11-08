# Dumper RAM: raccordo fra DDR, riserva alta e finestre CPU

22 ottobre 2026. Verifica offline dei byte originali V1.1: **il gestore applicativo riserva gli ultimi 9 MiB del suo spazio software proprio da `0x0F700000`, lo stesso indirizzo dell'ultimo punto del test BootNAND**. Questo raccordo restringe la ricerca della mappa reale; non certifica una banca RAM contigua.

Riproduzione: `python3 Python_Trace_Scripts/s33_verify_ram_dump_map_constraints.py`.

[Prova eseguita](../Risultati/Runtime_Kernel/RAM_Map_Constraints/20261022T083142Z/verified_evidence.json), [finestre GNU](../Risultati/Runtime_Kernel/RAM_Map_Constraints/20261022T083142Z/gnu_verified.txt). Esito `PASS_STATIC_RAM_MAP_CONSTRAINTS_NOT_FULL_PHYSICAL_MAP`. Firmware, BootNAND e tabella112record ricontrollati per SHA256; GNU usato esclusivamente per leggere/disassemblare immagini temporanee. Nessun hardware o nuova esecuzione CPU in questa prova.

## Raccordo verificato

Il getter `0xC768C` restituisce `1 << 28 = 0x10000000`: sono tre istruzioni, senza lettura hardware. Nella tabella `0x3766F4`, il primo record originale contiene `{id=0x6B,parent=0xE9,stato=0,base=0,size=0x900000,align=4}`. Il calcolo originale già eseguito nei [test sulle regioni](S33_NAND_PC_Regioni_RAM_Applicative_e_Limite_Installazione.md) produce:

```
align_down(0x10000000 - 0x00900000, 4) = 0x0F700000
```

La regione aggregata `[0x0F700000,0x10000000)` include sia finestre usate come memoria dal software, sia l'area MMIO nota da `0x0FE00000`. Perciò **non si può passare il record0 al dumper come se fosse RAM fisica**. Il rapporto fra confine della riserva e arresto del test è una coincidenza numerica verificata; il motivo progettuale del confine resta un'inferenza.

## Finestre alte: basi e dimensioni software

Il getter `0x2696F4` legge le basi dai quattro pool `0x269828..0x269834`. Il vicino getter `0x269730` restituisce le tre dimensioni con immediati e shift nel delay slot. Entrambi sono riancorati e confrontati sui byte originali:

| Selettore | Base CPU | Dimensione software | Fine esclusiva |
|---:|---:|---:|---:|
|0|`0x0F794000`|`7 << 11 = 0x3800`|`0x0F797800`|
|1|`0x0F798000`|`0xE3 << 7 = 0x7180`|`0x0F79F180`|
|2|`0x0F7A0000`|`0xD2 << 8 = 0xD200`|`0x0F7AD200`|
|altro|`0x0F7B0000`|getter dimensione restituisce0|nessuna lunghezza dedotta|

La fine della finestra1 coincide con la fine del [workspace precedentemente ricostruito](S33_Origine_Celle_Buffer_e_Area_Condivisa_Stadi.md), `[0x0F79B180,0x0F79F180)`. I tre intervalli occupano complessivamente `0x17B80` byte di spazio software, senza sovrapposizione; questo **non dimostra memoria fisica distinta**. Non sono pool liberi per il codice del dumper.

## Cosa resta da provare per tutta la RAM

- `DDR_SIZE_ID=0x120` configura il limite256MiB del [test sparso BootNAND](S33_BootNAND_DDR_ID_Dimensione_e_Checksum.md); non identifica basi fisiche, alias, buchi o capacità indipendente.
- Il salto del singolo punto `0x08000000` non prova né un buco1MiB né il limite128MiB. Il loop salta esattamente quel campione; non legge tutti gli indirizzi intorno.
- La riserva alta non equivale a9MiB di RAM: contiene MMIO e regioni di natura ancora ignota. Non estendere il dumper automaticamente fino a256MiB.
- Non è ancora ricostruita una traduzione CPU→DDR né l'eventuale alias delle finestre alte. Una scansione del listato alla ricerca di nomi MMU non costituisce prova di MMU assente: AUX calcolati o numerici e configurazione esterna restano possibili.
- Gli helper cache `0x26E610`/`0x26E640` operano su linee64byte e registri `dc_ivdl`/`dc_flsh`; provano richieste cache software. La semplice lettura C registra la vista CPU corrente e non certifica il contenuto DDR indipendente da cache/DMA. Invalidare indiscriminatamente la cache non è una soluzione dimostrata.

Passo concreto successivo: ricostruire il corpo completo DDR BootNAND `0x0F800A54` e i bit dei registri `0x0FE20100/104/110/134`, confrontandoli con la configurazione BFN realmente esportata; cercare un riscontro hardware della geometria. In parallelo, seguire gli utilizzatori della riservaID6B e delle tre finestre per distinguere SRAM, DDR e finestre hardware. Gli intervalli della tabella applicativa possono guidare questi controlli ma non sostituire la mappa fisica.

Il manifest prodotto da questa verifica ha `physical_map_complete=false` ed `executable_dumper_manifest=false`: documenta vincoli e unknown, senza aprire la SD o abilitare un dump hardware incompleto etichettato completo. Nessun nuovo dump RAM reale; NON_INSTALLARE invariato.
