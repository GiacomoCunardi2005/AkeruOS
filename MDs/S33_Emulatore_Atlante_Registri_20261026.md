# Emulatore ARC700 aggiornato all’atlante — 26 ottobre 2026

Il monitor in `AkeruOS/tools/arc700_web` ora usa l’atlante verificato
`Risultati/Processor_Registers/20261026T114224Z`: 64 posizioni core, 200 AUX,
1.002 MMIO. Il catalogo completo è cercabile nella pagina e consultabile via API,
con campi, fonti, valore disponibile e distinzione tra stato GNU e voce non modellata.
Gli atlanti e i verificatori storici non sono stati modificati.

I nuovi profili `main-registers` (predefinito) e `tbib-registers` mappano
esattamente le 1.000 celle scalari da due byte dell’atlante come memoria sintetica
R/W inizializzata a zero. Conservano anche le fixture precedenti: 1.003 celle
totali Main, 1.001 TBIB. Le celle USB `0x0FE50010` e `0x0FE50920` hanno larghezza
ignota e restano non mappate. Non si aggiungono intervalli MMIO interi.
Le maschere e le operazioni degli accessor sono eseguite dal firmware originale.
Questo modello di storage non stabilisce RO/W1C, reset, IRQ, frequenze o effetti
periferici fisici. Tutti i profili precedenti restano selezionabili.

Il bridge riusa `Python_Trace_Scripts/s33_register_memory_observer.c` attraverso
wrapper che delegano gli accessi a GNU. L’API conserva gli ultimi 80 eventi,
distinguendo tentativo e risultato. Le letture del monitor non generano accessi
guest. La consultazione AUX usa il bitmap di validità e non chiama getter
che inizializzerebbero celle sconosciute. IDENTITY zero resta un dato del modello.
Per accedere al bitmap, il bridge è compilato con le opzioni di layout CPU della
build GNU fissata, compresi `PROFILE`, `WITH_PROFILE` e `WITH_SCACHE`; controlla
PC/SP all’avvio. Le librerie e i sorgenti GNU rimangono in sola lettura.
Le posizioni core r61 e r62 non espongono valori; PCL è il PC GNU allineato a 4 byte,
distinto da STATUS32 e dai numeri di registro dell’interfaccia GDB.

## Verifiche

- `test_server.py`: 9 test PASS, inclusi tutti i 200 AUX nei due nuovi profili,
  nessun avanzamento/inizializzazione durante la consultazione, rifiuto di
  mappa/validazione/ledger alterati, protezioni HTTP e compatibilità dei profili.
- `test_registers.py`: CPU GNU reale su tutte le 1.000 celle, tre pattern
  (0, 65535, 0xA55A, combinati con l’indirizzo), 3.000 scritture e 3.000 letture.
  Scrittura guest AUX 0x45 seguita da consultazione del monitor verificata.
- Stesso bridge: 624 chiamate a 16 accessor TBIB originali, 39 scenari
  (tre seed e 13 argomenti), 897 eventi originali confrontati con l’oracolo
  esistente `s33_verify_tbib_fed20_tail.build`. Verificati risultati, memoria
  finale, SP e r13–r19. Stati CPU campionati identici con osservatore attivo
  e disattivo; ciò non afferma uguaglianza di ogni byte interno non campionato.
- Accesso a `0x0FED201A`, lettura da cella USB di larghezza ignota e lettura
  a 32 bit da cella isolata a 16 bit: arresto per indirizzo non mappato,
  senza evento di completamento. Il monitor rifiuta la lettura fuori whitelist.
- `test_snapshot48.py`: 32 casi del lettore Main originale, tre configurazioni
  invalide rifiutate e vicino non mappato, PASS.
- Main con il nuovo profilo: arresto di provenienza conservato a PC `0x0016C99A`,
  579.921 richieste di passo, RAM `0x00000970` non dichiarata, segnale 5;
  sequenza di scritture Snapshot48 1→0 verificata. Nessun boot completo.
- Browser Playwright: controlli, ricerca/valori/assenza modello, entrambi i nuovi
  profili, desktop 1512×1100 e mobile 390×844, nessun errore JS o overflow pagina.
  Il controllo stilistico segnala anche difetti dell’interfaccia preesistente;
  non è stata eseguita una riprogettazione generale.
- Integrità: tutti i 356 file del ledger dell’atlante e i 18 input del bridge
  verificati. Ledger fissato a
  `79d338a8fa5c33e2fc16d170e23c9c65ed617bbe764effdfce35d02246cb666b`.

Evidenze raccolte in
`outputs/arc700_web/register_update_20261026/`: log delle tre suite, screenshot,
risultati browser, integrità e audit conclusivo. `before/` conserva i sorgenti
precedenti dell’interfaccia. Gli output delle prove CPU sono indicati nei log
e nell’audit, con ELF, comandi, log e hash; gli output di tentativi falliti sono
conservati e non costituiscono prove PASS.

Avvio e API: [README dell’emulatore](../AkeruOS/tools/arc700_web/README.md).

Nessun accesso hardware, dumper, NAND/vendor, flash, reset USB o scrittura SD.
RAM di 128 MiB sintetica; geometria fisica, periferiche, IRQ/timing e boot
completo non verificati. Firmware **NON_INSTALLARE**.
