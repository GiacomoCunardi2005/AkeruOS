# HiddenMenu con file SD: contenitore BIN sperimentale

**Nuova evidenza dai dump,20 ottobre 2026:** [classificazione e confronti](S33_Classificazione_Dump_Fotocamera.md). MainCode fornito contiene ilTBM candidato identico;BootCode contieneTBIB originale eNANDReserved ilP1RES originale completo. Questo supera il solo confronto del nome delBIN per i byte del dump consegnato; acquisizione fisica non osservata dall’agente, recupero ancora non dimostrato.

**Continuazione hardware,20 ottobre 2026:** [foto dell’utente e stato corrente](S33_HiddenMenu_Hardware_Foto_e_Versioni.md) confermano GUIINFO e pagine informative; utente conferma installazione del candidatoSD e riferisce avvio normale senzaSD. Le precedenti frasi “rendering mai visto” e “nessun hardware” descrivono la fase di analisi. Marcatore all’apertura sconosciuto,USB/uscita/recupero non certificati.

**Sede aggiornata:** il BIN è in `Risultati/Firmware_sperimentali/SD/`; i rapporti sono in `MDs/`. [Confronto delle garanzie e riordino](S33_Riordino_Risultati_e_Confronto_Sicurezza.md). Le evidenze storiche conservano i vecchi percorsi, risolvibili tramite la mappa di trasferimento.

20 ottobre 2026 — R3/R4. Creato su richiesta dell’utente il file completo [S33_MODIFICA_SD_SPERIMENTALE_NON_INSTALLARE.bin](../Risultati/Firmware_sperimentali/SD/S33_MODIFICA_SD_SPERIMENTALE_NON_INSTALLARE.bin). **Esiste un contenitore binario modificato, ma non è ancora verificato per l’installazione: NO-GO flash.** Non è un ELF rinominato. Nessuna operazione sulla fotocamera o sulla SD.

## File e provenienza

| Elemento | Valore |
|---|---|
| Dimensione | 29.602.084 byte, identica all’originale |
| SHA-256 candidato | `ce504526dcb1ebffab33f17bf1467fd03f70b01c5393ad03812523f978b3e8c9` |
| SHA-256 originale V1.1 | `1d34e990a8f99019ffa53ca5de785399df863e942739a667ceb314ec6ce62a39` |
| Differenze effettive | 230 byte, nei soli intervalli autorizzati dal verificatore |
| Modifiche al MainCode | Collegamento di 8 byte a `0x1353F2`; routine di 220 byte a `[0x35BB14,0x35BBF0)` |
| Dati e risorse | Gli altri 15 payload TBM, TBIB, P1RES e trailer restano identici |
| Integrità ricostruita | Somma del payload 0, somma/complemento KHIR, XOR globale |
| XOR globale del candidato | `0x23C50ECB` |

Il campione è V1.1; i log storici della macchina indicano V1.0. La stringa del contenitore V2.0 è distinta dalla versione Nikon. Il candidato contiene software Nikon locale e non è destinato alla redistribuzione.

## Comportamento richiesto e provato nel modello

Dal punto `0x1353F2` il nuovo codice controlla `B:\modifica.modifica`. Se il predicato Nikon lo trova come file, chiede il menu root `0x20`; assenza, cartella omonima o errori restituiti selezionano `0x135426`, la continuazione normale. Il contenuto non viene letto: il file può essere vuoto nel modello. Lo stato `0x366880` non viene scritto; non viene impostato temporaneamente a 3.

Il codice originale della sonda `0xCDA24` è rimasto invariato: ha altri chiamanti, fra cui quelli a `0x7CD400`, `0x7D456A` e `0x7D46F6` nel listato candidato. Cambiarne globalmente il criterio directory/file avrebbe allargato gli effetti della patch. La nuova routine richiama invece direttamente il predicato `0x12BBB8 → 0x18B45C` con selettore file 0.

La routine salva/ripristina r0–r12 e usa 56 byte aggiuntivi di stack, oltre alle chiamate Nikon. Usa chiamate relative risolte dal linker attraverso simboli esterni; GNU ne verifica i destinatari. Tre caricamenti PC-relative leggono il pool `0x35BBEC = 0x365870`, la stringa volume Nikon `B:`. Il percorso del marcatore si trova a `0x35BBD4`. Il ramo negativo ricostruisce getter/confronto/registro di ritorno del prefisso normale studiato e bypassa anche il vecchio selettore NAND Tool. Questo non prova equivalenza dell’intero avvio fotografico.

## Perché la collocazione resta sperimentale

La zona inizialmente proposta `0x35BB04` non viene usata per codice: il pool `0x333B78`, caricato a `0x333972`, punta lì; la chiamata a `0x128C20` riceve lunghezza 16. I byte `[0x35BB04,0x35BB14)` sono preservati integralmente. È preservata anche la zona da `0x35BBF0` in avanti, verso cui esiste una parola nel payload 6.

Il nuovo intervallo di 220 byte era interamente zero. Una ricerca su tutti i byte dei 16 payload non trova parole LE32 che puntino al suo interno. Due coincidenze ARC ME32 restano registrate: quella del payload 0 attraversa parole LE allineate `0x00351E30`/`0x0036BB48`, dopo un salto; l’altra è a offset dispari nel payload 9. Nessuna delle due dimostra un immediato ARC eseguibile verso la routine.

**Questa ricerca non dimostra che l’intervallo sia libero.** Restano possibili accessi calcolati, strutture più ampie, inizializzazioni runtime, vincoli di residenza e permessi/cache di esecuzione. La prova dal nuovo indirizzo mostra che il modello lo esegue quando il MainCode è già caricato; non dimostra che la macchina lo conservi ed esegua durante il vero avvio. Per questo il nome del file contiene NON_INSTALLARE.

## Verifiche realmente eseguite

Comandi, dalla radice:

```bash
python3 -m unittest discover -s coolpix-s33-re/tests -v
python3 S33-sections/safety_audit_codex/build_sd_marker_candidate.py
python3 S33-sections/safety_audit_codex/build_sd_marker_offline.py
python3 coolpix-s33-re/s33_extract.py Risultati/Firmware_sperimentali/SD/S33_MODIFICA_SD_SPERIMENTALE_NON_INSTALLARE.bin
```

- **7 test del parser passati.** Corretto il controllo che trattava i primi quattro byte come una magic fissa: sono la word confrontata con lo XOR delle word successive, come già ricostruito a `0x12B060..0x12B084`. Due test nuovi verificano rifiuto dopo corruzione e accettazione dopo ricostruzione dello XOR. Struttura, metadati, risorse e trailer del candidato coincidono con quelli originali; la word XOR è confrontata separatamente.
- **16 identità dei payload originali e 16 somme del contenitore candidato controllate**, oltre a KHIR e XOR globale; TBIB identico e sua somma interna verificata. Confronto integrale dei 29.602.084 byte: differenze limitate a collegamento, routine e campi d’integrità. Tutto il resto, incluso P1RES, resta identico.
- **60 scenari P-code del candidato**, importando il MainCode realmente modificato ed eseguendo da `0x1353F2`, senza blocco codice a `0x02000000`: cinque stati iniziali × dodici esiti filesystem. 25 richieste menu e 35 continuazioni normali; nessuna scrittura di `0x366880`, stack e registri preservati nei controlli dichiarati. Una baseline originale e sette confronti negativi con stato 1 coincidono al confine controllato.
- **60 scenari di regressione dell’ELF precedente**, dopo la piccola estrazione del caricamento immagini nel probe condiviso: passati. Non sono ulteriori prove di boot del candidato.
- Hash originale e hash degli eseguibili GNU usati invariati. Gli strumenti sono stati usati in lettura; nessuna scrittura nelle installazioni, sorgenti o build GNU. I nuovi Markdown sono nella radice.

[Manifest e hash delle evidenze](../outputs/sd_marker_candidate/20261020T130654Z_d14a5907/verified_evidence.json), [traccia candidato](../outputs/sd_marker_candidate/20261020T130654Z_d14a5907/pcode.txt), [GNU routine](../outputs/sd_marker_candidate/20261020T130654Z_d14a5907/gate_gnu.txt), [riferimenti collocazione](../outputs/sd_marker_candidate/20261020T130654Z_d14a5907/placement_references.json), [regressione ELF](../outputs/sd_marker_offline/20261020T130622Z_27d53bec/verified_evidence.json). Il primo tentativo `20261020T130509Z_eb35f7a3` si era fermato sul vecchio controllo magic del parser, prima della pubblicazione del BIN; non è un test passato. Due build successive hanno prodotto gli stessi byte e lo stesso hash.

Script riproducibile: [build_sd_marker_candidate.py](../S33-sections/safety_audit_codex/build_sd_marker_candidate.py). Sorgente: [sd_marker_gate_candidate.s](../S33-sections/safety_audit_codex/sd_marker_gate_candidate.s). Il builder non sovrascrive un candidato diverso: se il nome esiste, ne richiede identità completa. Conserva snapshot dei sorgenti e manifest distinti per ogni esecuzione.

## Limiti e prossimo passo

I quattro servizi filesystem `0x12B8E8`, `0x12B7E4`, `0x12B888` e `0x26E6BC` sono simulati. Il predicato file è eseguito, ma non sono verificati SD fisica pronta al selettore, risoluzione del nome lungo, attese bloccanti, rimozione concorrente o disponibilità dello stack reale. La prova termina al manager `0x1453E4` o alla continuazione `0x135426`: niente sessione GUI completa.

Non sono verificati reset/boot completo, accettazione del pacchetto da parte dell’updater residente V1.0, scrittura fisica o recupero dopo un mancato avvio. TBIB invariato nel file non dimostra che l’updater eviti di riscriverlo. Togliere il marcatore disabiliterebbe la richiesta del menu quando il controllo viene raggiunto; non disinstalla la patch né ripara un brick.

Prossimo punto utile R4: stabilire proprietà/residenza del nuovo intervallo e disponibilità della SD al selettore, poi avvio e recupero indipendente. **NO-GO flash e circa 10% funzionale AkeruOS invariati.**
