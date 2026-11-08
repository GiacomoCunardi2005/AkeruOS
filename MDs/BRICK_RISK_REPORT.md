# Valutazione del rischio di brick

Verifica documentale locale del 19 ottobre 2026 sul campione Nikon S33 **V1.1** (29.602.084 byte; SHA-256 `1d34e990a8f99019ffa53ca5de785399df863e942739a667ceb314ec6ce62a39`). Gli indirizzi sono CPU della mappa candidata dei payload, non offset del contenitore. Le istruzioni e i risultati qui citati sono evidenze statiche **pregresse lette in questa sessione**, non una nuova esecuzione del firmware né una verifica hardware. Nessun trasferimento degli indirizzi alla macchina V1.0 è dimostrato.

**Il flash non è raccomandabile con le prove attuali.** È provato che il menu contiene percorsi capaci di richiedere modifiche al codice di avvio, firmware, calibrazioni e partizioni; non è provata una procedura S33 di recupero da un avvio fallito. Questi risultati non quantificano la probabilità di brick. La sola patch del confronto non dimostra un brick certo, né l'integrità dei checksum dimostra la sicurezza.

## Scenari distinti

| Scenario | Prova attuale | Conseguenza plausibile / ciò che manca |
|---|---|---|
| Pacchetto rifiutato prima del flash | Esistono validatori locali, ma catena updater/boot completa e firma non chiuse. | Rifiuto innocuo possibile; non assumere che tutti i controlli precedano ogni scrittura. Vedere [compatibilità](PATCH_COMPATIBILITY.md). |
| Patch accettata, apertura UI fallita o boot interrotto | Cambio `cmp_s` a CPU `0x1353F6`; dipendenze manager, risorse e hook runtime aperte. | Avvio o transizione UI potrebbero fermarsi; nessuna dimostrazione corrente di avvio o recupero. |
| Sola apertura HiddenMenu | Callback root RAM e chiamate di framework; inizializzazioni 4A/4B con servizi aperti. | Nessuna scrittura NAND automatica dimostrata; assenza transitiva di scritture non provata. |
| Selezione Update Boot/MainCode o Erase | Callback `12AA3C/12A9FC → 12AE00/12AD58 → 1EEA4C` con partizioni 0/6; `2FFF0C`. | Corruzione del codice necessario all'avvio; recupero non dimostrato. |
| Calibrazione / reset / parametri | `2FFF0C(1/2)`; restore/reset `3001D0`, `300208`, `C9D58` e root reset `C9D84`. | Perdita di calibrazioni o configurazione, anche con boot ancora possibile. Non equivale sempre a brick permanente. |
| BootNANDBase / BFN / partizioni / update composto | `3014C0 → 1EEF6C`; `3016EC → 1EEAEC`; `3012F0 → 29EFC4`; `301E1C`. | Layout o metadati incoerenti e perdita d'avvio plausibili; atomicità e rollback non provati. |
| SKY risorse P1 | Cancellazione `2FFF0C(5)` precede caricamento/commit `129460`. | Fallimento intermedio può lasciare risorse eliminate. |
| Dump, SD Life e format | Dump `30017C`, loop `7D58D8`, format `300D0C`; volume fisico parzialmente aperto. | File o supporto possono essere modificati; perdita dati e usura plausibili, non brick automaticamente. |
| Errore e polling | `0x7D4840` è un ciclo locale senza uscita; attese `16F920(0x62)` e guardia pulita a `7D4880`. | Blocco UI verificabile staticamente; togliere alimentazione durante writer attivo potrebbe aggravare inconsistenza. Nessun timeout globale escluso. |

Fonti per indirizzi e limiti: [mappa scritture](NAND_WRITE_MAP.md), [audit dei casi](FUNCTION_RISK_AUDIT.md), [followup MMIO e SD Life](HIDDENMENU_FOLLOWUP.md), [azioni NAND](../S33-sections/analysis_codex/evidence/007d444c_actions4a.txt). Il legame fino a `sth.di` a `0x25E0B0` rende concreto il rischio storage per il ramo partizione 0; protocollo e completamento fisico restano aperti.

## Diagnostica e confine della sola lettura

Getter `0x129920`, lettori lista `0x635DAC/0x635BD8` hanno corpi locali di sola lettura del dato. Questo non autorizza a classificare i menu che li chiamano come innocui. I toggle SKY focus, strobe, shutter speed e GTE hanno store RAM osservati, ma consumer e possibili effetti fisici non tutti chiusi. L'etichetta ERROR CODE offre Dump2File/Clear; CALIBRATION e DEBUG non hanno audit transitivo completo. L'assenza di un sink trovato non è prova di assenza di persistenza. Fonti: [audit classi L/R/U/P/F](FUNCTION_RISK_AUDIT.md), [mappa voci](HIDDENMENU_MAP.md).

## Apertura automatica e selezione esplicita

La patch rende eleggibile lo stato 1 nel primo ramo: solo con lookup/attributi corretti arriva a `1453E4(0x20,0)`. Gli eventi root aprono sottomenu; le operazioni NAND richiedono successivi eventi di selezione. Queste distinzioni riducono il rischio di interpretare “apertura” come “erase automatico”, ma non certificano assenza di effetti automatici: manager `145180`, hook `367808/367810`, default `20E814` e lifecycle restano dipendenze. Anche un indice fuori lista può diventare dato 0 in SKY e attivare SD Life nel modello locale: non considerare qualunque evento sintetico innocuo. Fonti: [percorso](SERVICE_MODE_PATH.md), [questioni aperte](OPEN_QUESTIONS.md).

## Perché non si può ancora raccomandare il flash

- Hardware nei log V1.0 e campione V1.1: indirizzi, layout, compatibilità di modello e politica di aggiornamento non sono trasferibili senza verifica.
- Non dimostrati boot del modificato, memoria residente di tutti i payload, transizioni UI, assenza di writer automatici e comportamento in errore.
- Nessuna prova di recovery applicabile esattamente alla S33 dopo perdita di codice/partizioni. Una normale procedura di aggiornamento dipende da firmware ancora funzionante. Vedere [opzioni di recupero](RECOVERY_OPTIONS.md).
- Non dimostrate autenticazione globale del pacchetto, tutte le verifiche updater, atomicità, boot alternativo o rollback. Nessuna di queste capacità può essere dedotta dal numero ridotto di byte diversi.

## Controlli di questa consegna e prossimo punto

In questo rapporto sono stati letti e confrontati dossier ed estratti GNU già salvati; è stata eseguita una ricerca testuale locale limitata dei termini relativi al Service Mode. Le precedenti esecuzioni `audit_storage_followup.py` (16 payload/roundtrip, 23 finestre, 40 istruzioni) e `sweep_activation_references.py` sono riportate come storiche, non rilanciate da questo sottoaudit. Nessuna emulazione o test hardware è attribuito a questi rapporti. I risultati correnti di byte/checksum ed emulazione sono negli appositi rapporti della consegna.

Il singolo passo che più riduce il rischio del flash è ricostruire il percorso updater/boot e verificare se esista un recupero S33 indipendente dal MainCode aggiornato. La prova P-code del confronto può risolvere il comportamento locale della patch, ma non chiude questo rischio. Il checkpoint funzionale AkeruOS resta circa 10%: nessun boot nuovo e nessuna foto prodotti.

## Riverifica nella consegna complessiva

Il coordinatore ha poi rieseguito `audit_storage_followup.py`: 23 finestre GNU e 40 istruzioni controllate, con hash dei due firmware invariati. [Risultato corrente](evidence/storage_followup.json), [log](../S33-sections/safety_audit_codex/evidence/storage_recheck.log). La scansione globale dei candidati allo stato resta una prova precedente letta; non è stata rieseguita. Nessuna esecuzione storage reale. La sonda della sola istruzione è documentata separatamente in [EMULATION_RESULTS.md](EMULATION_RESULTS.md).

## Seguito: updater pubblico e candidato TBIB

La [nuova verifica R4](SD_UPDATE_RECOVERY_PATH.md) collega la UI pubblica V1.1 ai writer MainCode/BootCode e identifica nel TBIB un caricamento RHIR alternativo precedente al MainCode. Sono prove statiche nuove (48 finestre/145 istruzioni), integrate nel runner e nel manifest. Non certificano preservazione fisica: il pubblico può raggiungere il writer BootCode selettore0, il mapping dipende da metadati runtime e reset/ROM→copia TBIB non è dimostrato. Il candidato non è una procedura pronta di ripristino e non equivale al pacchetto pubblico firmware.bin. NO-GO invariato; nessuna azione hardware.
