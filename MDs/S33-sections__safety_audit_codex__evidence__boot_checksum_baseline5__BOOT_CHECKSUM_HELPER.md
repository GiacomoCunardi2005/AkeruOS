# Controllo BootCode: integrità locale e sicurezza sono requisiti diversi

20 ottobre2026,R4. **Eseguita la vera routine P-code `0x12AF44` del validatore BootCode, fino al ritorno, su cinque input controllati.** Il corpo `0x1ED914` somma le parole del payload e il wrapper confronta la somma col campo dell'header. Non è stata eseguita l'intera accettazione del pacchetto o una scrittura.

## Riproduzione e input

```bash
python3 S33-sections/safety_audit_codex/run_boot_checksum.py
```

[Runner](../S33-sections/safety_audit_codex/evidence/boot_checksum_baseline5/run_boot_checksum.py), [probe Java](../S33-sections/analysis_ghidra/scripts/ProbeBootChecksum.java), [manifest](../S33-sections/safety_audit_codex/evidence/boot_checksum_baseline5/boot_checksum_verified.json), [GNU](../S33-sections/safety_audit_codex/evidence/boot_checksum_gnu.txt), [risultati](../S33-sections/safety_audit_codex/evidence/boot_checksum_pcode.txt), [log](../S33-sections/safety_audit_codex/evidence/boot_checksum_run.log). **PASS,5casi P-code,2finestreGNU**,16identità payload controllate tramite helper esistente. Le due finestre sono identiche nei campioni CMP3/CMP1; si esegue il codice del campione canonico, senza duplicare test di istruzioni identiche.

Campioni integri29.602.084byte, SHA-256CMP3 `1d34e990a8f99019ffa53ca5de785399df863e942739a667ceb314ec6ce62a39` eCMP1 `932281f89b840a45dc1b050dac52d5250f040ea6576b94696b55f3b93e123f1c`. TBIB `[file0x6C,file0x4806C)` identico nei due pacchetti; header base/ingresso01000000, lunghezza corpo44BBC, checksum confrontato anche mediante Python. Il componente originale locale viene copiato nella RAM di laboratorio0F100000; stack0F000000..0F001000, registri inizializzati. Le variazioni esistono esclusivamente nella memoria dell'emulatore. Nessun nuovo firmware modificato è stato scritto su file.

Linguaggio aliasfix già convalidato, file firmati ricontrollati prima del test. Nessuna nuova istruzione implementata, nessuna risposta di servizio sostituita. Il probe ferma sia `step()==false` sia fault segnalati; ogni caso deve tornare al sentinel0F000100, con SP ripristinato e nessun errore/fault. Non vengono chiamati driver storage o periferiche fisiche.

## Risultati

| Caso | Alterazione dell'input in laboratorio | Ritorno del solo helper |
|---|---|---:|
| `valid` | Componente TBIB originale |1,verifica locale riuscita |
| `body_changed` | Un bit cambiato nel primo word del corpo, somma dichiarata invariata |0,rifiuto locale |
| `compensated` | Primo word+1,secondo word−1,header invariato |1,verifica locale riuscita |
| `entry_changed` | Bit0x10 cambiato nel campo ingresso aheader+12,corpo invariato |1,verifica locale riuscita |
| `null` | Puntatore nullo |0,rifiuto locale |

Nei primi quattro casi sono completati211.196step P-code, eccetto `body_changed`211.195; il caso nullo30. Sono passi del helperGhidra, che può incorporare gli slot di ritardo: non conteggi fisici completi delle istruzioni ARC o misure di prestazione. Gli assert verificano anche ritorno, assenza di fault e ripristino stack.

## Interpretazione delimitata

Il controllo protegge da alcune alterazioni dei dati. Una somma additiva consente però compensazioni: superare questa funzione non certifica l'origine del contenuto né la validità del codice da eseguire. Il campo ingresso non è letto da questa funzione; l'esito del caso modificato non permette di affermare che tutti gli altri controlli lo ignorino.

Nel callback `0x12AE00`, il wrapper più ampio `0x12AF8C` aggiunge capacità e, in un ramo, un controllo di identità/sentinella prima di chiamare `0x12AF44`. **Quel wrapper più ampio non è stato eseguito qui.** Il test non dimostra l'accettazione dei due input alterati dall'updater intero, sullaV1.1 o sullaV1.0 residente. Non dimostra un difetto sfruttabile o una firma crittografica assente da ogni altro percorso.

Per la patch esistente i checksum validi rimangono una condizione utile già verificata. Non sostituiscono avvio completo, effetti automatici del menu, compatibilità updaterV1.0, preservazione delle calibrazioni e recupero dopo interruzione. Il [rapporto semplice nella radice](S33_Sicurezza_Flash_Spiegata_Semplice.md) distingue questi aspetti.

**NO-GO flash invariato**, firmware originali e patch invariati, nessun hardware. Prossimo: delimitare i controlli precedenti alla prima richiesta di scrittura nel callback BootCode, tenendo distinti capacità, identità e confronto con il BootCode già installato.
