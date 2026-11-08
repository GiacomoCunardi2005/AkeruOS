# Ritorno ISO: pulizia della coda originale — CPU emulata V1.1

Data 2026-11-04. Il banco estende la [sequenza scanner → menu → ISO → ritorno](S33_GUI_Menu_ISO_Ritorno_Ritenta_CPU_20261104.md). Esegue ora i byte originali della chiusura `0x16A0BC`, del filtro `0x17BF60` e del compattatore `0x17BEE8`; le finestre caricate vengono confrontate con il payload verificato dopo il link. La tabella delle destinazioni rimane sintetica: ID `0x36` punta al descrittore AkeruOS di laboratorio. Il callback ISO e il manager sono originali; nessun byte del firmware è modificato.

**8/8 casi PASS**: due ordini callback × scelta ISO software 120/140 × busy 0/1 al ritorno. Dopo l'estrazione degli eventi di conferma, ma prima della loro consegna al dispatcher, il banco accoda deliberatamente tre record di prova:

| Destinazione | Evento | Argomento | Busy 0: dopo chiusura ISO |
|---|---:|---:|---|
| finestra ISO `0x989FCC` | `0x580` | `0x111` | eliminato |
| finestra AkeruOS `0x367780` | `0x580` | `0x222` | conservato |
| finestra ISO `0x989FCC` | `0x8000` | `0x333` | conservato |

Con busy 0 la chiusura chiama `0x17BF60(0x989FCC, 1, 0x7FFF)`: la comparazione dell'evento è **signed 16 bit**, quindi `0x8000` è fuori intervallo. Il compattatore originale conserva in ordine i due record sopravvissuti e il manager accoda dopo di essi `0x4409` per la finestra sperimentale. In questi casi l'indice read finale è 9 e write 12; il contatore di segnalazioni sale a 13, perché la cancellazione non annulla le segnalazioni già prodotte. I contenuti e gli indici sono verificati, oltre alla traccia di chiamata del filtro e del compattatore.

Con busy 1 il manager non esegue la chiusura: tutti e tre i record restano in coda nell'ordine inserito, la finestra corrente resta ISO e nessuna notifica finale del ritorno viene aggiunta. La prova non consuma i record dopo il ritorno e non sostiene che la notifica della coda rifletta il numero di record presenti.

Lock, segnali, timer `0x149134`, risorse e altri servizi sono fixture/stub; coda, guardie, momenti di inserimento, stato e tabella sono imposti dal banco. Non sono dimostrati concorrenza, gestione su hardware, comportamento di tutti gli intervalli, ritorno con tabella originale, effetti sul sensore o associazione ai tasti fisici. **NON_INSTALLARE**.

Riproduzione `python3 Python_Trace_Scripts/s33_verify_key_scanner_menu_iso_purge_cpu.py`; [evidenze 8/8](../Risultati/GUI_S33/key_scanner_menu_iso_purge_cpu_20261104T154321427535Z/verified_evidence.json). Regressioni: ritorno con purge stub [8/8](../Risultati/GUI_S33/key_scanner_menu_iso_return_cpu_20261104T154332383407Z/verified_evidence.json), nuovo tentativo [4/4](../Risultati/GUI_S33/key_scanner_menu_iso_open_cpu_20261104T154332378449Z/verified_evidence.json).
