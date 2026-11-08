# S33 V1.1 — conferma ISO e tempo seguita dal ripristino combinato

Il 29 ottobre 2026 un banco GNU esegue in sequenza i callback originali di conferma ISO `0x7D25B0` e tempo `0x7D2394`, quindi la routine originale di ripristino `0xCA654`. È un passo verso il sottomenu esposizione richiesto: collega in una stessa sequenza scelte e campi osservabili, ma l'ordine è imposto dal banco, non ricostruito da uno scatto reale.

Il controllo ISO sintetico punta alla lista originale V1.1 da 24 record; sono iniettate selezioni Exit, Auto e ISO 125. Il tempo è inserito direttamente nella word del controllo con valori 0 o 42. Il record passato a `0xCA654` parte sempre da indice ISO 19 e word tempo 90.000; gli stati diagnostici iniziali sono indice 19 e ISO software 1600. La conferma tempo moltiplica per 1000. Sono sei combinazioni; i valori del record sono ipotesi del banco, non letture dalla fotocamera.

| Selezione ISO | Tempo immesso | Dopo conferma: indice diagnostico / valore ISO / word tempo | Dopo `0xCA654`: indice ISO / tempo nel record | Valori software ISO / tempo dopo `0xCA654` |
|---|---:|---|---|---|
| Exit | 0 | 19 / 1600 / 0 | 19 / 90000 | 1600 / 90000 |
| Exit | 42 | 19 / 1600 / 42000 | 19 / 42000 | 1600 / 42000 |
| Auto | 0 | 0 / 0 / 0 | 19 / 90000 | 1600 / 90000 |
| Auto | 42 | 0 / 0 / 42000 | 19 / 42000 | 1600 / 42000 |
| 125 | 0 | 6 / 125 / 0 | 6 / 90000 | 125 / 90000 |
| 125 | 42 | 6 / 125 / 42000 | 6 / 42000 | 125 / 42000 |

Nel caso Auto l'indice diagnostico rimane zero anche dopo `0xCA654`, mentre il valore ISO operativo torna 1600 perché **in questo banco** il record contiene indice 19 e la guardia zero non lo sovrascrive. Analogamente, tempo diagnostico zero lascia il valore 90.000 del record, riscritto nel campo operativo. Exit conserva l'indice diagnostico precedente 19. I campi diagnostici e operativi sono dunque distinti; lo zero non basta a stabilire da solo un valore fisico o quale impostazione verrà usata nella macchina. La GUI futura deve distinguere scelta Auto, valore selezionato e valore effettivamente applicato.

Risultato: **6 casi PASS, 3.152 istruzioni nel modello**; ogni caso controlla campi dopo ciascuna conferma, record e campi dopo ripristino, due richieste di apertura `0x36`/argomento 0 e stack. [Verificatore](../Python_Trace_Scripts/s33_verify_gui_iso_time_confirm_restore_cpu.py), [casi](../Risultati/GUI_S33/iso_time_confirm_restore_cpu_20261028T232232Z/cases.json), [manifest, hash e traccia](../Risultati/GUI_S33/iso_time_confirm_restore_cpu_20261028T232232Z/verified_evidence.json), [fixture](../Risultati/GUI_S33/iso_time_confirm_restore_cpu_20261028T232232Z/fixture_patches.json). Le finestre dichiarate e i record della lista sono confrontati con il dump V1.1. Rispetto al [test precedente](S33_GUI_Ripristino_ISO_Tempo_CPU_20261028.md), che iniettava direttamente gli stati diagnostici, qui entrambi i callback di conferma vengono eseguiti prima del ripristino.

Le selezioni, il record e l'ordine delle chiamate sono sintetici; recupero controllo e apertura GUI sono fixture, come 14 altri servizi di `0xCA654`. Il banco non esegue navigazione completa, scheduler, sensore, AE o scatto; non dimostra tempo fisico, ISO fisico, concorrenza, persistenza o ritorno al nuovo menu. Le due aperture registrate chiedono il menu diagnostico originale `0x36`; non sono una soluzione del ritorno al futuro sottomenu esposizione. Nessuna operazione hardware o SD, nessun firmware modificato; **NON_INSTALLARE**.
