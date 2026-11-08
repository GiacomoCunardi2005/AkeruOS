# Adattatore richiesta iride e risultato software — 2026-11-04

Il prototipo `AkeruOS/camera/iris_action.c` espone `akeru_iris_apply(action, setter, observed)`. Accetta esclusivamente le due azioni del sottomenu, le traduce rispettivamente nei valori software 1 e 9 e invoca una volta il setter passato dal chiamante. Salva il valore restituito in `observed` e restituisce 1 se coincide, 0 se differisce, −1 se l'azione o i puntatori sono invalidi; nei casi invalidi non chiama il setter né tocca `observed`.

Questa è una verifica di **corrispondenza software**, non una conferma di movimento. Un setter che restituisca il valore richiesto può semplicemente averlo trovato già presente; non sono distinti i diversi motivi di mancata corrispondenza. Il chiamante deve ancora gestire visualizzazione, retry, sincronizzazione e conferma fisica, e non è stato installato un binding sulla camera. In particolare il wrapper originale `0x149530` restituisce 1 anche quando lo stato non cambia: il banco usa il setter `0x18B85C` direttamente, non interpreta il wrapper come conferma.

## Verifiche

- [Modello e adattatore host UBSan/GNU ARC700 PASS](../Risultati/GUI_S33/akeru_menu_model_20261104T160805Z/verified_evidence.json): corrispondenza, disaccordo, azione estranea, callback/output nulli, numero chiamate e conservazione output su input invalidi.
- [Snapshot → sottomenu → adattatore → setter originale 14/14](../Risultati/GUI_S33/key_snapshot_menu_iris_cpu_20261104T160805693102Z/verified_evidence.json): due ordini, due direzioni, già uguale, tre rifiuti fixture e controllo ISO. Le pressioni di apertura e selezione sono prodotte dallo scanner; il banco preleva l'azione e chiama **l'adattatore C compilato**, che chiama il setter originale fornito come callback. I rifiuti simulati producono disaccordo, le accettazioni e il caso già uguale corrispondenza; il controllo ISO viene rifiutato dall'adattatore senza invocare il setter.
- [Regressione scanner colore/mono 8/8](../Risultati/GUI_S33/key_scanner_menu_color_cpu_20261104T160805257599Z/verified_evidence.json).

Snapshot, descrittore, ordine, controlli, lock e acquisizione/guardia/richiesta sono fixture o stub. Il banco consegna esplicitamente eventi e azione; non dimostra tasti fisici, movimento, valori f/, concorrenza AE, persistenza o esposizione reale. Firmware originale, SD e fotocamera invariati. **NON_INSTALLARE**.

Riproduzione: `make -C AkeruOS menu-model-verify`; `python3 Python_Trace_Scripts/s33_verify_snapshot_menu_iris_setter_cpu.py`.
