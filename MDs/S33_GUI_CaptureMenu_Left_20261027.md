# S33 V1.1 — evento Left dentro CaptureMenu

27 ottobre 2026. Analisi statica offline dei byte del firmware originale,
confrontati con `DUMPS/MainCode.dmp`. Non è stata eseguita la fotocamera.

## Percorso condizionale

Il descrittore dell'oggetto `0x02`, nome interno `CaptureMenu`, assegna il
wrapper `0x7CAFE8`. Il wrapper passa l'evento al dispatcher `0x169F60`,
insieme al filtro a `0x899858` e alla tabella `0x982384`. Se il filtro non
contiene l'evento, la voce `0x480` chiama `0x7CB0F8`. Il comando diagnostico
`KeyLeft` produce l'evento `0x480` nel caso studiato separatamente: questo
non identifica un interruttore fisico né prova la consegna a CaptureMenu.

L'handler non tratta `0x480` come una semplice selezione della lista: chiama
`0x20E814` con lo stesso contesto, evento **`0x2180`** e terzo argomento zero.
Questo secondo dispatcher usa la tabella `0x3E8BB4`, la cui voce `0x2180`
punta a `0x20E940`. Se le guardie consentono di proseguire, il percorso chiama
`0x1453E4(0x87, 0)`. La tabella oggetti identifica `0x87` come
`AutoSceneLiveView` (descrittore `0x783AE8`). È una richiesta al servizio,
non una prova che la schermata si apra o sia mostrata.

## Guardie osservate

L'handler `0x20E940` esce prima della richiesta quando:

- `0xCB4A8()` restituisce 2, oppure la prima chiamata `0xCAD5C()` restituisce 3;
- `0x17BE18(0, 0x3101, 0x3101)` restituisce un valore diverso da zero;
- una delle due letture `0x16F920(0x61)` coincide con il risultato di
  `0x16E41C(0x0B)` o rispettivamente `0x16E41C(0x0C)`; nel codice V1.1
  verificato quest'ultima routine restituisce `r0=0x2A`, `r1=0` per entrambi;
- dopo la chiamata `0x1564C0(1)`, la prima chiamata `0x1453FC()` restituisce
  1 oppure, se si arriva alla seconda, questa restituisce `0x7E`.

Le letture ripetute non sono necessariamente uguali. Dopo queste guardie,
una seconda lettura `0xCAD5C()` governa un ramo aggiuntivo di servizi; il suo
esito non elimina la successiva chiamata `0x1453E4` nel flusso statico
considerato. I significati e gli effetti dei servizi non sono attribuiti in
questa analisi. Prima della richiesta il codice chiama anche `0x17C074` per
quattro eventi (`0x81`, `0x80`, `0x101`, `0x100`), con primo argomento zero e
terzo argomento quello ricevuto dal secondo handler; l'esito è ignoto.

Il filtro è RAM: i byte presenti nel dump inizialmente elencano `0x500` e
terminatore zero, ma il contenuto runtime può cambiare. Anche la presenza
in tabella di un callback non prova che il wrapper venga invocato.

## Evidenza e limiti

[Verificatore](../Python_Trace_Scripts/s33_verify_gui_capturemenu_left_route.py)
e [finestre GNU](../Risultati/GUI_S33/capturemenu_left_route_20261027T174825Z/gnu_windows.txt)
controllano descrittori, tabelle e codice contro il dump; risultato
[PASS statico circoscritto](../Risultati/GUI_S33/capturemenu_left_route_20261027T174825Z/evidence.json).
Non sono verificati recapito, scheduler, stato runtime del filtro, valori o
side effect dei servizi, apertura della finestra, rendering o hardware. Non è
stata eseguita alcuna modifica firmware; candidati **NON_INSTALLARE**.
