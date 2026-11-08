# S33 V1.1 — tabella e preparazione dei descrittori grafici

Analisi statica offline del 27 ottobre 2026. Gli indirizzi sono quelli della
mappa candidata dei payload V1.1; le finestre indicate e lo stato iniziale
sono confrontati byte per byte con `DUMPS/MainCode.dmp`. Non è un'immagine
RAM acquisita durante l'uso della GUI.

## Tabella dei descrittori

Il lookup `0x23B20C`, raggiunto dal percorso grafico di CaptureMenu, legge
dal contesto `0x36A5E0` il puntatore alla tabella a `+0` e il limite signed
a `+4`. La routine `0x23B19C` scrive rispettivamente il proprio primo
argomento e la metà bassa del secondo in quei due campi. La sua presenza
non dimostra chi la invochi o quali valori siano configurati a runtime.

Nel payload iniziale le word a `+0` e `+4` valgono zero; anche `+0x14` e
`+0x18`, usati nel percorso compresso seguente, sono zero. La word `+8` vale
`0x2C8380`. Non è lecito usare questa immagine iniziale come tabella attiva.
Il lookup legge `tabella[ID]` **prima** di confrontare l'ID con il limite e
non controlla prima il puntatore alla tabella; con stato non inizializzato o
ID non valido il comportamento dipende dalla memoria effettivamente mappata.
Il controllo successivo rifiuta una voce nulla o un ID non inferiore al limite.

## Preparazione dell'immagine

La routine `0x23B4B4`, raggiunta da `0x23B5C8`, copia 20 byte dal descrittore
su stack tramite `0xAD920`. Se il byte `+8` della copia è diverso da zero,
chiama `0x23B234` prima dei passaggi di clipping e della callback grafica.
Questa modifica la **copia**, non dimostra modifiche al descrittore originale.

Nel caso `+8 = 1`, l'analisi del ciclo `0x23B27A`–`0x23B2CE`, per dimensioni
positive e dati validi, mostra una codifica a byte:

- il numero di elementi di ciascun blocco è il byte di controllo spostato a
  destra di un bit, limitato agli elementi ancora necessari;
- se il bit basso è zero, il byte successivo viene ripetuto; se è uno, vengono
  copiati i byte letterali successivi;
- il numero totale richiesto è il prodotto dei due halfword signed a `+0` e
  `+2`. Il risultato va nel buffer a `contesto+0x14`; se nullo si ha errore,
  e `contesto+0x18`, quando non zero, è un limite sul prodotto. Al termine
  la copia riceve il puntatore al buffer in `+0x10` e zero nel byte `+8`.

Nel caso `+8 = 0x80`, i primi quattro byte alla sorgente `+0x10` vengono
usati come due offset e due dimensioni; il puntatore avanza di quattro byte,
il campo `+4` è calcolato da dimensione e halfword `+6`, e il byte `+8` è
azzerato. Formato di pixel, colori e callback effettiva non sono qui risolti.
Non è stato verificato il comportamento con dati malformati, altri valori di
`+8`, lunghezza della sorgente o concorrenza sul buffer condiviso.

## Verifica e limiti

Il [verificatore](../Python_Trace_Scripts/s33_verify_gui_graphic_resource_format.py)
ha dato PASS sulle finestre GNU, i campi iniziali e il confronto con il dump;
[disassemblaggio e risultato](../Risultati/GUI_S33/graphic_descriptor_20261027T175726Z/)
consentono di ripetere l'analisi. I controlli di testo delle istruzioni non
eseguono il decodificatore: il formato è una lettura statica circoscritta.

Resta sconosciuta l'origine runtime della tabella ID→descrittore, compresi
gli ID di CaptureMenu 222–807: non si possono associare con certezza le
icone né ricostruire i pixel effettivi dai soli collegamenti qui verificati.
Una ricerca esplorativa con disassemblaggio lineare e letterali non ha trovato
chiamanti diretti del setter; non esclude entry alternative, chiamate indirette
o indirizzi calcolati. Nessuna prova di display o hardware; **NON_INSTALLARE**.
