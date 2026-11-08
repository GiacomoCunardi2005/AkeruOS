# S33 — ricerca di un frame RAW locale

28 ottobre 2026. L'inventario non ha individuato un **frame RAW S33 con
provenienza verificata** utilizzabile per sviluppare Mono RAW Luminance.
Questo non dimostra che nessun frame esista sotto un nome, una dimensione o
un percorso diverso da quelli verificati.

## Inventario e provenienza

Il [risultato completo](../Risultati/Mono_RAW/inventory_20261028/inventory.json)
elenca 124.258 file regolari, inclusi nomi nascosti, sul filesystem della radice
del progetto. La scansione ha usato nomi e metadati, senza seguire symlink;
sono escluse le directory di primo livello `tools`, `work`, `Research` e `.git`
e altri filesystem. Nessun errore di scansione riportato. La lista comprende
anche tutti i file tra 10 e 30 MiB, senza classificarli come immagini.

Tra le estensioni `.nef`, `.nrw`, `.dng`, `.raw`, `.rw2`, `.cr2`, `.cr3`,
`.arw`, i 14 file trovati sono `dump.raw` in cartelle delle prove NAND PC:
dimensioni 135.168 o 270.336 byte. Sono dati di test NAND, non frame fotografici:
il [generatore della prova](../Python_Trace_Scripts/s33_verify_nand_pc_dump.py)
usa pattern e un trasporto simulato; la
[fixture nota](../Python_Trace_Scripts/s33_verify_nand_pc_dump_journal.py)
è una finestra offline di `NANDP1.dmp`, con provenienza registrata nel suo
manifest. Le copie alterate servono alle prove del journal.

Nessun file censito misura esattamente 13.263.616 o 26.527.232 byte, le due
lunghezze **richieste** dal writer nelle prove sintetiche del percorso RAW.
Questa verifica non esclude frame con intestazione, troncati, compressi, con
altre dimensioni o in archivi. La lunghezza richiesta non prova capacità,
contenuto o packing del buffer reale. L'osservazione storica della SD del 27
ottobre riportava un JPEG ma nessun RAW visibile; non è una nuova ispezione
della SD. [Diagnosi e limiti](S33_Diagnosi_RAW_Assente_20261027.md).

## Prossimo approfondimento offline

Seguire l'inizializzatore originale `0x18E4B4` e la sua chiamata fino alla
base e alla dimensione usate per gli elementi del pool; poi verificare in CPU,
con regione e code sintetiche, il passaggio del puntatore
`elemento+8 → descrittore+4` in `0x18ED60` e il suo ciclo fino alla
pubblicazione. La [ricostruzione statica dei descrittori](S33_Descrittori_e_Ciclo_Buffer.md)
descrive già tale passaggio e distingue le due code; una prova concatenata può
testare il contratto software senza pretendere di individuare memoria fisica
libera o di produrre un fotogramma. Per stabilire CFA, profondità e packing
serve comunque un campione reale di provenienza accertata.

Nessun dump, comando alla fotocamera, modifica alla SD, firmware o toolchain è
stato eseguito o prodotto per questo inventario. Stato: **NON_INSTALLARE**.
