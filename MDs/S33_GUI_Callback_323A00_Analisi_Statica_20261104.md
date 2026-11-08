# Callback tasti 0x323A00 — analisi statica

Data: 2026-11-04. Ambito: listato `Risultati/Disassemblati/Firmware1.1.asm`, firmware 1.1. Nessuna esecuzione CPU o su fotocamera in questa analisi; nessuna modifica al firmware. Stato: **NON_INSTALLARE**.

## Registrazione e percorso

Nel codice a 0x323848–0x32385A, se la word del contesto a offset 0x14 è zero, viene impostata a 1 e viene chiamata 0x16F988 con 0x323A00 caricato dal pool 0x3239DC nello slot di ritardo. Il pool 0x3239D0 contiene 0x00370664. La registrazione 0x16F988 verifica prima la presenza del puntatore e, se assente, cerca una cella libera fra dieci: il suo ordine effettivo dipende dallo stato e dalla sequenza runtime.

Il fan-out 0x16F6B0 passa (classe, stato, puntatore a copia dell'evento) e visita la tabella nell'ordine degli slot. Un ritorno zero impedisce l'invocazione delle callback successive e l'inserimento nell'anello; un ritorno nonzero permette di proseguire, ma non garantisce l'inserimento: restano le altre guardie del fan-out.

## Corpo 0x323A00–0x323A3B

La callback controlla `stato == 1` e `classe == 1` (0x323A10–0x323A16). Per ogni altra coppia restituisce 1 senza scrivere il contesto. Non legge né modifica il puntatore all'evento in r2. Nel caso classe 1 e stato 1 legge la word a `0x370664 + 0x0C` e usa un confronto **signed** con 130:

| Word a +0x0C | Word a +0x08 | Word a +0x14 | Ritorno |
|---|---:|---:|---:|
| <= 130 signed | 1 | 0 | 0 |
| > 130 signed | 0 | 1 | 0 |

Le istruzioni sono a 0x323A18–0x323A38; l'epilogo condiviso parte da 0x323636. Il significato operativo del contesto e la durata dei suoi stati non sono dimostrati da questo controllo isolato.

## Conseguenza per i quattro slot

Nel banco e nella mappa già documentati le classi dei quattro slot AkeruOS sono 11 (`0x580/581`), 14 (`0x700/701`), 67 (`0x2180/2181`) e 78 (`0x2700/2701`). Se questa callback viene effettivamente invocata con una di queste classi, il suo corpo restituisce 1 e non cambia il contesto; non distingue pressione, rilascio o valore dell'evento per tali classi. Questo **non** dimostra che la callback sia sempre invocata, né che l'evento raggiunga la GUI: l'ordine delle callback, 0x16E588 e le guardie dell'anello restano determinanti. I numeri sono classi logiche, non identificazioni provate dei pulsanti fisici.

Fonti precedenti: [mappa macchina tasti](S33_GUI_Macchina_Tasti_0x16F630_Mappa_Bit_Evento_CPU_20261101.md), [callback 0x16E588](S33_GUI_Macchina_Tasti_Callback_16E588_CPU_20261101.md). Da verificare: esecuzione del fan-out con entrambe le callback originali e ordini/guardie controllati, poi corrispondenza pulsanti fisici e navigazione GUI. Nessuna conclusione nuova sui valori ISO, diaframma, tempo o monocromatico.
