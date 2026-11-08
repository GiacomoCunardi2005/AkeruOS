# S33 V1.1 — Mono RAW e integrità del buffer candidato

27 ottobre 2026. La proposta [Mono RAW Luminance](S33_Mono_RAW_Luminance.md)
richiede dati del sensore utilizzabili, ricostruzione calibrata e un percorso di
salvataggio o codifica. La GUI [ChangeColorMenu](S33_GUI_ChangeColorMenu_Voci_20261027.md)
identifica tre destinazioni EVMenu condizionali: i relativi valori di luminosità,
vivacità e selezione colore non dimostrano un collegamento alla pipeline Mono
RAW, al JPEG o al sensore. Non è stato individuato in queste fonti un interruttore
originale colore / Mono RAW Luminance.

## Un marcatore può alterare il buffer

La statica originale mostra un caso più preciso del limite già annotato nel
[rapporto RAW](S33_HiddenMenu_RAW_Massimo_20261027.md). Nel tratto
`0x1B91EC..0x1B9236`, se il getter del flag restituisce esattamente 1 e il byte
del contesto a `+0x0C` è diverso da `0x0B`, le chiamate ai getter
`0xBC698 → 0x12BE64` e `0xBC69C → 0x12BE6C` forniscono rispettivamente
4208 e 3152; viene chiamato `0x28D5BC` con selettore 2. Il primo argomento
proviene da descrittore+4, il secondo da `r16`. Il diverso ramo `+0x0C == 0x0B`
usa altri getter e non è analizzato qui.

Assumendo semantica normale delle istruzioni aritmetiche e del loop, copia
completa dei 32 byte tramite il servizio `0x128C20`, assenza di overflow degli
indirizzi e nessuna modifica concorrente, il corpo del selettore 2 legge 32
byte a queste posizioni:

```text
base = puntatore descrittore+4 + r16
posizione[i] = base + 4208 × 3152 + i × 2 × 4208,  i = 0..31
```

Per ogni posizione confronta il bit meno significativo con il corrispondente
byte della tabella originale a `0x35231C` e, se diverso, lo sostituisce con tale
bit. I 32 byte originali della tabella sono tutti 0 o 1. La funzione quindi
**può cambiare fino a 32 bit**, non necessariamente tutti: il risultato dipende
dai dati precedenti. La funzione non confronta qui la capacità del buffer con
quelle posizioni. Il servizio di copia e il suo esito runtime non sono eseguiti
in questa verifica.

Le posizioni rispetto a `base` vanno da **13.263.616** a **13.524.512** byte.
Se inoltre `r16 = 0` e il writer successivo usa lo stesso puntatore senza altre
modifiche, queste posizioni ricadono nel tratto richiesto dal writer in modo 3
(26.527.232 byte), ma non nei primi 13.263.616 byte richiesti dal ramo ordinario.
Questo confronto di intervalli non stabilisce la capacità reale, la validità
fisica dei puntatori, l'ordine effettivo o l'integrità complessiva del buffer.
Non descrive quali pixel o campioni siano coinvolti: packing, endian, CFA,
stride e margini rimangono sconosciuti.

## Prerequisiti ancora da chiudere

- Ottenere e verificare un fotogramma reale: lo scatto riferito dall'utente ha
  prodotto un JPEG ma nessun RAW visibile; la causa e il firmware realmente in
  esecuzione non sono accertati. [Diagnosi](S33_Diagnosi_RAW_Assente_20261027.md).
- Stabilire formato, geometria effettiva, packing, CFA, black level e durata
  del buffer; la dimensione richiesta di 4208 × 3152 × 2 non dimostra 16 bit
  utili né un RAW lineare. Valutare anche il marcatore sopra prima di usarlo
  come riferimento di qualità.
- Confrontare su uno stesso frame la ricostruzione RGB lineare calibrata e
  l'eventuale Direct RAW Luminance; collegare infine GUI, preview e output a
  una pipeline verificata, senza assumere che un filtro colore esistente sia
  equivalente. Proprietà e concorrenza dei buffer sono ancora ignote.

Riproduzione: `python3 Python_Trace_Scripts/s33_verify_raw_marker_positions.py`.
**PASS_STATIC_CONDITIONAL**: [evidenza con offset e hash](../Risultati/HiddenMenu_RAW/marker_positions_static_20261027T214405Z/evidence.json),
[finestre GNU](../Risultati/HiddenMenu_RAW/marker_positions_static_20261027T214405Z/disassembly.txt).
Le sei finestre originali sono confrontate al dump storico MainCode; la prova
non esegue la routine, servizi, GUI, sensore o fotocamera. La mappa è riferita
alla V1.1 esaminata e non è automaticamente trasferibile ad altre versioni.
Nessuna scrittura su SD o modifica firmware: **NON_INSTALLARE**.
