# Tre AUX nel prefisso originale di cambio contesto

25 ottobre 2026. PASS offline su prefisso e fixture dichiarate.
Mappa fisica incompleta; NON_INSTALLARE.

Atlante: `Risultati/Processor_Registers/20261025T202612Z/REGISTER_MAP.md`.
1179 voci: 64 posizioni core, 200 AUX, 915 MMIO. Tre nuovi indici AUX;
nessun nuovo MMIO o finestra. Tutte le schede precedenti sono conservate,
con sola rilocazione dei percorsi AUX generati. Verificati i 41 atlanti PASS
precedenti: nessuna chiave o geometria persa. Le 50 finestre e le due famiglie
MMIO calcolate restano invariate.

## Indici e istruzioni originali

| Indice AUX | Lettura | Scrittura | Ruolo software osservato |
|---|---|---|---|
| `2F` | `B3334` | `B337C` | Prima parola del buffer di contesto |
| `32` | `B3348` | `B3390` | Seconda parola, selezionata dal flag `20000` |
| `33` | `B3350` | `B3398` | Terza parola, selezionata dallo stesso flag |

LR/SR e copie RAM trasportano 32 bit nei test. Questo non certifica la
larghezza fisica, i permessi o gli effetti dei registri sul SoC Nikon.
I nomi nell'atlante sono neutrali: `KERNEL_AUX_2F/32/33_PHYSICAL_UNKNOWN`.

Le definizioni GNU non autorizzano un nome di periferica Nikon:
`aux_fbf_store_16` a 2F è marcata ARC600; `aux_crc_poly` e `aux_crc_mode`
a 32/33 hanno applicabilità `ARC_OPCODE_NONE`. Non viene quindi attribuito
un blocco CRC o FBF alla S33.

## Contratto del prefisso

L'esecuzione inizia dal codice originale a `B2E12`. Il flag `00000008`
nel contesto in ingresso seleziona il ramo a `B3318`.

- `[r2+36]` contiene il puntatore corrente; r3 è il contesto in ingresso.
- Se il puntatore corrente è diverso dal nuovo ed è nonzero, il codice
  salva 2F a `[[corrente+200]]`. Con flag `00020000` nel contesto corrente
  salva anche 32/33 agli offset 4/8. Imposta poi `00000100` nei suoi flag.
- Il puntatore corrente viene sostituito con r3. Se i flag del nuovo contesto
  contengono `00000100`, il codice ripristina 2F; con `00020000` ripristina
  anche 32/33. Alla fine cancella `00000100` nei flag in ingresso.
- Contesto corrente uguale al nuovo e gate `00000008` disabilitato sono
  percorsi senza accessi ai tre AUX nei test.

Questi sono ruoli e trasformazioni software locali; non è stata dimostrata
la raggiungibilità globale del cambio contesto o la gestione fisica degli IRQ.

## Lettura nel delay slot con puntatore nullo

`B3320` è un `beq.d`: il caricamento a `B3324`, `ld r10,[r0,200]`, viene
eseguito anche quando r0 è zero e il salto viene preso. Il suo indirizzo
effettivo è quindi `C8`.

Il primo test nullo senza input dichiarato si è fermato sul read a C8.
Nelle prove completate l'harness scrive esplicitamente un valore a C8 prima
di entrare nel codice originale; il tracker conferma la successiva lettura.
Sono quattro casi, due percorsi nulli per due pattern. Il dato non viene
assunto zero, reset o RAM libera. Non è prova di un difetto hardware: la
mappa fisica di quell'indirizzo non è stata interrogata.

## Evidenze e confine delle prove

CPU: `outputs/gnu_arc700/20261025T202451Z_4bf1977d/`.
Audit: `Risultati/Processor_Registers/20261025T202612Z/evidence/kernel_aux_context_audit.json`.

Sedici scenari: otto percorsi per due pattern AUX/RAM. Verificati 32 accessi
originali (16 letture e 16 scritture), inclusi valori con bit alto impostato,
zero e FFFFFFFF. Per ogni scenario confrontati tutti i 2048 byte della fixture
RAM, non soltanto le parole attese modificate. I salvataggi parziali devono
conservare le parole non selezionate e tutti i byte estranei.

Il prefisso termina su un **confine di decoder dichiarato a B2E22**, con
exit 5 atteso. Non è un ritorno completato del kernel né un errore hardware.
Il decoder può effettuare lookahead: non si attribuisce avanzamento oltre
il prefisso sulla base della sola stampa della traccia. Le scritture nel
delay slot finale sono verificate anche nel file RAM estratto.

Le sei istruzioni originali sono integrate nell'audit delle tracce AUX:
25 indici con risultati guest osservati e 204 siti per coppia run/PC
(prima 22 e 172). I 32 eventi nuovi appartengono a dieci run con accessi;
gli altri sei scenari verificano i percorsi senza accessi.

Riproduzione:

1. `python3 Python_Trace_Scripts/s33_verify_kernel_aux_context.py`
2. `python3 Python_Trace_Scripts/s33_integrate_kernel_aux_context.py outputs/gnu_arc700/20261025T202451Z_4bf1977d`

Il verificatore riusa il frontend libsim esistente con osservatore memoria
disabilitato; non aggiunge dispositivi AUX, non cambia la banca GNU e non
modifica il firmware. Tutti i valori AUX iniziali sono scritti dall'harness,
quindi non sono letture di reset Nikon. Le copie codice includono ulteriori
byte **originali** per il lookahead del decoder; non sono padding inventati.

I tentativi precedenti sono conservati come FAIL e non ammessi. Hanno
evidenziato una dipendenza dal frontend, una finestra di mapfile insufficiente,
l'input mancante a C8 e un conflitto con il segmento ELF basso: quest'ultimo
è stato risolto mediante store dichiarato nell'harness. Una correzione del
parser ha inoltre accettato il PC stampato con zero iniziale. Questi sono
limiti/configurazioni dei test; nessuna patch al codice originale.

## Ancora aperto

Nomi e implementazione fisica dei tre AUX, reset, effetti SR, IRQ, mappa RAM
fisica, cambio contesto completo e domini reali dei task. Restano inoltre
BCR/SoC, altri candidati AUX codice/dati e DSP fisica. Nessun hardware,
USB, NAND o SD toccato; originali e GNU invariati. Il goal resta attivo.
