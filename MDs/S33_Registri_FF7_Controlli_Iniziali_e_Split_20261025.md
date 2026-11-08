# Nikon S33: controlli FF7 iniziali e scritture divise in halfword

> Aggiornamento del 25 ottobre 2026: questo checkpoint da 800 voci ometteva
> un ramo già verificato. L’unione corretta contiene 929 voci; due nuovi parametri
> portano il successivo atlante a 931. Quattro dei sette writer indicati come
> prossimi avevano già prove CPU nell’altro ramo. Vedi
> [riconciliazione e prove successive](S33_Registri_Riconciliazione_Rami_e_FF7_Raw_20261025.md).


Data: 25 ottobre 2026. Stato: mappa fisica incompleta; obiettivo attivo.

L’atlante consolidato contiene **800 voci: 64 posizioni core, 197 indici AUX e
539 indirizzi MMIO singoli**. Le posizioni core includono encoding opzionali,
riservati e speciali; non sono 64 registri fisici dimostrati. Separatamente sono
rappresentate **14 finestre di trasferimento con 2.937 offset di cella** e due
famiglie MMIO indicizzate con dominio dei chiamanti ancora irrisolto.

Rispetto al precedente atlante sono aggiunti 37 indirizzi singoli, due finestre
con sette celle e quattro siti run/PC AUX, per 108 siti e 22 indici distinti.
Nessuna nuova attribuzione fisica o verifica sul silicio Nikon. Il totale fisico
dei registri resta sconosciuto: non esiste una percentuale globale dimostrabile.

## Fonti riproducibili

- Atlante: `Risultati/Processor_Registers/20261025T152133Z/REGISTER_MAP.md`;
  JSON, CSV, grafo e `atlas_validation.json` nella stessa directory.
- Parent immutato: `Risultati/Processor_Registers/20261025T150447Z/`,
  177 file del ledger SHA-256 verificati prima e dopo l’integrazione.
- CPU: `outputs/gnu_arc700/20261025T151429Z_57c4519d/verified_evidence.json`;
  copia mantenuta nell’atlante come `evidence/ff7_early_controls.json`.
- Audit indipendente: `evidence/ff7_early_controls_audit.json` nell’atlante;
  disassemblato e tre script di verifica/audit/integrazione conservati accanto.
- Script correnti: `Python_Trace_Scripts/s33_verify_ff7_early_controls.py`,
  `s33_audit_ff7_early_controls.py`, `s33_integrate_ff7_early_controls.py`.
- Originale firmware SHA-256:
  `1d34e990a8f99019ffa53ca5de785399df863e942739a667ceb314ec6ce62a39`.
- Main originale SHA-256:
  `06754a1f451f17b3047fe03cdb83fd08af11dac725638818254ef0de26a5ed29`;
  base software `0xAD800`, 2.810.880 byte, verificato contro il contenitore.

Il ledger del nuovo atlante contiene 183 file. I candidati successivi sono
conservati separatamente: non modificano quel ledger o i conteggi consolidati.

## Dodici indirizzi di controllo e parametri iniziali

Tutti gli accessi osservati sono halfword. Le descrizioni sono operazioni del
software, senza dedurre nomi periferici, reset, permessi hardware o W1C.

| Indirizzo | Entry originale | Operazione software verificata |
|---|---|---|
| `FF70800` | `2E0040` | RMW: imposta sempre bit0; argomento r0 ignorato |
| `FF70838` | `2E005C` | RMW bit0: set solo per r0==1, altrimenti clear |
| `FF70844` | `2E0090` | RMW bit0: set solo per r0==1, altrimenti clear |
| `FF70C00` | `2E00C4`, `2E00EC` | Sostituisce bits0..1 con r0&3 oppure bits2..3 con (r0<<2)&C |
| `FF70C60` | `2E0118` | Scrive uint16(r0 OR (r1<<8)) |
| `FF70C64` | `2E0130`, `2E015C` | Sostituisce bits4..5 oppure low4; conserva gli altri bit |
| `FF70CC4` | `2E015C` | Scrive low16 di r1 dopo il RMW di FF70C64 |
| `FF70CC8` | `2E0194` | Prima scrittura: uint16(r0 OR (r1<<4)) |
| `FF70CCC` | `2E0194` | Seconda scrittura: uint16(r2 OR (r3<<8)) |
| `FF71000` | `2E0258` | RMW bit0: set solo per r0==1, altrimenti clear |
| `FF71004` | `2E028C` | Prima scrittura: low16 di r0 |
| `FF71008` | `2E028C` | Seconda scrittura: low16 di r1 |

Negli OR con shift gli operandi non sono mascherati separatamente: possono
sovrapporsi. Non sono dimostrati campi indipendenti da quattro/otto bit.

## Venticinque destinazioni FF77000..FF77060

Le sette entry `2E0318`, `2E032C`, `2E0340`, `2E0354`, `2E04D0`, `2E04E4`,
`2E04F8` scrivono low16 di r0, rispettivamente a `FF77000/04/08/0C/58/5C/60`.

Le nove entry da `2E0368` a `2E04A8`, passo `0x28`, dividono r0 in due
scritture: prima low16, poi il risultato dello shift logico di 16 bit.
Le destinazioni sono coppie da `FF77010/14` a `FF77050/54`, passo otto.
L’atlante conserva relazione, ruolo low/high e ordine per ogni destinazione.
**Due scritture ordinate a 16 bit non provano atomicità o un registro fisico a
32 bit.** Argomenti controllati: 0, FFFFFFFF, 1234ABCD e 80000001.

## Due piccole finestre mantenute separate

`2E01C8` scrive quattro halfword con passo quattro da `FF70C68`, usando
esattamente 15 halfword d’ingresso. Con v[i]=input[i]&F:

- cella0=(v0<<4)|(v1<<8)|(v2<<12), con low4 sempre zero;
- cella1=v3|(v4<<4)|(v5<<8)|(v6<<12);
- cella2=v7|(v8<<4)|(v9<<8)|(v10<<12);
- cella3=v11|(v12<<4)|(v13<<8)|(v14<<12).

`2E02B0` scrive tre halfword con passo quattro da `FF7100C`, usando nove byte:
cella0=byte0|(byte2<<8), cella1=byte4|(byte6<<8),
cella2=byte8|((r1&7)<<8). I byte1/3/5/7 sono ignorati; bits11..15 dell’ultima
uscita sono zero. Entrambe le routine scrivono sempre, senza flag skip.

Le sette celle non sono ammesse come sette registri di controllo indipendenti.
La semantica fisica può essere un array o una finestra di memoria periferica.

## Verifiche e limiti sperimentali

PASS: 11 scenari, 22 run e 348 chiamate originali includendo i replay.
L’osservatore esterno registra 331 accessi completati: 304 sugli indirizzi
singoli e 27 scritture nelle due finestre. Tutte le 11 coppie di tracce
osservatore spento/acceso sono identiche byte per byte. L’audit ricostruisce
maschere, valori, ordine e packing dagli argomenti e byte iniziali, senza usare
le sequenze attese del verificatore come proprio oracolo.

Tre equivalenze metamorfiche verificano nibble alti ignorati, byte dispari
ignorati e bit alti di r1 ignorati. Un input r1=8 verifica il troncamento a tre
bit. SP e sentinelle r13..r16 sono conservati dopo ogni chiamata.

I quattro siti SR aggiunti riguardano LP_START/LP_END; il valore tracciato è
l’operando del setter, non necessariamente lo stato AUX successivo. La
verifica dei 108 siti confronta byte originali e disassemblato riallineato.

Input a `0x700000`, MMIO iniziali 0/FFFF/A55A, backing e padding A5 sono
fixture sintetiche. Non provano RAM libera, stato di reset, permessi,
interrupt, latenza o comportamento periferico reale. GNU, sorgenti/build e
firmware originali restano invariati; nessun accesso hardware. NON_INSTALLARE.

## Prossime routine: sovrapposizione individuata

Il nuovo censimento statico mirato è in
`Risultati/Processor_Registers/ff7_raw_window_candidates_20261025T152600Z/candidates.json`,
con script conservato e ledger separato. Verifica i byte delle istruzioni,
conteggi LP, pool LP_START/END, carico halfword, passo input due e output quattro
per sette routine. Non è ancora una prova CPU dei sette writer.

| Entry | Base uscita | Celle |
|---|---|---:|
| `2E0F30` | `FF741DC` | 33 |
| `2E0F70` | `FF74044` | 33 |
| `2E0FB0` | `FF74260` | 9 |
| `2E0FF0` | `FF74284` | 9 |
| `2E10F0` | `FF760D0` | 9 |
| `2E1298` | `FF76128` | 33 |
| `2E12D8` | `FF761AC` | 17 |

Il range da FF74044 attraversa le 17 celle della finestra packed7_a,
15 celle di packed7_b e il parametro FF74088 già catalogato. Ciò richiede
contratti di writer sovrapposti: aggiungere tutte le celle come nuovi registri
o trattare i range come periferiche disgiunte gonfierebbe la mappa. Nessuna
ammissione viene fatta da questo solo censimento. La routine 2E10F0 presenta
anche due parametri di coda FF760F4/F8, legati staticamente ai pool e store.

Restano aperti le esecuzioni di questi writer, gli altri blocchi FF7/FFB/FFC,
i domini dei chiamanti indicizzati, i candidati AUX codice/dati, BCR e
configurazione reale del SoC, oltre alla semantica e verifica hardware.
