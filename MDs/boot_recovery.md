# TBIB: sorgenti alternative del MainCode prima del trasferimento

19 ottobre 2026, R4, solo analisi statica del firmware Nikon V1.1. Questa verifica riguarda la metà boot della domanda sul recupero; non dimostra che l'updater pubblico preservi il TBIB fisico.

**Risultato concreto:** il TBIB contiene un caricatore di file RHIR e una selezione di sorgenti che può raggiungere `B:\TBM_SK501.BIN` dopo un errore del caricatore a settori, prima dell'ingresso MainCode. È un candidato di avvio alternativo indipendente dall'esecuzione del MainCode, sotto le guardie seguenti. Non equivale a recupero dimostrato, né al percorso pubblico `firmware/firmware.bin`.

## Identità e mappa

[Verificatore](../S33-sections/safety_audit_codex/boot_recovery.py), [evidenze JSON](../S33-sections/safety_audit_codex/boot_recovery_evidence.json), [finestre GNU](../S33-sections/safety_audit_codex/boot_recovery_gnu.txt). Riproduzione: `python3 S33-sections/safety_audit_codex/boot_recovery.py`.

Il verificatore confronta il contenitore originale di 29.602.084 byte con SHA-256 `1d34e990a8f99019ffa53ca5de785399df863e942739a667ceb314ec6ce62a39`; confronta integralmente il TBIB estratto con il contenitore da offset `0x6C`, controlla il checksum del corpo e riusa la verifica dei 16 payload TBM. Header TBIB: base/ingresso `0x01000000`, corpo `0x44BBC` byte, checksum `0xF3F78173`.

Per le istruzioni qui riportate: `offset_payload = VA−0x01000000+0x10`; `offset_firmware = VA−0x01000000+0x7C`. Il roundtrip ELF conserva tutti i byte del corpo. GNU usa `-m arc:ARC700 -EL` e finestre con ingressi riancorati. La tabella originale a `0x010417C4` contiene ID `0x40400001`, entry `0x01001384`, puntatore nome `0x010425C6 = BootTask`.

## Selezione delle sorgenti nel BootTask

Il primo controllo a `0x0100139C` deve ritornare zero per raggiungere la selezione; il ruolo completo di quel servizio non è qui attribuito. La selezione avviene nel corpo TBIB, non nel MainCode.

| Ordine | Istruzioni e guardie | Sorgente passata al lettore |
|---|---|---|
| 1, tentativo anticipato | `0x010013AE..3BC`: byte `[0x01041104]==1` e ritorno `0x01000488!=0`; `bl.d 0x0100125C` a `0x010013C0`, r1 preparato nel delay slot | r0=`B:`, r1=`B:\TBM_SK501.BIN` dai pool `0x0100144C/450` |
| 2, caricatore a settori | se il tentativo anticipato non è selezionato o fallisce, chiamata `0x010010C0` a `0x010013D0` | Il wrapper inferiore `0x0100A120` usa selettore6, ma l'identità del namespace e la sua mappa fisica richiedono un collegamento ulteriore |
| 3, fallback file A | solo quando il ritorno del caricatore a settori è nonzero (`mov.f r14,r0` a `0x010013D4`, ramo a `0x010013DC`); `bl.d 0x0100125C` a `0x010013EA`, r1 nel delay slot | r0=`A:`, r1=`A:\TBM_SK501.BIN` dai pool `0x01001454/458` |
| 4, fallback file B | solo se fallisce anche A, byte `[0x01041105]==1` e `0x01000488!=0`; chiamata `0x01001408` con delay slot a `0x0100140C` | r0=`B:`, r1=`B:\TBM_SK501.BIN` dai pool `0x01001460/464` |

Il risultato finale viene scritto da `0x01001426` nella cella `0x01041108`. Una lettura riuscita non prova automaticamente che si arrivi al successivo trasferimento: inizializzazioni, condizioni di avvio e gestione degli errori restano necessarie. Il significato fisico A:/B: non è dimostrato da queste sole stringhe; B: è una pista SD, non un'equivalenza qui assunta.

Il lettore file `0x0100125C` apre/consulta il file attraverso servizi TBIB, verifica una lettura di 16 byte e il magic RHIR a `0x010012CA`, scorre i descrittori a `0x010012F6..338` e chiama `0x010011BC` per ciascuno. Quest'ultimo per tipo1 usa offset/conteggio con shift9, destinazione descrittore+8 e confronto checksum; per tipo2 copia la parola descrittore+4 nella cella `0x01041100`. Per altri tipi il tratto ritorna zero senza la stessa operazione. Nel TBM originale il tipo2/record16 vale `0x000BB540`, già ricostruito nel [rapporto del trasferimento](S33_Passaggio_TBIB_TBM_e_Ingresso_CPU.md). La chiamata indiretta `jl_s [r14]` a `0x010000D8` consuma la cella.

**Formato distinto:** `TBM_SK501.BIN` è un file che questo lettore si aspetta inizi con RHIR. Il pacchetto pubblico `firmware.bin` inizia con un contenitore e colloca RHIR a offset `0x480B8`. La presenza del lettore TBIB non autorizza a trattare il pacchetto pubblico come suo input diretto.

## Provenienza locale delle guardie

I due byte nel payload originale valgono rispettivamente **0 e 1**. Nel prefisso di inizializzazione TBIB `0x010000EC`, r17 è impostato a zero; il tratto `0x010002BE..2C4` può poi scrivere `+4=1` e `+5=0` rispetto a base `0x01041100`. La condizione è il bit15 del campo base+`0x2C`, precedentemente riempito con il complemento del risultato di `0x01005A2C` (`0x010002A4..2B0`). La sorgente/semantica completa della query e l'assenza di altri writer runtime non sono dimostrate da questa verifica.

`0x01000488` legge il byte `0x01041104`: se nonzero ritorna1; altrimenti chiama `0x01007168` con r0=0. Quest'ultimo confronta r0 con byte `[0x01041274]` e, se uguale, chiama `0x0101FCC4`, altrimenti ritorna0. Non si attribuisce a questa guardia una combinazione di tasti o una presenza scheda senza seguire il backend.

## Perché il recupero rimane non dimostrato

Il codice TBIB fornisce una pista concreta precedente al MainCode. Per chiudere la sopravvivenza servono ancora questi collegamenti, distinti:

1. **Reset/ROM → TBIB:** il campione distribuito contiene TBIB, ma non la prova della selezione ROM, della copia fisica eseguita e di eventuali guardie che dipendano dal contenuto MainCode. L'intervallo CPU `[0x01000000,0x01044BBC)` è la mappa di analisi del corpo, non un intervallo NAND dimostrato.
2. **Updater pubblico → regioni fisiche:** dimostrare se/come il percorso ordinario scrive il TBIB e ogni metadato necessario per selezionarlo, anche su errore/interruzione. TBIB immutato nel pacchetto patchato non significa TBIB non riscritto.
3. **Fallback file → supporto accessibile:** mappa A:/B:, guardia `0x01000488`, completamento init/driver, destinazioni e controlli dei descrittori, esiti prima del trasferimento. Un tentativo statico di lettura non certifica una macchina recuperabile.
4. **Boot alternativo → ripristino:** caricare MainCode da file non dimostra la disponibilità di una funzione di riscrittura dopo il guasto; va collegato al contratto dell'updater con eventuali risorse mancanti.

Verifica effettiva: 16 identità payload, identità/checksum TBIB, 1 roundtrip ELF, 11 finestre GNU, 43 istruzioni chiave, 17 parole e 6 stringhe di percorso più nome BootTask. Nessuna emulazione dell'intero boot, nessun hardware e nessuna modifica firmware. V1.1 non trasferito automaticamente alla macchina V1.0. Avanzamento funzionale AkeruOS circa10%, invariato.

## Continuazione — guardia e produttore eseguiti

La [verifica successiva](S33_NAND_PC_TBIB_Guardia_Produttore_e_Selezione_Fallback.md) collega il bit4 diFED2068 e i registriFE70224/228 ai predicati originali, poi esegue256routing con servizi simulati. Il byteINFO20 può comparire anche quando falliscono tutti i file. Nessuna combinazione di tasti o proceduraSD fisica attribuita; proseguire sul lettorefile0100125C e sull’identità dei supporti.
