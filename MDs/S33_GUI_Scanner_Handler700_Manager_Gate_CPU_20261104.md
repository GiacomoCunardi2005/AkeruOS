# Tasto 0x700 e gate del manager originale — CPU emulata

Data 2026-11-04, firmware campione 1.1. [Verificatore](../Python_Trace_Scripts/s33_verify_key_scanner_manager700_cpu.py), [evidenze 8/8 PASS](../Risultati/GUI_S33/key_scanner_manager700_cpu_20261104T105825491333Z/verified_evidence.json); [regressione handler 6/6 PASS](../Risultati/GUI_S33/key_scanner_handler700_cpu_20261104T105851678039Z/verified_evidence.json). **NON_INSTALLARE**.

## Percorso e fixture

Il banco integra il [percorso scanner → CaptureMenu → tabella condivisa → handler 0x700](S33_GUI_Scanner_Tabella_Condivisa_Handler700_CPU_20261104.md) con wrapper originale 0x1453E4, risolutore originale 0x14507C e commutatore originale 0x145180. La tabella originale 0x3F5900 e i descrittori originali CaptureMenu 0x9802AC e ID 0x3F a 0x989FCC sono caricati da payload verificati; le finestre sono ricontrollate dopo il link. Le tracce verificano l'esecuzione dei tre ingressi e del ramo di uscita, oltre al valore risolto. L'estrazione dei record e il successivo dispatch sono chiamati dal banco.

Per entrambi gli ordini callback, le fixture impongono C9BF8=0, finestra corrente CaptureMenu, controllo attivo zero, esclusioni vuote, CD9C8=0x3F e CAD5C=1 oppure 2. La tabella finestre viene installata nel contesto RAM sintetico con puntatore 0x3F5900; count e busy sono variati. Lock, segnale, filtri e getter di stato rimangono stub. Nessuna interazione con hardware.

## Risultati dei gate

Otto casi: due ordini × due stati CAD5C × due configurazioni. Nel primo gruppo count=197 e busy=1; il resolver legge dalla tabella originale:

| CAD5C fixture | ID richiesto | Descrittore letto dalla tabella | Risultato |
|---:|---:|---|---|
| 1 | 2 | 0x9802AC | Manager occupato: uscita 0, corrente invariata |
| 2 | 0x3F | 0x989FCC | Manager occupato: uscita 0, corrente invariata |

Nel secondo gruppo count=0 e busy=0: per entrambi gli ID il resolver restituisce zero e il manager esce 0 per target nullo. Corrente, pending e busy restano quelli iniziali. Le tracce e le asserzioni verificano i rami; non sono state eseguite transizioni lifecycle in questi casi.

## Esperimento con gate aperti

Una corsa esplorativa separata con CAD5C=2, count=197 e busy=0 non ha raggiunto il probe: il simulatore è stato terminato dal timeout di 10 secondi. L'evidenza è conservata con stato FAIL in `Risultati/GUI_S33/key_scanner_manager700_cpu_20261104T105837794514Z/`. Non è una dimostrazione di comportamento o blocco della fotocamera.

Aggiornamento successivo: la [diagnosi del 2026-11-04](S33_GUI_Manager700_Diagnosi_Timeout_20261104.md) ha localizzato il primo arresto nella callback 0x7D252C non caricata nell'ELF del banco; due ulteriori prove hanno individuato altre finestre mancanti e un redirect prodotto da una fixture.

## Limiti e seguito

Questa prova dimostra la risoluzione di ID 2 e 0x3F e i due rifiuti nel contesto sintetico, non l'accettazione della richiesta, il completamento lifecycle o la visualizzazione di ISO. Il valore 0x3F arriva da una fixture. Prossimo passo: localizzare il timeout del caso con gate aperti, integrare i servizi lifecycle necessari senza modificare i byte firmware, e controllare descrittore corrente e valori di ritorno. GPIO, rendering e modifiche alle impostazioni fisiche restano non verificati.
