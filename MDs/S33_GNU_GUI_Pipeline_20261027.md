# S33 — banco GUI integrato sul simulatore GNU ARC700

27 ottobre 2026. Aggiunto un banco offline riutilizzabile che usa il simulatore GNU già presente e mette insieme quattro routine originali individuate nello studio REA:

1. `0x21DC34` converte 256 elementi tramite il lookup originale `0x17AF2C`.
2. `0x23B234` decomprime ciascuna risorsa grafica.
3. `0x2C9018` elabora le 72 righe della risorsa usando la tabella convertita.

Le chiamate sono orchestrate da un **chiamante sintetico**: non dimostrano che il firmware reale esegua questa intera sequenza in quell'ordine. Il banco non modifica firmware né sorgenti, configurazioni o installazioni GNU e non ripristina il servizio web rimosso.

## Esecuzione

```sh
make -C AkeruOS gnu-gui-pipeline-verify
```

Il [verificatore](../Python_Trace_Scripts/s33_verify_gui_pipeline_cpu.py) controlla l'identità del motore e confronta codice, dati di palette e sorgenti compresse con i payload originali e con il dump. Riusa gli 11 descrittori di CaptureMenu e i corrispondenti flussi compressi verificati, con puntatori di laboratorio. Per ciascuna risorsa confronta i 5.184 indici decompressi con il riferimento host, i 5.184 byte prodotti con un oracolo host, controlla stack, descrittore e guardie oltre entrambi i buffer.

La tabella di ricerca a `0x47A448` è una **fixture sintetica** costruita dalle chiavi dei 256 record originali. Due esecuzioni usano le stesse risorse e dati iniziali con ordine delle word rispettivamente diretto e inverso. I risultati cambiano, e ciascuno coincide con l'oracolo della propria configurazione; ciò verifica il collegamento fra tabella, conversione e scritture nel perimetro delle fixture, non identifica la tabella attiva sulla macchina. Gli output sono byte di laboratorio, non immagini a colori certificate.

[Evidenza PASS](../Risultati/GUI_S33/pipeline_cpu_20261027T184633Z/verified_evidence.json): 22 casi risorsa, 792 chiamate di riga per esecuzione, 740.094 e 784.550 istruzioni riportate dal profiler GNU nei due scenari, nessun fault. Il simulatore DSP v7 usa un modello **provvisorio** di `MULDW` per il prodotto 72×72; le chiamate previste sono controllate nel log. I valori iniziali del contesto e la RAM sono sintetici.

Il banco non esegue il dispatcher degli eventi, il caricatore originale, la selezione runtime, il clipping, `0x2C8380`/`0x2C8170` o un display fisico. Non prova boot, geometria RAM, colori, hardware o recupero. I candidati restano **NON_INSTALLARE**.
