# S33 — Getter della base immagini e tabella GUI

27 ottobre 2026, verifica statica V1.1. La routine GUI `0x7C9E38` chiama `0x302634`, che restituisce il valore fisso `0x40EB18` dal literal `0x302638`. Quel valore corrisponde esattamente alla posizione `0x35C918` nel file TBM originale, tradotta secondo la mappa del payload 1: offset file `0x2AE600`, destinazione candidata `0x360800`, dimensione `0xC7E00`.

Per ciascuno dei 18 record JPEG della tabella `0x981734`, il verificatore confronta tutti i byte tra `0x40EB18 + offset` nel payload 1, `0x35C918 + offset` nel TBM e la stessa posizione nel dump `MainCode.dmp`. I 18 confronti sono riusciti, incluse le firme SOI/EOI. Per l'indice 14, offset `0xA7B9`, i rispettivi indirizzi sono `0x4192D1` e `0x3670D1`, per 2715 byte. Anche il contenuto completo del payload 1 coincide con TBM e dump.

Il collegamento **non dimostra che la GUI legga dalla RAM**. Nel codice originale, se i due puntatori richiesti sono validi, il valore restituito dal getter non viene usato prima che `0x7C9E6C` sovrascriva `r0` caricando il puntatore alla tabella. In caso contrario `r0` viene azzerato e la routine esce. La successiva chiamata al lettore `0x159558` riceve in `r0` l'offset del record, non il valore restituito dal getter; non vi è una chiamata diretta al setter `0x159550` nel corpo analizzato. Il motivo della chiamata al getter è ignoto.

[Verificatore riproducibile](../Python_Trace_Scripts/s33_verify_gui_jpeg_resident_getter.py); [risultati](../Risultati/GUI_S33/jpeg_resident_getter_20261027T171655Z/evidence.json); [disassemblati GNU](../Risultati/GUI_S33/jpeg_resident_getter_20261027T171655Z/gnu_windows.txt). Comando: `python3 Python_Trace_Scripts/s33_verify_gui_jpeg_resident_getter.py`.

La mappa di caricamento è statica: non sono stati osservati RAM fisica, inizializzazione o permanenza del payload, sincronizzazione, backend o display. La base effettiva del lettore resta da dimostrare; nessun firmware è stato scritto o installato. Stato **NON_INSTALLARE**.
