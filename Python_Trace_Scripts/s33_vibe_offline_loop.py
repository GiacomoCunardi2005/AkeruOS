#!/usr/bin/env python3
"""Ripete Vibe headless per lo studio offline; nessuna dipendenza esterna (Linux)."""
from __future__ import annotations

import argparse
import codecs
from datetime import datetime, timezone
import fcntl
import json
import math
import os
from pathlib import Path
import shutil
import signal
import subprocess
import sys
import threading
import time
from uuid import UUID

ROOT = Path(__file__).resolve().parents[1]
CHECKPOINT = "MDs/S33_Vibe_Offline_Checkpoint.md"


PROMPT = """Prosegui autonomamente lo STUDIO OFFLINE del firmware Nikon COOLPIX S33
e lo sviluppo sperimentale della GUI AkeruOS.

Questa è l'iterazione {iteration} di un ciclo persistente.
Non creare altri loop, daemon, automazioni o richiami ricorsivi di vibe.
Concludi questa sessione dopo un avanzamento concreto e verificabile,
lasciando un prossimo passo preciso.

DOCUMENTAZIONE E CONTINUITÀ

Leggi:
- AGENTS.md
- MDs/00_INIZIA_QUI.md
- Le parti aggiornate di MDs/roadmap.md
- MDs/percorsi_progetto.md
- MDs/S33_Stato_progetto.md
- MDs/mappa_ram_cpu.md
- {checkpoint}

Il checkpoint contiene il passaggio di consegne fra sessioni indipendenti.
Controlla i checkpoint più recenti e i rapporti già completati.
Non ripartire da vecchi prossimi passi superati.

Per la GUI consulta anche i rapporti più recenti in MDs/,
specialmente quelli del 31 ottobre e 1 novembre 2026 relativi a:
- CaptureMenu, AutoScene, WindowManager e classi dei controlli.
- Snapshot, tasti logici, eventi, dispatcher e code.
- ISO, tempo di esposizione e controllo iride.
- Flash e applicazione dei valori.
- Lifecycle, transizioni, ritorni e fallimenti.
- RAW CFA, Mono RAW Luminance e pipeline fotografica.

Usa rg per individuare i dossier aggiornati, non inventare percorsi.
Le prove nuove prevalgono sulle ipotesi precedenti solo per ciò che
verificano effettivamente.

AGENTI

L'utente chiede di utilizzare gli agenti.

Usa lo strumento task con agente explore per:
1. Cercare fonti, caller, consumer e collegamenti nel firmware.
2. Effettuare una revisione indipendente delle conclusioni.
3. Individuare eventuali controesempi, guardie o percorsi alternativi.

Se task non è disponibile, annotalo nel checkpoint e procedi senza
inventare delegazioni.

Il coordinatore integra, scrive e verifica.
Evita modifiche concorrenti agli stessi file.
Usa attese limitate per gli agenti e documenta quelli non conclusi.

OBIETTIVO GENERALE

Comprendere il percorso completo:

INQUADRATURA -> INPUT FISICO -> EVENTI -> GUI ->
IMPOSTAZIONI FOTOGRAFICHE -> ACQUISIZIONE ->
ELABORAZIONE -> JPEG / RAW -> SALVATAGGIO SD ->
RITORNO ALLA LIVE VIEW PRONTA.

Riutilizzare, per quanto possibile, i servizi originali Nikon.

PRIORITÀ ATTUALE: GUI AKERUOS

La GUI personalizzata è attualmente il principale filone di ricerca
e integrazione offline.

Non ridurre però l'intero progetto alla GUI: continua lo studio
di acquisizione, sensore, ottica, display, buffer, filesystem,
task, boot e caricamenti quando necessario o quando la GUI è bloccata.

Il risultato desiderato è una nuova interfaccia che sfrutti
quattro pulsanti fisici, preservando le funzionalità Nikon originali.

Organizzazione desiderata:

PULSANTE 1 — ESPOSIZIONE
- ISO: Auto e valori manuali.
- Diaframma: Auto e stati manuali realmente supportati.
- Tempo: Auto e valori manuali.
- Flash: acceso/spento.
- Eventuali pagine aggiuntive se necessarie.

ISO, tempo e diaframma devono avere opzioni Auto indipendenti.
Devono essere rappresentabili combinazioni miste Auto/manuale.
Questa è una specifica da realizzare, non una capacità già dimostrata.

PULSANTE 2 — COLORE
- Modalità fotografica standard.
- Mono RAW Luminance.
- Selezione della modalità da usare per il singolo scatto.
- Preservazione della pipeline Nikon originale.

Mono RAW Luminance è un'elaborazione dei campioni CFA.
Non confonderla con ChangeColorMenu o con un filtro JPEG.

PULSANTE 3 — FUNZIONE DA DECIDERE
- Conservare lo slot logico.
- Non inventare una funzione definitiva.
- Studiare possibilità compatibili con i controlli originali.

PULSANTE 4 — IMPOSTAZIONI
- Aprire le impostazioni Nikon originali quando possibile.
- Gestire correttamente apertura, ritorno e contesto.
- Evitare interferenze con la navigazione Nikon.

Queste assegnazioni sono desiderate: la mappa dei pulsanti fisici,
l'ordine, la polarità e la consegna reale non sono ancora provati.

STATO DELLE SCOPERTE GUI DA NON DIMENTICARE

1. AUTO SCENE E CAPTURE MENU

Nel dump Nikon V1.1 l'ID 2 originale identifica CaptureMenu,
descrittore 0x9802AC.

Nei banchi con condizioni sintetiche:
- Evento 0x700 -> ID 2, argomento 4.
- Evento 0x2180 -> ID 2, argomento 5.
- Argomento 4 -> risorsa 0x4800.
- Argomento 5 -> risorsa 0x4801.

Le due richieste hanno significati differenti.

NON sostituire globalmente ID 2 con AkeruOS assumendo che serva
un unico evento. Studiare un raccordo contestuale che conservi
le semantiche originali e gestisca esplicitamente gli argomenti.

2. RISORSE CAPTUREMENU

Sono stati studiati:
- Risorsa 0x9801C0, classe 0x15, ID 0x4800.
- Risorsa 0x980268, classe 0x15, ID 0x4801.
- Risorsa 0x3ABA38, classe 1, ID 0x4A12.
- Eventi di inizializzazione e gestione 0x4401 e 0x4405.
- Aggiornamento dei record tramite 0x7CB1B4.

Una prova più recente usa il recupero originale del controllo
e osserva 0x980268 nel campo controllo attivo 0x366EAC.

Nei casi sintetici studiati, alcuni record ricevono flag 2
e le successive pressioni non provocano nuove aperture.

Non dedurre che tali voci siano sempre disabilitate.
Studiare produttori dei flag, condizioni, lifecycle e contesto
prima di cambiare il comportamento delle liste originali.

3. PULSANTI ED EVENTI

Sono stati individuati quattro slot logici candidati:
- Slot 0: 0x580 / 0x581.
- Slot 1: 0x700 / 0x701.
- Slot 2: 0x2180 / 0x2181.
- Slot 3: 0x2700 / 0x2701.

Sono stati studiati snapshot, normalizzatori, generatore,
coda Nikon, dispatcher, monitor e timer.

I bit snapshot candidati non sono ancora una mappa fisica.
Non trasferire automaticamente il significato degli eventi
da AutoScene a CaptureMenu, ISO o altre schermate.

4. CODA AKERUOS

Esiste un modello C con coda sequenziale di quattro pressioni,
overflow esplicito e azioni pendenti.

Le transizioni esterne devono gestire:
- Ownership degli eventi.
- Sospensione della coda.
- Scarto di pressioni obsolete.
- Conferma del completamento.
- Fallimento dell'apertura.
- Ritorno a un descrittore diverso da quello previsto.

Un ritorno positivo del dispatcher non prova che la schermata
richiesta sia realmente diventata corrente.

5. LIFECYCLE ISO E RITORNO

Sono stati provati percorsi ISO -> AkeruOS e ISO -> AutoSceneLiveView
con manager originale, descrittori e servizi parzialmente sintetici.

Il flag di ritorno sperimentale può diventare obsoleto.

NON cancellarlo semplicemente all'evento lifecycle 0x4402:
un controesempio mostra che il manager può tentare una transizione,
ricevere un fallimento e ripristinare ISO.

Nei casi verificati, una strategia più robusta osserva sia il
risultato del manager sia l'identità del descrittore corrente
dopo la transizione.

Questo non risolve ancora concorrenza, atomicità, ownership
e tutti i possibili fallimenti.

6. ESPOSIZIONE

ISO:
Sono stati verificati setter, getter, scelte diagnostiche,
ripristino e percorsi AutoScene in condizioni controllate.

Tempo:
Sono stati verificati valori software, calcolo e copia.
L'unità fisica resta da dimostrare.

Iride:
Sono stati verificati stati software 1 e 9, conversioni,
selezione del valore, copia, richiesta asincrona e callback.

Il valore zero attraversa un percorso sperimentale,
ma non è identificato come comando Auto.

Non equiparare stati software a valori f/ reali.
Considerare i limiti dell'ottica e del filtro ND.

Non dichiarare funzionante il controllo manuale indipendente
senza aver verificato l'arbitraggio con l'esposizione automatica.

7. FLASH

Sono stati identificati i valori software originali:
- Auto = 4.
- Spento = 1.
- Sempre acceso = 8.

I test collegano scelta, setter, getter, oggetto software,
modello AkeruOS e un consumatore originale.

Il comportamento dipende anche dal contesto/modalità:
in un modo sintetico 0x08 è stato osservato il valore 26.

Non trattare i risultati del consumatore come prova di
attivazione fisica del flash o applicazione allo scatto.

8. RAW E MONOCROMATICO

Esiste un elaboratore Mono RAW Luminance verificato offline,
ma non ancora integrato nella cattura Nikon.

Sono stati studiati file CFA, strutture, tripla candidata AWB,
dispatcher di scrittura e selettore del backend.

Non assumere che i buffer diagnostici abbiano capacità,
durata o sincronizzazione sufficienti per una nuova pipeline.

Non confondere l'elaborazione offline con una modifica reale
al processo di acquisizione.

METODO DI LAVORO PER OGNI ITERAZIONE

1. Leggi il checkpoint e individua il punto aperto più recente.

2. Preferisci un problema GUI concreto ancora irrisolto,
   soprattutto se collega due componenti già studiati.

3. Formula una domanda tecnica precisa e verificabile.

4. Cerca gli ingressi, i caller, i consumer e le condizioni
   che determinano il percorso originale.

5. Usa prima l'analisi statica e i verificatori già disponibili.

6. Se utile, costruisci una prova CPU offline delimitata,
   usando le routine originali e il minimo di fixture necessario.

7. Inserisci controlli negativi, percorsi alternativi e condizioni
   di fallimento quando possono cambiare la conclusione.

8. Confronta i risultati con i dossier precedenti.
   Distingui un risultato nuovo da una semplice regressione.

9. Documenta il risultato, aggiorna i checkpoint e termina
   lasciando il prossimo passo preciso.

Dai particolare valore ai collegamenti:
snapshot -> coda -> dispatcher -> AutoScene -> manager ->
CaptureMenu -> controllo attivo -> handler -> ritorno.

Non cercare necessariamente di estendere ogni volta la catena.
Un controesempio verificato, una guardia chiarita o una condizione
di lifecycle identificata possono costituire avanzamento concreto.

Se il checkpoint indica una domanda più recente e produttiva,
segui quella invece di ripetere questa lista.

VINCOLI DI SICUREZZA

Valgono anche per tutti gli agenti.

- Solo file locali ed esecuzioni offline controllate.
- Il modello Mistral usa la rete, ma lo studio non deve
  interrogare fotocamera o dispositivi collegati.
- Nessun USB, PTP, SCSI, SG_IO o accesso a /dev di dispositivi.
- Nessun mount, flash, scrittura SD o supporti rimovibili.
- Nessun privilegio elevato.
- Nessuna installazione o modifica di firmware.
- Nessuna costruzione o distribuzione di aggiornamenti.
- Nessuna modifica agli originali Nikon, ai dump, alle foto,
  alle calibrazioni e ai log storici.
- Nessuna modifica alle configurazioni personali o credenziali.
- Alberi GNU in sola lettura; non eseguire builder che li modificano.
- Non installare dipendenze.
- Non cancellare risultati storici.
- Non modificare questo runner o il suo STOP.
- Non scrivere su hardware, registri o periferiche reali.

Le copie di laboratorio, la RAM sintetica e i registri MMIO
simulati non autorizzano operazioni analoghe sulla fotocamera.

VERIFICA E QUALITÀ

Leggi dossier e script prima di eseguire un verificatore.
Controlla destinazioni e possibili side effect.

Esegui i verificatori Python direttamente, senza pipe a tail/head
che possano nascondere l'exit code.

Per modificare regex usa patch esatte e controlla il diff.
Non usare sostituzioni sed globali.

Dopo tre tentativi falliti sullo stesso problema, fermati:
conserva diff, log ed errore, scrivi un checkpoint di blocco
e passa a un'altra domanda offline.

Non indebolire le asserzioni soltanto per ottenere PASS.
Non trasformare una fixture in un fatto sul firmware reale.
Non assumere che un codice di uscita zero dimostri successo:
controlla anche gli artefatti e le evidenze richieste.

Verifica hash, provenienza e confini codice/dati.
Classifica i riferimenti pcl, limm e straddle.
Usa GNU ARC700 little endian per le finestre pertinenti.

Distingui sempre:
- Byte verificati nel dump.
- Collegamento statico.
- Comportamento originale eseguito in CPU.
- Condizioni e valori imposti dal banco.
- Interpretazioni o ipotesi.
- Comportamento su hardware non verificato.

Un test simulato non dimostra boot, RAM libera,
rendering, scatto, movimento ottico, persistenza
o funzionamento fisico della fotocamera.

DOCUMENTAZIONE E CONSEGNA

Lascia uno script riproducibile per i nuovi esperimenti.

Salva nuove evidenze, hash, assunzioni, fixture, risultati,
controesempi e limiti in Risultati/.
Non lasciare l'unica evidenza in work/.

Scrivi rapporti Markdown esclusivamente in MDs/.

Aggiorna:
- MDs/roadmap.md
- MDs/percorsi_progetto.md
- MDs/S33_Stato_progetto.md
- MDs/mappa_ram_cpu.md soltanto se cambia un'interpretazione.

Conserva alias e provenienza storica.

Il progresso funzionale rimane circa 10% senza una nuova
applicazione effettivamente avviata e senza foto reale.
Non aumentare tale valore per il solo superamento di test offline.

Aggiorna {checkpoint} indicando:
- Domanda affrontata.
- Risultato verificabile e significato.
- Fonti, indirizzi e file precisi.
- Comandi realmente eseguiti ed esiti.
- Fixture e assunzioni.
- Controlli negativi e regressioni.
- Limiti e questioni non dimostrate.
- Agenti usati e risultati delle loro revisioni.
- Prossimo passo concreto e non ripetitivo.

Salva anche checkpoint intermedi dopo circa dieci operazioni.
Non rimandare tutta la documentazione alla fine.

Se hai già ottenuto un risultato circoscritto, chiudilo
prima di aprire nuove piste.

Se non ottieni una scoperta, registra il tentativo,
il motivo del blocco e le verifiche eseguite.
Non presentare semplice attività come avanzamento funzionale.

Rispondi in italiano.
Non attendere autorizzazioni per il normale studio locale.
Quando serve hardware, documenta il limite e scegli
un'altra domanda offline.

Concludi questa iterazione senza avviare un altro ciclo.


STRUMENTI DISPONIBILI E SERVER MCP — OBBLIGATORIO

Sfrutta attivamente tutti gli strumenti pertinenti messi a
disposizione dall'ambiente, inclusi i server MCP PMB e REA.

All'inizio di ogni iterazione:
1. Scopri quali strumenti, risorse e agenti sono effettivamente
   disponibili, compresi quelli esposti dai server MCP.
2. Consulta descrizioni, capacità, parametri e limitazioni.
3. Individua quali possono migliorare la ricerca, l'analisi,
   il reverse engineering, la verifica o la documentazione.
4. Combina gli strumenti quando permette di ottenere risultati
   più completi, riproducibili e verificabili.

Non limitarti ai soli comandi terminale, Python e Ghidra
quando sono disponibili strumenti specializzati più adatti.

Utilizza, quando disponibili e pertinenti:
- Agenti di esplorazione e revisione indipendente.
- Ricerca e navigazione del codice.
- Analisi di firmware, binari, istruzioni e riferimenti.
- Disassemblaggio, decompilazione e analisi dei flussi.
- Analisi di memoria, strutture dati e dipendenze.
- Esecuzione controllata di verificatori e simulazioni.
- Confronto di risultati, log e checkpoint.
- Strumenti di documentazione e verifica delle evidenze.

I server MCP PMB e REA devono essere considerati parte
integrante dell'ambiente di lavoro, non strumenti opzionali
da ignorare senza motivo.

Non inventare nomi, capacità o risultati degli strumenti.
Non è necessario invocare ogni strumento a ogni iterazione:
usa tutti quelli che sono realmente utili al problema.

Se uno strumento non è disponibile, non risponde oppure
non è adatto, documenta il motivo e scegli un'alternativa.

Rispetta sempre i vincoli offline del progetto:
nessuno strumento MCP o agente può accedere a hardware,
USB, SD, dispositivi fisici o modificare firmware originali.

Nel checkpoint finale indica:
- Server MCP disponibili e consultati.
- Strumenti effettivamente utilizzati.
- Contributo concreto di ciascuno.
- Strumenti rilevanti non disponibili o non funzionanti.
- Eventuali opportunità di utilizzo nelle iterazioni future.

Non dichiarare di aver usato un MCP o un agente
senza una chiamata effettiva e un risultato verificabile.

"""




def now():
    return datetime.now(timezone.utc).isoformat()


def write_json(path, value):
    temporary = path.with_suffix(".tmp")
    temporary.write_text(json.dumps(value, ensure_ascii=False, indent=2) + "\n")
    temporary.replace(path)


def positive(value):
    number = float(value)
    if not math.isfinite(number) or number <= 0:
        raise argparse.ArgumentTypeError("richiesto numero positivo finito")
    return number


def integer(value):
    number = int(value)
    if number < 0:
        raise argparse.ArgumentTypeError("richiesto intero >= 0")
    return number


def parser():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--vibe", default="vibe", help="eseguibile Vibe (default: PATH)")
    p.add_argument("--max-rounds", type=integer, default=0, help="0 = infinito")
    p.add_argument("--pause", type=positive, default=15, help="secondi fra cicli riusciti")
    p.add_argument("--time-limit", type=positive, default=1800, help="secondi per sessione")
    p.add_argument("--grace", type=positive, default=30, help="secondi per uscita dopo SIGTERM")
    p.add_argument("--idle-timeout", type=positive, default=600, help="arresta la sessione dopo N secondi senza output")
    p.add_argument("--heartbeat", type=positive, default=30, help="mostra lo stato ogni N secondi")
    p.add_argument("--max-turns", type=integer, default=60, help="turni per sessione, >0")
    p.add_argument("--max-price", type=positive, help="limite dollari PER sessione, non totale")
    p.add_argument("--dry-run", action="store_true", help="mostra prompt senza chiamare Mistral")
    p.add_argument("--quiet", action="store_true", help="salva output Vibe solo nei log, senza diretta")
    p.add_argument("--raw-output", action="store_true", help="mostra eventi JSON grezzi nella diretta")
    return p


def kill_group(process, sig):
    try:
        os.killpg(process.pid, sig)
    except ProcessLookupError:
        pass


class ProcessTree:
    """Segue anche figli che creano una nuova sessione (Linux /proc)."""

    def __init__(self, pid):
        self.root = pid
        self.identities = {}
        self.refresh()

    @staticmethod
    def identity(pid):
        try:
            fields = Path(f"/proc/{pid}/stat").read_text().rsplit(")", 1)[1].split()
            return fields[19] if fields[0] != "Z" else None  # starttime, field 22
        except (OSError, IndexError):
            return None

    def refresh(self):
        pending = [self.root] if not self.identities else [
            pid for pid, identity in self.identities.items() if self.identity(pid) == identity]
        seen = set()
        while pending:
            pid = pending.pop()
            if pid in seen:
                continue
            seen.add(pid)
            identity = self.identity(pid)
            if identity is None:
                continue
            self.identities[pid] = identity
            for children in Path(f"/proc/{pid}/task").glob("*/children"):
                try:
                    pending.extend(int(child) for child in children.read_text().split())
                except OSError:
                    pass

    def signal(self, sig):
        self.refresh()
        for pid, identity in self.identities.items():
            if self.identity(pid) == identity:
                try:
                    os.kill(pid, sig)
                except ProcessLookupError:
                    pass


def read_result(path):
    """Legge solo metadati di esito, senza esportare config o credenziali."""
    try:
        value = json.loads(path.read_text())
    except (OSError, ValueError):
        return {}
    return value if isinstance(value, dict) else {}


def session_id(value):
    if not isinstance(value, str):
        return None
    try:
        return str(UUID(value))
    except ValueError:
        return None


class StreamDisplay:
    """Rende gli eventi NDJSON Vibe senza riversare prompt e file nel terminale."""

    def __init__(self, raw=False):
        self.raw = raw
        self.pending = ""
        self.messages = {}
        self.effects = {}

    def feed(self, text, final=False):
        if self.raw:
            sys.stdout.write(text)
            return
        self.pending += text
        while "\n" in self.pending:
            line, self.pending = self.pending.split("\n", 1)
            self.line(line)
        if final and self.pending:
            self.line(self.pending)
            self.pending = ""

    def line(self, line):
        if not line.strip():
            return
        try:
            event = json.loads(line)
        except json.JSONDecodeError:
            if line.lstrip().startswith("{"):
                print("[flusso] Evento JSON non leggibile; dettagli in console.log.")
            else:
                print(line)
            return
        if not isinstance(event, dict):
            return
        kind = event.get("type")
        if kind == "message" and event.get("role") == "assistant":
            content = event.get("content", [])
            text = ""
            if isinstance(content, str):
                text = content
            elif isinstance(content, list):
                text = "".join(part.get("text", "") for part in content
                               if isinstance(part, dict) and part.get("type") == "text")
            if not text:
                return
            key = event.get("id")
            previous = self.messages.get(key, "") if key else ""
            if text == previous:
                return
            addition = text[len(previous):] if text.startswith(previous) else text
            if key:
                self.messages[key] = text
            print(f"\nVibe: {addition}")
        elif kind == "effect":
            detail = event.get("detail") or {}
            display = detail.get("display") or {}
            state = event.get("state") or {}
            status = state.get("status") or event.get("generationStatus") or ""
            failed = (state.get("display") or {}).get("success") is False
            if failed:
                status = "failed"
            summary = display.get("summary") or detail.get("toolName") or event.get("title") or "operazione"
            # Solo una riga descrittiva: mai state.outputText o detail.input.
            summary = " ".join(str(summary).split())[:240]
            key = event.get("id")
            signature = (status, summary)
            if key and self.effects.get(key) == signature:
                return
            if key:
                self.effects[key] = signature
            print(f"[{status or 'strumento'}] {summary}")
            if failed:
                error_lines = str(state.get("outputText") or "").strip().splitlines()
                if error_lines:
                    print(f"  Errore: {error_lines[-1][:300]}")
        elif kind == "error":
            message = event.get("message") or event.get("text") or "errore Vibe (vedere console.log)"
            print(f"[errore] {str(message)[:1000]}")
        # Prompt, ragionamento, dati letti e metadati restano nel log integrale.


def relay_output(reader, decoder, display, final=False):
    """Segue il log senza pipe bloccanti, preservando caratteri UTF-8 spezzati."""
    while chunk := reader.read(65536):
        display.feed(decoder.decode(chunk))
    if final:
        display.feed(decoder.decode(b"", final=True), final=True)
    sys.stdout.flush()


def run(args, root=ROOT):
    if args.max_turns == 0:
        raise ValueError("--max-turns deve essere >0")
    if args.dry_run:
        print(PROMPT.format(iteration=1, checkpoint=CHECKPOINT))
        return 0
    executable = shutil.which(args.vibe)
    if executable is None:
        raise ValueError(f"eseguibile non trovato: {args.vibe}")
    root = root.resolve()
    if not (root / "MDs/AGENTS.md").is_file() or not (root / CHECKPOINT).is_file():
        raise ValueError("mancano istruzioni o checkpoint nel progetto")
    base = root / "Risultati/Vibe_Offline"
    base.mkdir(parents=True, exist_ok=True)
    stop_file = base / "STOP"
    stopped = threading.Event()
    def on_signal(signum, frame):
        stopped.set()
    previous = {s: signal.signal(s, on_signal) for s in (signal.SIGINT, signal.SIGTERM)}
    process = None
    tree = None
    try:
        # Non rimuovere il file: l'inode deve restare condiviso fra le istanze.
        with (base / "loop.lock").open("a+") as lock:
            try:
                fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
            except BlockingIOError:
                raise ValueError("un altro ciclo Vibe è già attivo") from None
            if stop_file.exists():
                print(f"Arrestato: esiste {stop_file}. Rimuoverlo per riavviare.", flush=True)
                return 0
            session = base / (datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%S_%fZ") + f"_{os.getpid()}")
            session.mkdir()
            print(f"PID {os.getpid()} | log: {session} | arresto: Ctrl+C o {stop_file}", flush=True)
            failures = 0
            iteration = 0
            continuation = base / "continuation.json"
            resume = session_id(read_result(continuation).get("session_id"))
            # Compatibilità con i cicli prodotti prima del supporto --resume.
            old_round = read_result(base / "latest.json").get("round")
            if not resume and isinstance(old_round, str):
                old_export = (Path(old_round) / "vibe/export.json").resolve()
                if old_export.is_relative_to(base.resolve()):
                    old_result = read_result(old_export)
                    if old_result.get("outcome") == "turn_limit" and old_result.get("exit_code") == 3:
                        resume = session_id(old_result.get("session_id"))
                        if resume:
                            write_json(continuation, {"session_id": resume, "source_export": str(old_export)})
            while not stopped.is_set() and not stop_file.exists():
                if args.max_rounds and iteration >= args.max_rounds:
                    break
                iteration += 1
                folder = session / f"round_{iteration:06d}"
                folder.mkdir()
                prompt = folder / "prompt.txt"
                if resume:
                    prompt.write_text(
                        "Riprendi questa stessa sessione interrotta dal limite di turni. "
                        "Conserva il contesto e non ripetere analisi già fatte. "
                        "Prima di aprire altre piste, chiudi un risultato circoscritto, "
                        "salva prove e aggiorna " + CHECKPOINT + ". "
                        "Restano validi tutti i vincoli di studio offline e conservazione "
                        "delle fonti; rileggi le istruzioni del progetto se aggiornate. "
                        "Salva checkpoint intermedi, usa agenti per ricerca/revisione "
                        "se disponibili e attendili prima di terminare. "
                        "Esegui verificatori senza pipe a tail/head; modifica regex con "
                        "patch esatte e verifica il diff, senza sed globale. Dopo tre "
                        "tentativi falliti sullo stesso problema conserva errore e diff, "
                        "scrivi il blocco nel checkpoint e cambia domanda offline; non "
                        "indebolire asserzioni per ottenere PASS. Evita attese ripetute "
                        "listing-subagents/sleep. Rispondi in italiano.\n")
                else:
                    prompt.write_text(PROMPT.format(iteration=iteration, checkpoint=CHECKPOINT))
                    recovery = read_result(base / "recovery.json")
                    if recovery.get("reason") == "idle_timeout":
                        with prompt.open("a") as stream:
                            stream.write("\nLa sessione precedente è stata interrotta per assenza di output. "
                                         "Consulta solo le ultime operazioni nel log " + str(recovery.get("log")) +
                                         "; lascia un checkpoint dei tentativi incompleti e scegli una "
                                         "domanda offline diversa se ritrovi lo stesso blocco. "
                                         "Non trattare lo script incompleto come verificato.\n")
                command = [executable, "--yolo", "--workdir", str(root),
                           "--output", "streaming",
                           "--prompt-file", str(prompt), "--output-dir", str(folder / "vibe"),
                           "--time-limit", str(args.time_limit), "--max-turns", str(args.max_turns)]
                if resume:
                    command += ["--resume", resume]
                    print(f"Riprendo sessione {resume}", flush=True)
                if args.max_price is not None:
                    command += ["--max-price", str(args.max_price)]
                record = {"iteration": iteration, "pid": os.getpid(), "started": now(),
                          "command": command, "cwd": str(root), "status": "running"}
                write_json(folder / "run.json", record)
                write_json(base / "latest.json", {"session": str(session), "round": str(folder), **record})
                reason = None
                begin = time.monotonic()
                terminated = None
                print(f"Ciclo {iteration}: {folder}", flush=True)
                with (folder / "console.log").open("wb") as log, (folder / "console.log").open("rb") as reader:
                    decoder = codecs.getincrementaldecoder("utf-8")(errors="replace")
                    display = StreamDisplay(raw=args.raw_output)
                    process = subprocess.Popen(command, cwd=root, stdin=subprocess.DEVNULL,
                                               stdout=log, stderr=subprocess.STDOUT, start_new_session=True)
                    tree = ProcessTree(process.pid)
                    last_activity = time.monotonic()
                    last_heartbeat = last_activity
                    output_bytes = 0
                    while process.poll() is None:
                        tree.refresh()
                        current = time.monotonic()
                        size = os.fstat(log.fileno()).st_size
                        if size != output_bytes:
                            output_bytes = size
                            last_activity = current
                        if not args.quiet:
                            relay_output(reader, decoder, display)
                        silence = current - last_activity
                        if current - last_heartbeat >= args.heartbeat:
                            print(f"[supervisore] Sessione attiva; ultimo output {silence:.0f}s fa "
                                  f"(limite silenzio {args.idle_timeout:g}s).", flush=True)
                            record.update(last_output_silence_seconds=round(silence, 1), output_bytes=output_bytes)
                            write_json(base / "latest.json", {"session": str(session), "round": str(folder), **record})
                            last_heartbeat = current
                        if terminated is None:
                            if stopped.is_set() or stop_file.exists():
                                reason = "stop"
                            elif time.monotonic() - begin > args.time_limit + args.grace:
                                reason = "watchdog"
                            elif silence >= args.idle_timeout:
                                reason = "idle_timeout"
                            if reason:
                                print(f"[supervisore] Arresto sessione: {reason}.", flush=True)
                                kill_group(process, signal.SIGTERM)
                                terminated = time.monotonic()
                        elif time.monotonic() - terminated > args.grace:
                            tree.signal(signal.SIGKILL)
                            kill_group(process, signal.SIGKILL)
                        time.sleep(0.2)
                    code = process.wait()
                    # Anche eventuali discendenti rimasti nel gruppo vengono chiusi.
                    tree.signal(signal.SIGTERM)
                    tree.signal(signal.SIGKILL)
                    kill_group(process, signal.SIGKILL)
                    process = None
                    tree = None
                    if not args.quiet:
                        relay_output(reader, decoder, display, final=True)
                exported = read_result(folder / "vibe/export.json")
                exported_session = session_id(exported.get("session_id"))
                turn_limit = reason is None and code == 3 and exported.get("outcome") == "turn_limit" and exported_session
                status = reason or ("turn_limit" if turn_limit else "completed" if code == 0 else "vibe_error")
                if turn_limit:
                    resume = exported_session
                    write_json(continuation, {"session_id": resume, "source_export": str(folder / "vibe/export.json")})
                elif code == 0 or reason == "idle_timeout":
                    resume = None
                    continuation.unlink(missing_ok=True)
                if reason == "idle_timeout":
                    write_json(base / "recovery.json", {"reason": reason, "log": str(folder / "console.log"),
                                                        "round": str(folder), "created_utc": now()})
                elif code == 0:
                    (base / "recovery.json").unlink(missing_ok=True)
                record.update(ended=now(), exit_code=code, duration_seconds=round(time.monotonic()-begin, 3),
                              status=status, vibe_outcome=exported.get("outcome"), resume_session=resume)
                write_json(folder / "run.json", record)
                write_json(base / "latest.json", {"session": str(session), "round": str(folder), **record})
                with (session / "journal.jsonl").open("a") as journal:
                    journal.write(json.dumps(record, ensure_ascii=False) + "\n")
                print(f"Ciclo {iteration}: {record['status']} (exit {code})", flush=True)
                if turn_limit:
                    print("Limite turni raggiunto: il prossimo ciclo riprenderà la stessa sessione.", flush=True)
                if reason == "stop" or (args.max_rounds and iteration >= args.max_rounds):
                    break
                failures = 0 if code == 0 or turn_limit else failures + 1
                delay = args.pause if not failures else min(900, 30 * 2 ** min(failures-1, 5))
                until = time.monotonic() + delay
                while time.monotonic() < until and not stopped.is_set() and not stop_file.exists():
                    stopped.wait(min(0.5, max(0, until - time.monotonic())))
            return 0
    finally:
        if process is not None:
            if tree is not None:
                tree.signal(signal.SIGKILL)
            kill_group(process, signal.SIGKILL)
            process.wait()
        for signum, handler in previous.items():
            signal.signal(signum, handler)


def main():
    p = parser()
    args = p.parse_args()
    try:
        return run(args)
    except (ValueError, OSError) as exc:
        p.exit(2, f"Errore: {exc}\n")


if __name__ == "__main__":
    raise SystemExit(main())
