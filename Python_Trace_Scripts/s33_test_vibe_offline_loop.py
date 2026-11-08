#!/usr/bin/env python3
"""Collaudi offline del supervisore Vibe, con CLI locale simulata e nessuna API."""
from __future__ import annotations

import contextlib
import importlib.util
import io
import json
import os
from pathlib import Path
import signal
import select
import subprocess
import sys
import tempfile
import time
import unittest

SOURCE = Path(__file__).with_name("s33_vibe_offline_loop.py")
spec = importlib.util.spec_from_file_location("s33_vibe_loop_under_test", SOURCE)
runner = importlib.util.module_from_spec(spec)
spec.loader.exec_module(runner)

FAKE = '''#!/usr/bin/env python3
import json, os, pathlib, signal, subprocess, sys, time
root = pathlib.Path.cwd()
mode = (root / "fake_mode").read_text()
record = {"argv": sys.argv[1:], "cwd": str(root), "pid": os.getpid()}
if mode == "long":
    signal.signal(signal.SIGTERM, signal.SIG_IGN)
    child = subprocess.Popen([sys.executable, "-c", "import signal,time; signal.signal(signal.SIGTERM, signal.SIG_IGN); time.sleep(60)"], start_new_session=True)
    record["grandchild"] = child.pid
with (root / "calls.jsonl").open("a") as log:
    log.write(json.dumps(record) + "\\n")
if mode == "silent_once":
    (root / "fake_mode").write_text("success")
    time.sleep(60)
if mode == "limit_once":
    folder = pathlib.Path(sys.argv[sys.argv.index("--output-dir") + 1])
    folder.mkdir(parents=True)
    (folder / "export.json").write_text(json.dumps({"outcome": "turn_limit", "exit_code": 3, "session_id": "ce5331f6-abab-fa45-212a-852bd6c3d1d9"}))
    (root / "fake_mode").write_text("success")
    print("Stopped: turn_limit", flush=True)
    sys.exit(3)
if mode == "long":
    time.sleep(60)
if mode == "live":
    print(json.dumps({"id": "live-message", "type": "message", "role": "assistant", "content": [{"type": "text", "text": "messaggio in diretta"}]}), flush=True)
    while not (root / "finish_live").exists():
        time.sleep(0.02)
if mode == "error":
    print("errore simulato", flush=True)
    sys.exit(7)
print("risultato simulato", flush=True)
'''

CHILD = '''import importlib.util, pathlib, sys
spec = importlib.util.spec_from_file_location("loop", sys.argv[1])
m = importlib.util.module_from_spec(spec)
spec.loader.exec_module(m)
try:
    sys.exit(m.run(m.parser().parse_args(sys.argv[3:]), root=pathlib.Path(sys.argv[2])))
except (ValueError, OSError) as exc:
    print(str(exc), file=sys.stderr)
    sys.exit(2)
'''


def alive(pid):
    """Gli zombie non eseguono più codice e attendono solo il reaper del sistema."""
    try:
        state = Path(f"/proc/{pid}/stat").read_text().split(")", 1)[1].split()[0]
        return state != "Z"
    except FileNotFoundError:
        return False


class VibeOfflineLoopTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(prefix="s33 vibe test ")
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        (self.root / "MDs").mkdir()
        (self.root / "MDs/AGENTS.md").write_text("Studio offline.\n")
        (self.root / runner.CHECKPOINT).write_text("Punto aperto simulato.\n")
        self.fake = self.root / "fake vibe"
        self.fake.write_text(FAKE)
        self.fake.chmod(0o755)
        (self.root / "fake_mode").write_text("success")
        self.base = self.root / "Risultati/Vibe_Offline"
        self.children = []
        self.addCleanup(self.cleanup_children)

    def cleanup_children(self):
        for child in self.children:
            if child.poll() is None:
                child.terminate()
                try:
                    child.wait(timeout=3)
                except subprocess.TimeoutExpired:
                    child.kill()
                    child.wait(timeout=3)
            if child.stdout:
                child.stdout.close()
        calls = self.calls()
        for call in calls:
            for key in ("pid", "grandchild"):
                if key in call and alive(call[key]):
                    with contextlib.suppress(ProcessLookupError):
                        os.kill(call[key], signal.SIGKILL)

    def args(self, *extra):
        return runner.parser().parse_args([
            "--vibe", str(self.fake), "--pause", "0.05", "--grace", "0.1",
            "--time-limit", "20", *extra])

    def start(self, *extra):
        child = subprocess.Popen([
            sys.executable, "-c", CHILD, str(SOURCE), str(self.root),
            "--vibe", str(self.fake), "--pause", "0.05", "--grace", "0.1",
            "--time-limit", "20", *extra], stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT, text=True)
        self.children.append(child)
        return child

    def wait_for(self, predicate, timeout=8):
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            result = predicate()
            if result:
                return result
            time.sleep(0.03)
        self.fail("Timeout attendendo la condizione del test")

    def calls(self):
        file = self.root / "calls.jsonl"
        if not file.exists():
            return []
        return [json.loads(line) for line in file.read_text().splitlines() if line]

    def latest(self):
        file = self.base / "latest.json"
        return json.loads(file.read_text()) if file.exists() else {}

    def finish(self, child, expected=0):
        output = child.communicate(timeout=8)[0]
        self.assertEqual(child.returncode, expected, output)
        return output

    def test_dry_run_has_no_process_or_output_tree(self):
        args = self.args("--dry-run")
        args.vibe = "/missing/cli"
        output = io.StringIO()
        with contextlib.redirect_stdout(output):
            self.assertEqual(runner.run(args, root=self.root), 0)
        self.assertIn("STUDIO OFFLINE GENERALE", output.getvalue())
        self.assertIn("iterazione 1", output.getvalue())
        self.assertFalse(self.base.exists())
        self.assertEqual(self.calls(), [])

    def test_two_rounds_arguments_workdir_and_artifacts(self):
        child = self.start("--max-rounds", "2", "--max-turns", "4", "--max-price", "0.25")
        self.finish(child)
        calls = self.calls()
        self.assertEqual(len(calls), 2)
        for index, call in enumerate(calls, 1):
            argv = call["argv"]
            self.assertIn("--yolo", argv)
            for option, value in (("--workdir", str(self.root)), ("--max-turns", "4"),
                                  ("--max-price", "0.25"), ("--time-limit", "20.0")):
                self.assertEqual(argv[argv.index(option) + 1], value)
            self.assertEqual(call["cwd"], str(self.root))
            prompt = Path(argv[argv.index("--prompt-file") + 1])
            self.assertIn(f"iterazione {index}", prompt.read_text())
            self.assertEqual(prompt.parent.name, f"round_{index:06d}")
            self.assertEqual(argv[argv.index("--output-dir") + 1], str(prompt.parent / "vibe"))
            record = json.loads((prompt.parent / "run.json").read_text())
            self.assertEqual(record["status"], "completed")
            self.assertEqual(record["exit_code"], 0)
            self.assertIn("risultato simulato", (prompt.parent / "console.log").read_text())
        latest = self.latest()
        self.assertEqual(latest["iteration"], 2)
        self.assertEqual(len((Path(latest["session"]) / "journal.jsonl").read_text().splitlines()), 2)

    def test_stop_kills_long_child_and_grandchild(self):
        (self.root / "fake_mode").write_text("long")
        child = self.start()
        call = self.wait_for(lambda: self.calls() and self.calls()[0])
        self.assertTrue(alive(call["pid"]))
        self.assertTrue(alive(call["grandchild"]))
        (self.base / "STOP").touch()
        self.finish(child)
        self.wait_for(lambda: not alive(call["pid"]) and not alive(call["grandchild"]))
        self.assertEqual(self.latest()["status"], "stop")
        self.assertEqual(len(self.calls()), 1)

    def test_output_visible_before_session_exits(self):
        (self.root / "fake_mode").write_text("live")
        child = self.start("--max-rounds", "1")
        received = bytearray()
        def read_live():
            if select.select([child.stdout], [], [], 0)[0]:
                received.extend(os.read(child.stdout.fileno(), 65536))
            return b"messaggio in diretta" in received
        self.wait_for(read_live)
        self.assertNotIn(b'"role"', received)
        self.assertIsNone(child.poll(), "il messaggio deve apparire prima dell'uscita")
        call = self.calls()[0]
        argv = call["argv"]
        self.assertEqual(argv[argv.index("--output") + 1], "streaming")
        (self.root / "finish_live").touch()
        output = self.finish(child)
        self.assertIn("risultato simulato", output)
        log = Path(self.latest()["round"]) / "console.log"
        self.assertIn("messaggio in diretta", log.read_text())

    def test_quiet_keeps_output_in_log(self):
        child = self.start("--max-rounds", "1", "--quiet")
        output = self.finish(child)
        self.assertNotIn("risultato simulato", output)
        log = Path(self.latest()["round"]) / "console.log"
        self.assertIn("risultato simulato", log.read_text())

    def test_turn_limit_resumes_same_session_serially(self):
        (self.root / "fake_mode").write_text("limit_once")
        child = self.start("--max-rounds", "2")
        output = self.finish(child)
        calls = self.calls()
        self.assertEqual(len(calls), 2)
        self.assertNotIn("--resume", calls[0]["argv"])
        argv = calls[1]["argv"]
        self.assertEqual(argv[argv.index("--resume") + 1], "ce5331f6-abab-fa45-212a-852bd6c3d1d9")
        prompt = Path(argv[argv.index("--prompt-file") + 1]).read_text()
        self.assertIn("non ripetere analisi", prompt)
        self.assertIn("turn_limit (exit 3)", output)
        self.assertFalse((self.base / "continuation.json").exists())
        first_record = Path(calls[0]["argv"][calls[0]["argv"].index("--prompt-file") + 1]).parent / "run.json"
        self.assertEqual(json.loads(first_record.read_text())["status"], "turn_limit")

    def test_turn_limit_continuation_survives_restart(self):
        (self.root / "fake_mode").write_text("limit_once")
        self.finish(self.start("--max-rounds", "1"))
        self.assertTrue((self.base / "continuation.json").exists())
        self.finish(self.start("--max-rounds", "1"))
        self.assertIn("--resume", self.calls()[1]["argv"])
        self.assertFalse((self.base / "continuation.json").exists())

    def test_idle_watchdog_heartbeat_and_fresh_recovery(self):
        (self.root / "fake_mode").write_text("silent_once")
        output = self.finish(self.start("--max-rounds", "1", "--idle-timeout", "0.5", "--heartbeat", "0.1"))
        self.assertIn("ultimo output", output)
        self.assertIn("Arresto sessione: idle_timeout", output)
        self.assertEqual(self.latest()["status"], "idle_timeout")
        self.assertTrue((self.base / "recovery.json").exists())
        self.finish(self.start("--max-rounds", "1"))
        argv = self.calls()[1]["argv"]
        self.assertNotIn("--resume", argv)
        prompt = Path(argv[argv.index("--prompt-file") + 1]).read_text()
        self.assertIn("assenza di output", prompt)
        self.assertFalse((self.base / "recovery.json").exists())

    def test_old_export_turn_limit_can_be_recovered(self):
        folder = self.base / "old/round/vibe"
        folder.mkdir(parents=True)
        (folder / "export.json").write_text(json.dumps({"outcome": "turn_limit", "exit_code": 3, "session_id": "ce5331f6-abab-fa45-212a-852bd6c3d1d9"}))
        (self.base / "latest.json").write_text(json.dumps({"round": str(folder.parent)}))
        self.finish(self.start("--max-rounds", "1"))
        self.assertIn("--resume", self.calls()[0]["argv"])

    def test_stream_filters_prompt_reasoning_and_file_contents(self):
        events = [
            {"type": "message", "role": "user", "content": [{"type": "text", "text": "PROMPT_PRIVATO"}]},
            {"type": "reasoning", "text": "RAGIONAMENTO"},
            {"id": "a", "type": "message", "role": "assistant", "content": [{"type": "text", "text": "Leggo il checkpoint."}]},
            {"id": "e", "type": "effect", "detail": {"display": {"summary": "Reading checkpoint"}, "input": {"secret": "INPUT_PRIVATO"}}, "state": {"status": "completed", "outputText": "CONTENUTO_FILE"}},
        ]
        stream = "\n".join(json.dumps(e) for e in events)
        output = io.StringIO()
        display = runner.StreamDisplay()
        with contextlib.redirect_stdout(output):
            for char in stream:
                display.feed(char)
            display.feed("", final=True)
        rendered = output.getvalue()
        self.assertIn("Vibe: Leggo il checkpoint.", rendered)
        self.assertIn("[completed] Reading checkpoint", rendered)
        for hidden in ("PROMPT_PRIVATO", "RAGIONAMENTO", "INPUT_PRIVATO", "CONTENUTO_FILE", '"type"'):
            self.assertNotIn(hidden, rendered)

    def test_stream_deduplicates_snapshots_and_keeps_plain_errors(self):
        display = runner.StreamDisplay()
        output = io.StringIO()
        def message(text):
            return json.dumps({"id": "a", "type": "message", "role": "assistant", "content": text}) + "\n"
        with contextlib.redirect_stdout(output):
            display.feed(message("Ciao"))
            display.feed(message("Ciao"))
            display.feed(message("Ciao mondo"))
            display.feed("problema CLI\n")
            display.feed(json.dumps({"type": "error", "message": "quota finita"}), final=True)
            display.feed('{"state":{"outputText":"FILE_TRONCATO', final=True)
        rendered = output.getvalue()
        self.assertEqual(rendered.count("Ciao"), 1)
        self.assertIn("mondo", rendered)
        self.assertIn("problema CLI", rendered)
        self.assertIn("quota finita", rendered)
        self.assertIn("Evento JSON non leggibile", rendered)
        self.assertNotIn("FILE_TRONCATO", rendered)

    def test_raw_display_and_split_utf8(self):
        text = '{"text":"è"}\n'
        raw = text.encode()
        decoder = runner.codecs.getincrementaldecoder("utf-8")(errors="replace")
        reader = io.BytesIO()
        display = runner.StreamDisplay(raw=True)
        output = io.StringIO()
        with contextlib.redirect_stdout(output):
            for byte in raw:
                position = reader.tell()
                reader.seek(0, 2)
                reader.write(bytes([byte]))
                reader.seek(position)
                runner.relay_output(reader, decoder, display)
            runner.relay_output(reader, decoder, display, final=True)
        self.assertEqual(output.getvalue(), text)

    def test_completed_tool_with_negative_result_is_failed(self):
        event = {"id": "failure", "type": "effect", "generationStatus": "completed",
                 "detail": {"display": {"summary": "verificatore"}},
                 "state": {"status": "completed", "display": {"success": False},
                           "outputText": "Traceback\nAssertionError: semaphore missing"}}
        output = io.StringIO()
        with contextlib.redirect_stdout(output):
            runner.StreamDisplay().feed(json.dumps(event) + "\n")
        self.assertIn("[failed] verificatore", output.getvalue())
        self.assertIn("AssertionError: semaphore missing", output.getvalue())
        self.assertNotIn("[completed]", output.getvalue())

    def test_watchdog_kills_processes_ignoring_sigterm(self):
        (self.root / "fake_mode").write_text("long")
        child = self.start("--time-limit", "0.5", "--max-rounds", "1")
        call = self.wait_for(lambda: self.calls() and self.calls()[0])
        self.finish(child)
        self.wait_for(lambda: not alive(call["pid"]) and not alive(call["grandchild"]))
        self.assertEqual(self.latest()["status"], "watchdog")
        self.assertEqual(self.latest()["exit_code"], -signal.SIGKILL)
        self.assertEqual(len(self.calls()), 1)

    def test_lock_rejects_second_instance(self):
        (self.root / "fake_mode").write_text("long")
        first = self.start()
        self.wait_for(lambda: self.calls())
        second = self.start("--max-rounds", "1")
        output = self.finish(second, expected=2)
        self.assertIn("già attivo", output)
        self.assertEqual(len(self.calls()), 1)
        (self.base / "STOP").touch()
        self.finish(first)
        self.assertTrue((self.base / "loop.lock").exists())

    def test_error_logged_and_stop_interrupts_backoff(self):
        (self.root / "fake_mode").write_text("error")
        child = self.start()
        self.wait_for(lambda: self.latest().get("status") == "vibe_error")
        self.assertEqual(self.latest()["exit_code"], 7)
        begin = time.monotonic()
        (self.base / "STOP").touch()
        self.finish(child)
        self.assertLess(time.monotonic() - begin, 4)
        self.assertEqual(len(self.calls()), 1)

    def test_signal_interrupts_backoff(self):
        (self.root / "fake_mode").write_text("error")
        child = self.start()
        self.wait_for(lambda: self.latest().get("status") == "vibe_error")
        child.send_signal(signal.SIGTERM)
        self.finish(child)
        self.assertEqual(len(self.calls()), 1)

    def test_stop_preexisting_launches_nothing(self):
        self.base.mkdir(parents=True)
        (self.base / "STOP").touch()
        child = self.start()
        self.finish(child)
        self.assertEqual(self.calls(), [])
        self.assertFalse((self.base / "latest.json").exists())

    def test_invalid_arguments(self):
        for option, value in (("--pause", "0"), ("--grace", "-1"),
                              ("--idle-timeout", "0"), ("--heartbeat", "nan"),
                              ("--time-limit", "nan"), ("--max-price", "inf"),
                              ("--max-rounds", "-1"), ("--max-turns", "-2")):
            with self.subTest(option=option, value=value):
                with contextlib.redirect_stderr(io.StringIO()), self.assertRaises(SystemExit) as error:
                    runner.parser().parse_args([option, value])
                self.assertEqual(error.exception.code, 2)
        with self.assertRaisesRegex(ValueError, "max-turns"):
            runner.run(self.args("--max-turns", "0"), root=self.root)

    def test_missing_cli_and_project_inputs(self):
        args = self.args()
        args.vibe = str(self.root / "does not exist")
        with self.assertRaisesRegex(ValueError, "eseguibile non trovato"):
            runner.run(args, root=self.root)
        (self.root / runner.CHECKPOINT).unlink()
        with self.assertRaisesRegex(ValueError, "mancano istruzioni"):
            runner.run(self.args(), root=self.root)
        self.assertEqual(self.calls(), [])


if __name__ == "__main__":
    unittest.main(verbosity=2)
