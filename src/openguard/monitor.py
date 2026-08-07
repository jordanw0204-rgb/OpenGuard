"""Process/network monitoring coordinator and executable baseline logic."""

from __future__ import annotations

import threading
import time
from collections.abc import Callable
from dataclasses import replace

from .config import MONITOR_INTERVAL_SECONDS
from .models import ProcessRecord, SecurityEvent, Severity, SystemSnapshot, utc_now
from .reputation import EndpointEnricher
from .telemetry import EtwProcessEventSource, ProcessEvent, WfpNetEventMonitor
from .storage import Database
from .windows_api import WindowsNative


class SystemMonitor:
    def __init__(
        self,
        native: WindowsNative,
        database: Database,
        interval: float = MONITOR_INTERVAL_SECONDS,
        on_snapshot: Callable[[SystemSnapshot], None] | None = None,
        on_event: Callable[[SecurityEvent], None] | None = None,
        on_error: Callable[[Exception], None] | None = None,
        endpoint_enricher: EndpointEnricher | None = None,
        process_events: EtwProcessEventSource | None = None,
        wfp_monitor: WfpNetEventMonitor | None = None,
    ) -> None:
        self.native = native
        self.database = database
        self.interval = max(interval, 0.5)
        self.on_snapshot = on_snapshot
        self.on_event = on_event
        self.on_error = on_error
        self.endpoint_enricher = endpoint_enricher or EndpointEnricher()
        self.process_events = process_events or EtwProcessEventSource()
        self.wfp_monitor = wfp_monitor or WfpNetEventMonitor()
        self._stop = threading.Event()
        self._thread: threading.Thread | None = None
        self._collection_lock = threading.Lock()
        self._wake = threading.Event()

    @property
    def running(self) -> bool:
        return bool(self._thread and self._thread.is_alive())

    def start(self) -> None:
        if self.running:
            return
        self._stop.clear()
        self.process_events.start(self._on_process_event)
        self.wfp_monitor.start()
        self._thread = threading.Thread(target=self._run, name="OpenGuardMonitor", daemon=True)
        self._thread.start()

    def stop(self, timeout: float = 5.0) -> None:
        self._stop.set()
        self._wake.set()
        thread = self._thread
        if thread and thread.is_alive() and thread is not threading.current_thread():
            thread.join(timeout=timeout)
        self.endpoint_enricher.close()
        self.process_events.stop(timeout=timeout)
        self.wfp_monitor.stop()

    def collect_snapshot(self, persist: bool = True) -> SystemSnapshot:
        with self._collection_lock:
            processes = self.native.processes(verify_signatures=True)
            baseline_exists = self.database.baseline_initialized()
            identities = (process.identity for process in processes)
            known = self.database.known_executable_identities(identities)
            observed_at = utc_now()
            updated: list[ProcessRecord] = []
            new_events: list[SecurityEvent] = []
            for process in processes:
                is_unseen = bool(process.identity and process.identity not in known)
                is_new = baseline_exists and is_unseen
                record = replace(process, is_new=is_new)
                updated.append(record)
                if is_new:
                    severity = process.risk.severity
                    if severity == Severity.INFO:
                        severity = Severity.LOW
                    evidence = "; ".join(process.risk.reasons) or "Executable identity was not in the local baseline"
                    event = SecurityEvent(
                        event_type="new_executable",
                        severity=severity,
                        title=f"New executable observed: {process.name}",
                        detail=evidence,
                        process_id=process.pid,
                        path=process.path,
                    )
                    if persist:
                        event_id = self.database.record_event(event)
                        event = replace(event, event_id=event_id)
                    new_events.append(event)

            if persist:
                self.database.record_executables(
                    (
                        (
                            process.identity,
                            process.path,
                            process.name,
                            str(process.signature),
                            process.risk.score,
                            observed_at,
                        )
                        for process in updated
                    )
                )
                if not baseline_exists:
                    self.database.complete_baseline()

            process_map = {process.pid: process for process in updated}
            endpoints = self.endpoint_enricher.enrich(self.native.endpoints(process_map))
            metered_tcp = sum(endpoint.usage_status == "active" for endpoint in endpoints)
            warming_tcp = sum(endpoint.usage_status == "warming" for endpoint in endpoints)
            notes = [
                "Network rows show current endpoints; TCP byte totals begin when Windows collection is enabled.",
                "PTR hostnames are informational; reputation checks use a signed local feed only.",
            ]
            if metered_tcp:
                notes.append(f"Live TCP byte accounting is active on {metered_tcp} established connections.")
            elif warming_tcp:
                notes.append("TCP byte accounting is warming up; rates appear after the next sample.")
            else:
                notes.append("TCP byte accounting requires the elevated OpenGuard Monitor service; UDP rates are not yet available.")
            if self.process_events.running:
                notes.append("Process starts/stops trigger refreshes through ETW; polling reconciles state and metrics.")
            else:
                notes.append(f"ETW unavailable ({self.process_events.detail or self.process_events.status}); using polling fallback.")
            notes.append(f"WFP telemetry: {self.wfp_monitor.status} ({self.wfp_monitor.detail}).")
            elevated = self.native.is_elevated()
            if not elevated:
                notes.append("Running without elevation; protected process details may be unavailable.")
            snapshot = SystemSnapshot(
                processes=tuple(updated),
                endpoints=tuple(endpoints),
                captured_at=observed_at,
                elevated=elevated,
                coverage_notes=tuple(notes),
            )
            for event in new_events:
                if self.on_event:
                    self.on_event(event)
            return snapshot

    def _run(self) -> None:
        while not self._stop.is_set():
            started = time.monotonic()
            try:
                snapshot = self.collect_snapshot(persist=True)
                if self.on_snapshot:
                    self.on_snapshot(snapshot)
            except Exception as error:  # keep background protection observable
                if self.on_error:
                    self.on_error(error)
            elapsed = time.monotonic() - started
            self._wake.wait(max(self.interval - elapsed, 0.1))
            self._wake.clear()

    def _on_process_event(self, _event: ProcessEvent) -> None:
        self._wake.set()
