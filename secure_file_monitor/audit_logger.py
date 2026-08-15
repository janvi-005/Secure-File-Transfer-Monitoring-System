import json
import logging
import os
from datetime import datetime
from pathlib import Path
from config import LOG_FILE, REPORT_DIR


class AuditLogger:
    def __init__(self):
        self.log_file = LOG_FILE
        self.report_dir = REPORT_DIR
        self.events = []
        self._setup_logger()

    def _setup_logger(self):
        self.log_file.parent.mkdir(parents=True, exist_ok=True)
        self.logger = logging.getLogger("AuditLogger")
        self.logger.setLevel(logging.INFO)

        if not self.logger.handlers:
            file_handler = logging.FileHandler(self.log_file, encoding="utf-8")
            file_handler.setLevel(logging.INFO)
            formatter = logging.Formatter(
                "%(asctime)s | %(levelname)s | %(message)s",
                datefmt="%Y-%m-%d %H:%M:%S",
            )
            file_handler.setFormatter(formatter)
            self.logger.addHandler(file_handler)

    def log_event(self, event_type, details, severity="INFO"):
        event = {
            "timestamp": datetime.now().isoformat(),
            "event_type": event_type,
            "severity": severity,
            "details": details,
        }
        self.events.append(event)

        log_message = f"[{event_type}] {json.dumps(details)}"
        if severity == "CRITICAL":
            self.logger.critical(log_message)
        elif severity == "WARNING":
            self.logger.warning(log_message)
        else:
            self.logger.info(log_message)

    def log_file_created(self, file_path, file_size=0):
        self.log_event(
            "FILE_CREATED",
            {
                "path": file_path,
                "size": file_size,
                "user": os.getenv("USERNAME", "unknown"),
            },
        )

    def log_file_modified(self, file_path, old_hash=None, new_hash=None):
        self.log_event(
            "FILE_MODIFIED",
            {
                "path": file_path,
                "old_hash": old_hash,
                "new_hash": new_hash,
                "user": os.getenv("USERNAME", "unknown"),
            },
        )

    def log_file_deleted(self, file_path):
        self.log_event(
            "FILE_DELETED",
            {"path": file_path, "user": os.getenv("USERNAME", "unknown")},
        )

    def log_file_moved(self, src_path, dest_path):
        self.log_event(
            "FILE_MOVED",
            {
                "source": src_path,
                "destination": dest_path,
                "user": os.getenv("USERNAME", "unknown"),
            },
        )

    def log_file_copied(self, src_path, dest_path):
        self.log_event(
            "FILE_COPIED",
            {
                "source": src_path,
                "destination": dest_path,
                "user": os.getenv("USERNAME", "unknown"),
            },
        )

    def log_integrity_check(self, file_path, result):
        severity = "WARNING" if result.get("status") == "tampered" else "INFO"
        self.log_event(
            "INTEGRITY_CHECK",
            {"path": file_path, "result": result},
            severity=severity,
        )

    def log_authorization_check(self, file_path, authorized, reason=""):
        severity = "WARNING" if not authorized else "INFO"
        self.log_event(
            "AUTHORIZATION_CHECK",
            {
                "path": file_path,
                "authorized": authorized,
                "reason": reason,
                "user": os.getenv("USERNAME", "unknown"),
            },
            severity=severity,
        )

    def log_sensitive_access(self, file_path, access_type):
        self.log_event(
            "SENSITIVE_ACCESS",
            {
                "path": file_path,
                "access_type": access_type,
                "user": os.getenv("USERNAME", "unknown"),
            },
            severity="WARNING",
        )

    def generate_report(self, start_time=None, end_time=None):
        self.report_dir.mkdir(parents=True, exist_ok=True)

        filtered_events = self.events
        if start_time:
            filtered_events = [
                e for e in filtered_events if e["timestamp"] >= start_time.isoformat()
            ]
        if end_time:
            filtered_events = [
                e for e in filtered_events if e["timestamp"] <= end_time.isoformat()
            ]

        report = {
            "generated_at": datetime.now().isoformat(),
            "period": {
                "start": start_time.isoformat() if start_time else None,
                "end": end_time.isoformat() if end_time else None,
            },
            "summary": {
                "total_events": len(filtered_events),
                "by_type": {},
                "by_severity": {},
            },
            "events": filtered_events,
        }

        for event in filtered_events:
            event_type = event["event_type"]
            severity = event["severity"]
            report["summary"]["by_type"][event_type] = (
                report["summary"]["by_type"].get(event_type, 0) + 1
            )
            report["summary"]["by_severity"][severity] = (
                report["summary"]["by_severity"].get(severity, 0) + 1
            )

        report_filename = f"report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
        report_path = self.report_dir / report_filename

        with open(report_path, "w") as f:
            json.dump(report, f, indent=2)

        return report_path

    def get_events(self, event_type=None, severity=None, limit=None):
        filtered = self.events

        if event_type:
            filtered = [e for e in filtered if e["event_type"] == event_type]
        if severity:
            filtered = [e for e in filtered if e["severity"] == severity]
        if limit:
            filtered = filtered[-limit:]

        return filtered

    def clear_events(self):
        self.events.clear()
