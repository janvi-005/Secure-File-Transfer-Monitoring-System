import os
import time
import fnmatch
from pathlib import Path
from datetime import datetime
from watchdog.observers import Observer
from watchdog.events import (
    FileSystemEventHandler,
    FileCreatedEvent,
    FileModifiedEvent,
    FileDeletedEvent,
    FileMovedEvent,
)

from config import (
    MONITOR_DIRECTORIES,
    SENSITIVE_PATTERNS,
    SENSITIVE_KEYWORDS,
    AUTHORIZATION_RULES,
    MONITOR_CONFIG,
)
from hash_utils import HashManager
from audit_logger import AuditLogger
from alert_system import AlertSystem


class FileEventHandler(FileSystemEventHandler):
    def __init__(self, monitor):
        super().__init__()
        self.monitor = monitor

    def on_created(self, event):
        if not event.is_directory:
            self.monitor.handle_file_created(event.src_path)

    def on_modified(self, event):
        if not event.is_directory:
            self.monitor.handle_file_modified(event.src_path)

    def on_deleted(self, event):
        if not event.is_directory:
            self.monitor.handle_file_deleted(event.src_path)

    def on_moved(self, event):
        if not event.is_directory:
            self.monitor.handle_file_moved(event.src_path, event.dest_path)


class FileTransferMonitor:
    def __init__(self):
        self.hash_manager = HashManager()
        self.audit_logger = AuditLogger()
        self.alert_system = AlertSystem()
        self.observer = None
        self.running = False
        self._pending_moves = {}

    def is_sensitive_file(self, file_path):
        file_path_lower = file_path.lower()
        filename = os.path.basename(file_path_lower)

        for pattern in SENSITIVE_PATTERNS:
            if fnmatch.fnmatch(filename, pattern):
                return True

        for keyword in SENSITIVE_KEYWORDS:
            if keyword.lower() in file_path_lower:
                return True

        return False

    def check_authorization(self, file_path):
        filename = os.path.basename(file_path).lower()
        ext = os.path.splitext(filename)[1]

        if ext in AUTHORIZATION_RULES["blocked_extensions"]:
            return False, f"Blocked file extension: {ext}"

        file_size_mb = 0
        try:
            if os.path.exists(file_path):
                file_size_mb = os.path.getsize(file_path) / (1024 * 1024)
        except OSError:
            pass

        if file_size_mb > AUTHORIZATION_RULES["max_file_size_mb"]:
            return False, f"File size ({file_size_mb:.1f}MB) exceeds limit"

        return True, "Authorized"

    def classify_event(self, file_path, event_type):
        is_sensitive = self.is_sensitive_file(file_path)
        authorized, reason = self.check_authorization(file_path)

        return {
            "file_path": file_path,
            "event_type": event_type,
            "is_sensitive": is_sensitive,
            "authorized": authorized,
            "authorization_reason": reason,
            "timestamp": datetime.now().isoformat(),
        }

    def handle_file_created(self, file_path):
        try:
            file_size = os.path.getsize(file_path) if os.path.exists(file_path) else 0
        except OSError:
            file_size = 0

        classification = self.classify_event(file_path, "CREATED")

        self.audit_logger.log_file_created(file_path, file_size)

        self.hash_manager.store_file_hash(file_path)

        self.alert_system.check_excessive_transfers()

        if classification["is_sensitive"]:
            self.audit_logger.log_sensitive_access(file_path, "creation")
            self.alert_system.check_sensitive_access()
            self.alert_system.check_suspicious_hours()
            self.alert_system.check_sensitive_file_movement(file_path)

        if not classification["authorized"]:
            self.audit_logger.log_authorization_check(
                file_path, False, classification["authorization_reason"]
            )
            self.alert_system.check_unauthorized_access(
                file_path, classification["authorization_reason"]
            )

    def handle_file_modified(self, file_path):
        if not os.path.exists(file_path):
            return

        classification = self.classify_event(file_path, "MODIFIED")

        stored_info = self.hash_manager.get_file_info(file_path)
        old_hash = stored_info["hash"] if stored_info else None

        new_hash = self.hash_manager.store_file_hash(file_path)

        self.audit_logger.log_file_modified(file_path, old_hash, new_hash)

        if old_hash and new_hash and old_hash != new_hash:
            integrity_result = self.hash_manager.verify_file_integrity(
                file_path, old_hash
            )
            self.audit_logger.log_integrity_check(file_path, integrity_result)
            self.alert_system.check_integrity_violation(file_path, integrity_result)

        self.alert_system.check_excessive_transfers()

        if classification["is_sensitive"]:
            self.audit_logger.log_sensitive_access(file_path, "modification")
            self.alert_system.check_sensitive_access()
            self.alert_system.check_suspicious_hours()

    def handle_file_deleted(self, file_path):
        classification = self.classify_event(file_path, "DELETED")

        self.audit_logger.log_file_deleted(file_path)

        self.hash_manager.remove_file_hash(file_path)

        self.alert_system.check_excessive_transfers()

        if classification["is_sensitive"]:
            self.audit_logger.log_sensitive_access(file_path, "deletion")
            self.alert_system.check_sensitive_access()
            self.alert_system.check_sensitive_file_movement(file_path)

    def handle_file_moved(self, src_path, dest_path):
        classification = self.classify_event(src_path, "MOVED")

        self.audit_logger.log_file_moved(src_path, dest_path)

        self.hash_manager.remove_file_hash(src_path)

        if os.path.exists(dest_path):
            self.hash_manager.store_file_hash(dest_path)

        self.alert_system.check_excessive_transfers()

        if classification["is_sensitive"]:
            self.audit_logger.log_sensitive_access(src_path, "move")
            self.alert_system.check_sensitive_access()
            self.alert_system.check_suspicious_hours()
            self.alert_system.check_sensitive_file_movement(src_path, dest_path)

        if not classification["authorized"]:
            self.audit_logger.log_authorization_check(
                src_path, False, classification["authorization_reason"]
            )
            self.alert_system.check_unauthorized_access(
                src_path, classification["authorization_reason"]
            )

    def handle_file_copied(self, src_path, dest_path):
        self.audit_logger.log_file_copied(src_path, dest_path)

        if os.path.exists(dest_path):
            self.hash_manager.store_file_hash(dest_path)

        self.alert_system.check_excessive_transfers()

        dest_classification = self.classify_event(dest_path, "COPIED")
        if dest_classification["is_sensitive"]:
            self.audit_logger.log_sensitive_access(dest_path, "copy")
            self.alert_system.check_sensitive_access()
            self.alert_system.check_sensitive_file_movement(src_path, dest_path)

    def verify_all_files(self):
        results = {}
        for file_path in self.hash_manager.get_stored_files():
            result = self.hash_manager.verify_file_integrity(file_path)
            results[file_path] = result
            self.audit_logger.log_integrity_check(file_path, result)
            if result["status"] == "tampered":
                self.alert_system.check_integrity_violation(file_path, result)
        return results

    def start(self):
        if self.running:
            return

        self.observer = Observer()
        event_handler = FileEventHandler(self)

        for dir_path in MONITOR_DIRECTORIES:
            if os.path.exists(dir_path):
                recursive = MONITOR_CONFIG.get("recursive", True)
                self.observer.schedule(event_handler, dir_path, recursive=recursive)
                self.audit_logger.log_event(
                    "MONITORING_STARTED",
                    {"directory": dir_path, "recursive": recursive},
                )

        self.observer.start()
        self.running = True
        self.audit_logger.log_event("SYSTEM_STARTED", {"status": "active"})

    def stop(self):
        if self.observer and self.running:
            self.observer.stop()
            self.observer.join()
            self.running = False
            self.audit_logger.log_event("SYSTEM_STOPPED", {"status": "inactive"})

    def get_status(self):
        return {
            "running": self.running,
            "monitored_directories": MONITOR_DIRECTORIES,
            "tracked_files": len(self.hash_manager.get_stored_files()),
            "total_events": len(self.audit_logger.events),
            "total_alerts": len(self.alert_system.alerts),
            "alert_summary": self.alert_system.get_alert_summary(),
        }
