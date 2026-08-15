import json
import logging
import os
from datetime import datetime, timedelta
from collections import defaultdict
from config import ALERT_LOG_FILE, ALERT_THRESHOLDS


class AlertSystem:
    def __init__(self):
        self.alert_log_file = ALERT_LOG_FILE
        self.alerts = []
        self.event_counts = defaultdict(list)
        self._setup_logger()

    def _setup_logger(self):
        self.alert_log_file.parent.mkdir(parents=True, exist_ok=True)
        self.logger = logging.getLogger("AlertSystem")
        self.logger.setLevel(logging.WARNING)

        if not self.logger.handlers:
            file_handler = logging.FileHandler(self.alert_log_file, encoding="utf-8")
            file_handler.setLevel(logging.WARNING)
            formatter = logging.Formatter(
                "%(asctime)s | %(levelname)s | %(message)s",
                datefmt="%Y-%m-%d %H:%M:%S",
            )
            file_handler.setFormatter(formatter)
            self.logger.addHandler(file_handler)

    def _record_event(self, event_type):
        now = datetime.now()
        self.event_counts[event_type].append(now)
        cutoff = now - timedelta(hours=1)
        self.event_counts[event_type] = [
            t for t in self.event_counts[event_type] if t > cutoff
        ]

    def _check_threshold(self, event_type, max_count, window_minutes=60):
        now = datetime.now()
        cutoff = now - timedelta(minutes=window_minutes)
        recent_events = [t for t in self.event_counts[event_type] if t > cutoff]
        return len(recent_events) >= max_count

    def raise_alert(self, alert_type, message, severity="WARNING", details=None):
        alert = {
            "timestamp": datetime.now().isoformat(),
            "alert_type": alert_type,
            "severity": severity,
            "message": message,
            "details": details or {},
        }
        self.alerts.append(alert)

        log_message = f"[{alert_type}] {message}"
        if severity == "CRITICAL":
            self.logger.critical(log_message)
        elif severity == "ERROR":
            self.logger.error(log_message)
        else:
            self.logger.warning(log_message)

        return alert

    def check_excessive_transfers(self):
        self._record_event("file_transfer")
        threshold = ALERT_THRESHOLDS["max_transfers_per_minute"]
        if self._check_threshold("file_transfer", threshold, window_minutes=1):
            return self.raise_alert(
                "EXCESSIVE_TRANSFERS",
                f"Excessive file transfers detected (>{threshold}/minute)",
                severity="WARNING",
            )
        return None

    def check_sensitive_access(self):
        self._record_event("sensitive_access")
        threshold = ALERT_THRESHOLDS["max_sensitive_access_per_hour"]
        if self._check_threshold("sensitive_access", threshold, window_minutes=60):
            return self.raise_alert(
                "SENSITIVE_ACCESS_LIMIT",
                f"Excessive sensitive file access detected (>{threshold}/hour)",
                severity="WARNING",
            )
        return None

    def check_suspicious_hours(self):
        current_hour = datetime.now().hour
        suspicious_start, suspicious_end = ALERT_THRESHOLDS["suspicious_hours"]
        if suspicious_start <= current_hour or current_hour < suspicious_end:
            return self.raise_alert(
                "SUSPICIOUS_HOUR_ACCESS",
                "File access detected during suspicious hours",
                severity="WARNING",
            )
        return None

    def check_integrity_violation(self, file_path, result):
        if result.get("status") == "tampered":
            return self.raise_alert(
                "INTEGRITY_VIOLATION",
                f"File integrity violation detected: {file_path}",
                severity="CRITICAL",
                details={"file": file_path, "result": result},
            )
        return None

    def check_unauthorized_access(self, file_path, reason):
        return self.raise_alert(
            "UNAUTHORIZED_ACCESS",
            f"Unauthorized file access attempt: {file_path}",
            severity="WARNING",
            details={"file": file_path, "reason": reason},
        )

    def check_sensitive_file_movement(self, file_path, dest_path=None):
        return self.raise_alert(
            "SENSITIVE_FILE_MOVEMENT",
            f"Sensitive file movement detected: {file_path}",
            severity="WARNING",
            details={"source": file_path, "destination": dest_path},
        )

    def check_blocked_extension(self, file_path):
        return self.raise_alert(
            "BLOCKED_EXTENSION",
            f"File with blocked extension detected: {file_path}",
            severity="ERROR",
            details={"file": file_path},
        )

    def check_large_file(self, file_path, size_mb):
        return self.raise_alert(
            "LARGE_FILE",
            f"Large file detected ({size_mb:.1f}MB): {file_path}",
            severity="INFO",
            details={"file": file_path, "size_mb": size_mb},
        )

    def get_recent_alerts(self, minutes=30):
        cutoff = datetime.now() - timedelta(minutes=minutes)
        return [
            a for a in self.alerts if datetime.fromisoformat(a["timestamp"]) > cutoff
        ]

    def get_alerts_by_type(self, alert_type):
        return [a for a in self.alerts if a["alert_type"] == alert_type]

    def get_alerts_by_severity(self, severity):
        return [a for a in self.alerts if a["severity"] == severity]

    def get_alert_summary(self):
        summary = {
            "total_alerts": len(self.alerts),
            "by_type": defaultdict(int),
            "by_severity": defaultdict(int),
        }
        for alert in self.alerts:
            summary["by_type"][alert["alert_type"]] += 1
            summary["by_severity"][alert["severity"]] += 1
        return dict(summary)

    def clear_alerts(self):
        self.alerts.clear()
        self.event_counts.clear()
