import sys
import time
import signal
import argparse
from datetime import datetime

from file_monitor import FileTransferMonitor
from config import MONITOR_DIRECTORIES


def signal_handler(sig, frame):
    print("\nShutting down monitor...")
    monitor.stop()
    sys.exit(0)


def print_banner():
    print("=" * 60)
    print("  Secure File Transfer Monitoring System")
    print("=" * 60)
    print()


def print_status(monitor):
    status = monitor.get_status()
    print("\n--- System Status ---")
    print(f"Running: {status['running']}")
    print(f"Monitored Directories: {len(status['monitored_directories'])}")
    for d in status["monitored_directories"]:
        print(f"  - {d}")
    print(f"Tracked Files: {status['tracked_files']}")
    print(f"Total Events: {status['total_events']}")
    print(f"Total Alerts: {status['total_alerts']}")
    if status["alert_summary"]:
        print("Alert Summary:")
        for alert_type, count in status["alert_summary"]["by_type"].items():
            print(f"  {alert_type}: {count}")
    print("----------------------\n")


def run_monitor():
    global monitor
    parser = argparse.ArgumentParser(
        description="Secure File Transfer Monitoring System"
    )
    parser.add_argument(
        "--verify",
        action="store_true",
        help="Verify integrity of all tracked files and exit",
    )
    parser.add_argument(
        "--report",
        action="store_true",
        help="Generate audit report and exit",
    )
    parser.add_argument(
        "--status",
        action="store_true",
        help="Show current status and exit",
    )
    parser.add_argument(
        "--interval",
        type=int,
        default=60,
        help="Status check interval in seconds (default: 60)",
    )
    args = parser.parse_args()

    print_banner()

    monitor = FileTransferMonitor()

    if args.verify:
        print("Verifying file integrity...")
        results = monitor.verify_all_files()
        for file_path, result in results.items():
            status_icon = "[OK]" if result["status"] == "verified" else "[FAIL]"
            print(f"  {status_icon} {file_path}: {result['status']}")
        print(f"\nTotal files checked: {len(results)}")
        return

    if args.report:
        print("Generating audit report...")
        report_path = monitor.audit_logger.generate_report()
        print(f"Report saved to: {report_path}")
        return

    if args.status:
        print_status(monitor)
        return

    signal.signal(signal.SIGINT, signal_handler)
    signal.signal(signal.SIGTERM, signal_handler)

    print("Starting file transfer monitoring...")
    print("Press Ctrl+C to stop.\n")

    print("Monitored directories:")
    for d in MONITOR_DIRECTORIES:
        print(f"  - {d}")
    print()

    monitor.start()

    print("Monitor is running. Watching for file events...\n")

    try:
        while True:
            time.sleep(args.interval)
            print_status(monitor)
    except KeyboardInterrupt:
        print("\nShutting down monitor...")
        monitor.stop()
        print("Monitor stopped.")


if __name__ == "__main__":
    run_monitor()
