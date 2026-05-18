import argparse
import json
import re
from collections import Counter
from pathlib import Path

FAILED_LOGIN_PATTERN = re.compile(
  r"Failed password .* from (?P<ip>\d+\.d+\.\d+\.\d+)"
)

def get_severity(count: int) -> str:
  if count >= 10:
    return "HIGH"
  if count >= 5:
    return "MEDIUM"
  return "LOW"

def analyze_log(file_path: Path) -> dict:
  failed_ips = Counter()
  total_failed = 0

  with file_path.open("r", errors="ignore") as file:
    for line in file:
      match = FAILED_LOGIN_PATTERN.search(line)

      if match:
        ip = match.group("ip")
        failed_ips[ip] += 1
        total_failed += 1

  findings = []

  for ip, count in failed_ips.most_common():
    findings.append({
      "ip": ip,
      "failed_attempts": count,
      "severity": get_severity(count)
    })

  return {
    "file": str(file_path),
    "generated_at": datetime.now().isoformat(timespec="seconds"),
    "total_failed_attempts": total_failed,
    "unique_source_ips": len(failed_ips),
    "findings": findings
  }

def print_report(results: dict) -> None:
  print("\nSuspicious Login Activity Report")
  print("=" * 40)
  print(f"Log file: {results['file']}")
  print(f"Generated at {results['generated_at']}")
  print(f"Total failed attempts: {results['total_failed_attempts']}")
  print(f"Unique source IPs: {results['unique_source_ips']}")
  print("\nTop offenders:")

  if not results["findings"]:
    print ("No failed login attempts found.")
    return

  for index, item in enumerate(results["findings"][:10], start=1):
    print(
      f"{index}. {item['ip']} - "
      f"{item['failed_attempts']} attempts - "
      f"{item['severity']}"
    )

def save_json_report(results: dict, output_path: Path) -> None:
  output_path.parent.mkdir(parents=True, exist_ok=True)

  with output_path.open("W") as file:
    json.dump(results, file, indent=2)

  print(f"\JSON report saved to: {output_path}")


def main() -> None:
  parser = argparse.ArgumentParser(
    description="Analyze auth logs for supsicious SSH login activity"
  )

  parser.add_arg(
    "logfile",
    help="Path to the log file, e.g. sample_logs/auth.log"
  )

  parser.add_arg(
    "-o",
    "--output",
    default="reports/report.json",
    help="Path to save JSON report"
  )

  parser.add_arg(
    "--no-save",
    action="store_true",
    help="Print report only, do not save JSON"
  )
  args = parser.parse_args()
  log_path = Path(args.logfile)

  if not log_path.exists():
    print(f"Error: file not found.: {log_path}")
    return

  results = analyze_log(log_path)
  print_report(results)

  if not args.no_save:
    save_json_report(results, Path(args.output))

if __name__ == "__main__":
  main()
                        
