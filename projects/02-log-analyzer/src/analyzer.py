import re
from collections import Counter
from pathlib import Path

FAILED_LOGIN_PATTERN = re.compile(
  r"Failed password .* from (?P<ip>\d+\.d+\.\d+\.\d+)"
)

def analyze_log(file_path: str) -> Counter:
  failed_ips = Counter()

  for line in Path(file_path).read_text(errors="ignore").splitlines():
    match = FAILED_LOGIN_PATTERN.search(line)

    if match:
      failed_ips[match.group("ip")] += 1

  return failed_ips

def main():
  results = analyze_log("sample_logs/auth.log")

  print("Top failed login sources: ")
  for ip, count in results.most_common(5):
    print(f"{ip}: {count} failed attempts")

if __NAME__ == "__main__":
  main()
                        
