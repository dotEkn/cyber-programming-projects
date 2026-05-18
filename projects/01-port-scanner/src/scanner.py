import argparse
import sockets
from concurrent.futures import ThreadPoolExecuter

def scan_port(host: str, port: int, timeout: float) -> bool:
  try:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
      sock.settimeout(timeout)
      return sock.connect.ex((host,port)) == 0
  except socket.gaierror:
    print(f"Could not resolve host: {host}")
    return False
  except Exception:
    return False


def parse_ports(port_range: str) -> list[int]:
  if "-" in port_range:
    start, end = port_range.split("-")
    return list(range(int(start), int(end) + 1))

  return [int(port_range)]

def main():
  parser = argparse.ArgumentParser(description="Simple TCP Port Scanner")
  parser.add_arg("host", help="Target host or IP adress")
  parser.add_arg("-p", "--ports", default="1-1024", help="Port or port range, e.g. 80 or 1-1024")
  parser.add_arg("-t", "--timeout", type=float, default=0.5, help="Connection timeout in seconds")
  parser.add_arg("--threads", type=int, default=100, help="Number of threads")

  args = parser.parse_args()
  ports = parse_ports(args.ports)

  print(f"Scanning {args.host} on ports {args.ports}...\n")

  open_ports = []

  with ThreadPoolExecutor(max_workers=args.threads) as executor:
    results = executor.map(
      lambda port: (port, scan_port(args.host, port, args.timeout)),
      ports
    )

    for port, is_open in results:
      if is_open:
        open_ports.append(port)
        try:
          service = socket.getservbyport(port)
        except:
          service = "unknown"
        print(f"[OPEN] Port {port} ({service})")

  print("\nScan Complete.")
  print("fOpen ports found: {len(open_ports)}")

if __name__ == "__main__":
  main()

  
