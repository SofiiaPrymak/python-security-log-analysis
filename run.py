from collections import defaultdict

def detect_failed_logins():
    failed_attempts = defaultdict(int)

    with open("auth.log", "r") as f:
        for line in f:
            if "Failed password" in line:
                ip = line.split("from")[1].split()[0]
                failed_attempts[ip] += 1

    return {ip: c for ip, c in failed_attempts.items() if c > 5}


# POWERSHELL 
def detect_powershell():
    keywords = ["EncodedCommand","DownloadString","Invoke-WebRequest","ExecutionPolicy Bypass"]
    results = []
    with open("powershell_log.txt", "r") as f:
        for line in f:
            for k in keywords:
                if k in line:
                    results.append(line.strip())
    return results


# IOC
def load_iocs():
    with open("ioc.txt", "r") as f:
        return [line.strip() for line in f]

def check_iocs(iocs):
    matches = []
    files = ["access.log", "auth.log", "powershell_log.txt"]

    for file in files:
        with open(file, "r") as f:
            for line in f:
                for ioc in iocs:
                    if ioc in line:
                        matches.append(line.strip())

    return matches

def main():
    report = open("investigation_report.txt", "w")

    report.write("SECURITY REPORT\n\n")

    report.write("Failed Login Attempts:\n")
    for ip, count in detect_failed_logins().items():
        report.write(f"{ip} -> {count} attempts\n")

    report.write("\n")
    report.write("Suspicious PowerShell:\n")
    for cmd in detect_powershell():
        report.write(cmd + "\n")

    report.write("\n")

    report.write("IOC Matches:\n")
    iocs = load_iocs()
    for match in check_iocs(iocs):
        report.write(match + "\n")

    report.close()

    print("Report generated!")
main()