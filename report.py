import json
import sys
from texttable import Texttable
from collections import Counter


def load_json(input_file):
    """
    Load JSON data from a file.
    """
    try:
        with open(input_file, 'r') as file:
            return json.load(file)
    except Exception as e:
        print(f"Error loading JSON file: {e}")
        sys.exit(1)


def write_report(output_file, content):
    """
    Write the report content to the specified output file.
    """
    try:
        with open(output_file, 'w') as file:
            file.write(content)
    except Exception as e:
        print(f"Error writing report to file: {e}")
        sys.exit(1)


def generate_summary_section(data):
    """
    Generate a textual section summarizing the information for each domain.
    """
    section = "Domain Summary\n" + "=" * 50 + "\n"
    for domain, info in data.items():
        section += f"Domain: {domain}\n"
        for key, value in info.items():
            if isinstance(value, list):
                section += f"  {key}: {', '.join(map(str, value))}\n"
            else:
                section += f"  {key}: {value}\n"
        section += "-" * 50 + "\n"
    return section


def generate_rtt_table(data):
    """
    Generate a table showing RTT ranges for all domains, sorted by minimum RTT.
    """
    table = Texttable()
    table.set_deco(Texttable.HEADER)
    table.set_cols_align(["l", "l"])
    table.add_row(["Domain", "RTT Range (ms)"])

    rtt_data = [(domain, info.get("rtt_range", [None, None])) for domain, info in data.items()]
    rtt_data = sorted(rtt_data, key=lambda x: x[1][0] if x[1][0] is not None else float('inf'))

    for domain, rtt in rtt_data:
        table.add_row([domain, str(rtt)])

    return "\nRTT Range Table\n" + table.draw() + "\n"


def generate_occurrences_table(data, key, title):
    """
    Generate a table showing occurrences for the specified key, sorted by popularity.
    """
    table = Texttable()
    table.set_deco(Texttable.HEADER)
    table.set_cols_align(["l", "l"])
    table.add_row([title, "Occurrences"])

    values = [info.get(key) for info in data.values() if info.get(key)]
    values = [item for sublist in values for item in (sublist if isinstance(sublist, list) else [sublist])]

    counter = Counter(values)
    sorted_counts = sorted(counter.items(), key=lambda x: x[1], reverse=True)

    for item, count in sorted_counts:
        table.add_row([item, count])

    return f"\n{title} Table\n" + table.draw() + "\n"


def generate_tls_support_table(data):
    """
    Generate a table showing the percentage of domains supporting each TLS version.
    """
    table = Texttable()
    table.set_deco(Texttable.HEADER)
    table.set_cols_align(["l", "r"])
    table.add_row(["TLS Version", "Percentage"])

    total_domains = len(data)
    if total_domains == 0:
        return "TLS Support Table\nNo data available."

    tls_versions = Counter()
    for info in data.values():
        if "tls_versions" in info and info["tls_versions"]:
            tls_versions.update(info["tls_versions"])

    for version, count in tls_versions.items():
        percentage = (count / total_domains) * 100
        table.add_row([version, f"{percentage:.2f}%"])

    return "\nTLS Support Table\n" + table.draw() + "\n"


def generate_support_table(data):
    """
    Generate a table showing percentages for HTTP, HTTPS redirect, HSTS, and IPv6 support.
    """
    table = Texttable()
    table.set_deco(Texttable.HEADER)
    table.set_cols_align(["l", "r"])
    table.add_row(["Feature", "Percentage"])

    total_domains = len(data)
    if total_domains == 0:
        return "Support Table\nNo data available."

    metrics = {
        "Plain HTTP": sum(1 for info in data.values() if info.get("insecure_http")),
        "HTTPS Redirect": sum(1 for info in data.values() if info.get("redirect_to_https")),
        "HSTS": sum(1 for info in data.values() if info.get("hsts")),
        "IPv6 Support": sum(1 for info in data.values() if info.get("ipv6_addresses")),
    }

    for feature, count in metrics.items():
        percentage = (count / total_domains) * 100
        table.add_row([feature, f"{percentage:.2f}%"])

    return "\nSupport Table\n" + table.draw() + "\n"


def main():
    """
    Main function to generate the report.
    """
    if len(sys.argv) != 3:
        print("Usage: python3 report.py [input_file.json] [output_file.txt]")
        sys.exit(1)

    input_file = sys.argv[1]
    output_file = sys.argv[2]

    # Load JSON data
    data = load_json(input_file)

    # Generate the report
    report = ""
    report += generate_summary_section(data)
    report += generate_rtt_table(data)
    report += generate_occurrences_table(data, "root_ca", "Root Certificate Authority")
    report += generate_occurrences_table(data, "http_server", "Web Server")
    report += generate_tls_support_table(data)
    report += generate_support_table(data)

    # Write the report to a file
    write_report(output_file, report)
    print(f"Report generated and saved to {output_file}")


if __name__ == "__main__":
    main()
