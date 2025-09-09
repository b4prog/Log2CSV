# Log2CSV

`Log2CSV` is a command-line tool written in Go that transforms raw log files into CSV.
It extracts structured data from logs using a regular expression with named capture groups and writes CSV to STDOUT.

---

## Features

- Reads log lines from **STDIN** and writes CSV to **STDOUT**.
- Extracts fields using **named capture groups** (`(?P<Name>...)`).
- The **CSV header row** is automatically generated from group names.
- Preserves the input's line endings (LF/CRLF).
- Optional **unmatched mode** (`-unmatched`) to print **unique non-matching lines** instead of CSV.

## Usage

Log2CSV reads from STDIN and, by default, converts matching lines to CSV written to STDOUT using the provided regular expression.

- **CSV mode :** provide `-regexp` with named capture groups; matching lines become CSV rows (header generated automatically).
- **Unmatched mode:** add `-unmatched` to print each **unique** input line that **does not** match the pattern (one per line), to STDOUT. No CSV is produced in this mode.

### Example - convert UFW log to CSV

```sh
log2csv -regexp '^(?P<Timestamp>\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?\+\d{2}:\d{2})\s+(?P<Hostname>\S+)\s+(?P<Facility>\S+):\s+\[\s*(?P<Kernel_Time>\d+(?:\.\d+)?)\]\s+\[(?P<Action>UFW\s+\S+)\]\s+IN=(?P<IN>\S*)\s+OUT=(?P<OUT>\S*)\s+MAC=(?P<MAC>\S*)\s+SRC=(?P<SRC>\S+)\s+DST=(?P<DST>\S+)\s+LEN=(?P<LEN>\d+)(?:(?:\s+(?:TOS=(?P<TOS>0x[0-9A-Fa-f]{2})\s+)?(?:PREC=(?P<PREC>0x[0-9A-Fa-f]{2})\s+)?(?:TTL=(?P<TTL>\d+)\s+)?ID=(?P<ID>\d+)(?:\s+(?P<DF>DF))?)|\s+TC=(?P<TC>\d+)\s+HOPLIMIT=(?P<HOPLIMIT>\d+)\s+FLOWLBL=(?P<FLOWLBL>[0-9A-Fa-fx]+))?\s+PROTO=(?P<PROTO>[A-Za-z0-9]+)(?:\s+(?:SPT|SP)=(?P<SPT>\d+))?(?:\s+(?:DPT|DP)=(?P<DPT>\d+))?(?:\s+WINDOW=(?P<WINDOW>\d+))?(?:\s+RES=(?P<RES>0x[0-9A-Fa-f]{2}))?(?:\s+(?P<TCP_Flags>(?:SYN|ACK|FIN|RST|PSH|URG|CWR|ECE)(?:\s+(?:SYN|ACK|FIN|RST|PSH|URG|CWR|ECE))*))?(?:\s+URGP=(?P<URGP>\d+))?(?:\s+TYPE=(?P<ICMP_TYPE>\d+))?(?:\s+CODE=(?P<ICMP_CODE>\d+))?(?:\s+SEQ=(?P<ICMP_SEQ>\d+))?(?:\s+LEN=(?P<L4_LEN>\d+))?\s*$' < /var/log/ufw.log
```

On Windows

```powershell
Get-Content C:\path\ufw.log | log2csv -regexp "^(?P<Timestamp>\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?\+\d{2}:\d{2})\s+(?P<Hostname>\S+)\s+(?P<Facility>\S+):\s+\[\s*(?P<Kernel_Time>\d+(?:\.\d+)?)\]\s+\[(?P<Action>UFW\s+\S+)\]\s+IN=(?P<IN>\S*)\s+OUT=(?P<OUT>\S*)\s+MAC=(?P<MAC>\S*)\s+SRC=(?P<SRC>\S+)\s+DST=(?P<DST>\S+)\s+LEN=(?P<LEN>\d+)(?:(?:\s+(?:TOS=(?P<TOS>0x[0-9A-Fa-f]{2})\s+)?(?:PREC=(?P<PREC>0x[0-9A-Fa-f]{2})\s+)?(?:TTL=(?P<TTL>\d+)\s+)?ID=(?P<ID>\d+)(?:\s+(?P<DF>DF))?)|\s+TC=(?P<TC>\d+)\s+HOPLIMIT=(?P<HOPLIMIT>\d+)\s+FLOWLBL=(?P<FLOWLBL>[0-9A-Fa-fx]+))?\s+PROTO=(?P<PROTO>[A-Za-z0-9]+)(?:\s+(?:SPT|SP)=(?P<SPT>\d+))?(?:\s+(?:DPT|DP)=(?P<DPT>\d+))?(?:\s+WINDOW=(?P<WINDOW>\d+))?(?:\s+RES=(?P<RES>0x[0-9A-Fa-f]{2}))?(?:\s+(?P<TCP_Flags>(?:SYN|ACK|FIN|RST|PSH|URG|CWR|ECE)(?:\s+(?:SYN|ACK|FIN|RST|PSH|URG|CWR|ECE))*))?(?:\s+URGP=(?P<URGP>\d+))?(?:\s+TYPE=(?P<ICMP_TYPE>\d+))?(?:\s+CODE=(?P<ICMP_CODE>\d+))?(?:\s+SEQ=(?P<ICMP_SEQ>\d+))?(?:\s+LEN=(?P<L4_LEN>\d+))?\s*$".
```

## Install

```sh
go install github.com/b4prog/Log2CSV@latest
```

## Build from source

```sh
task build
./build/log2csv -help
```
