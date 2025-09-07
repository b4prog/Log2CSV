# Log2CSV

`Log2CSV` is a command-line tool written in Go that transforms raw log files into CSV.
It extracts structured data from logs using a regular expression with named capture groups and writes CSV to STDOUT.

---

## Features

- Reads log lines from **STDIN** and writes CSV to **STDOUT**.
- Extracts fields using **named capture groups** (`(?P<Name>...)`).
- The **CSV header row** is automatically generated from group names.
- Ignores lines that do not match the expression.
- Skips matched lines where every named group is empty.
- Preserves the input's line endings (LF/CRLF).

## Usage

Log2CSV reads from STDIN and converts matching lines to CSV, writing the result to STDOUT, using the provided regular expression.

### Example - convert UFW log to CSV

```sh
log2csv -regexp '^(?P<Timestamp>\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d+\+\d{2}:\d{2})\s+(?P<Hostname>\S+)\s+(?P<Facility>\S+):\s+\[(?P<Kernel_Time>[\d\.]+)\]\s+\[(?P<Action>UFW\s+\S+)\]\s+IN=(?P<IN>\S*)\s+OUT=(?P<OUT>\S*)\s+MAC=(?P<MAC>\S+)\s+SRC=(?P<SRC>\S+)\s+DST=(?P<DST>\S+)\s+LEN=(?P<LEN>\d+)\s+(?:TOS=(?P<TOS>0x[0-9A-Fa-f]{2})\s+)?(?:PREC=(?P<PREC>0x[0-9A-Fa-f]{2})\s+)?(?:TTL=(?P<TTL>\d+)\s+)?ID=(?P<ID>\d+)\s+(?:(?P<DF>DF)\s+)?PROTO=(?P<PROTO>[A-Z0-9]+)\s+(?:(?:SPT|SP)=(?P<SPT>\d+)\s+)?(?:(?:DPT|DP)=(?P<DPT>\d+)\s+)?(?:WINDOW=(?P<WINDOW>\d+)\s+)?(?:RES=(?P<RES>0x[0-9A-Fa-f]{2})\s+)?(?:(?P<TCP_Flags>(?:SYN|ACK|FIN|RST|PSH|URG|CWR|ECE)(?:\s+(?:SYN|ACK|FIN|RST|PSH|URG|CWR|ECE))*))?(?:\s+URGP=(?P<URGP>\d+))?(?:\s+TC=(?P<TC>\d+))?(?:\s+HOPLIMIT=(?P<HOPLIMIT>\d+))?(?:\s+FLOWLBL=(?P<FLOWLBL>\d+))?(?:\s+LEN=(?P<L4_LEN>\d+))?\s*$' < /var/log/ufw.log
```

On Windows

```powershell
Get-Content C:\path\ufw.log | log2csv -regexp "^(?P<Timestamp>\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d+\+\d{2}:\d{2})\s+(?P<Hostname>\S+)\s+(?P<Facility>\S+):\s+\[(?P<Kernel_Time>[\d\.]+)\]\s+\[(?P<Action>UFW\s+\S+)\]\s+IN=(?P<IN>\S*)\s+OUT=(?P<OUT>\S*)\s+MAC=(?P<MAC>\S+)\s+SRC=(?P<SRC>\S+)\s+DST=(?P<DST>\S+)\s+LEN=(?P<LEN>\d+)\s+(?:TOS=(?P<TOS>0x[0-9A-Fa-f]{2})\s+)?(?:PREC=(?P<PREC>0x[0-9A-Fa-f]{2})\s+)?(?:TTL=(?P<TTL>\d+)\s+)?ID=(?P<ID>\d+)\s+(?:(?P<DF>DF)\s+)?PROTO=(?P<PROTO>[A-Z0-9]+)\s+(?:(?:SPT|SP)=(?P<SPT>\d+)\s+)?(?:(?:DPT|DP)=(?P<DPT>\d+)\s+)?(?:WINDOW=(?P<WINDOW>\d+)\s+)?(?:RES=(?P<RES>0x[0-9A-Fa-f]{2})\s+)?(?:(?P<TCP_Flags>(?:SYN|ACK|FIN|RST|PSH|URG|CWR|ECE)(?:\s+(?:SYN|ACK|FIN|RST|PSH|URG|CWR|ECE))*))?(?:\s+URGP=(?P<URGP>\d+))?(?:\s+TC=(?P<TC>\d+))?(?:\s+HOPLIMIT=(?P<HOPLIMIT>\d+))?(?:\s+FLOWLBL=(?P<FLOWLBL>\d+))?(?:\s+LEN=(?P<L4_LEN>\d+))?\s*$".
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
