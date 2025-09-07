package main

import (
	"bufio"
	"bytes"
	"encoding/csv"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"regexp"
	"strings"
)

const (
	csvSeparator   = ','
	logLineSizeMax = 64 * 1024
	bufferSizeMax  = 10 * 1024 * 1024
)

var (
	// ErrInvalidRegexp is returned when the provided regular expression
	// cannot be compiled due to invalid syntax.
	ErrInvalidRegexp = errors.New("invalid regular expression syntax")
	// ErrNoNamedCaptureGroups is returned when the provided regular expression
	// does not contain any named capture groups (e.g. (?P<name>...)).
	ErrNoNamedCaptureGroups = errors.New("the regular expression must contain at least one named capture group")
)

func usage() {
	msg := `Usage:
  log2csv -regexp '<pattern with (?P<name>...) groups>'

Description:
  Reads log lines from STDIN, extracts named capture groups using the provided regular expression,
  and writes a CSV to STDOUT.

Examples:
  log2csv -regexp '^(?P<Timestamp>\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?\+\d{2}:\d{2})\s+(?P<Hostname>\S+)\s+(?P<Facility>\S+):\s+\[(?P<Kernel_Time>[\d\.]+)\]\s+\[(?P<Action>UFW\s+\S+)\]\s+IN=(?P<IN>\S*)\s+OUT=(?P<OUT>\S*)\s+MAC=(?P<MAC>\S+)\s+SRC=(?P<SRC>\S+)\s+DST=(?P<DST>\S+)\s+LEN=(?P<LEN>\d+)\s+(?:(?:TOS=(?P<TOS>0x[0-9A-Fa-f]{2})\s+)?(?:PREC=(?P<PREC>0x[0-9A-Fa-f]{2})\s+)?(?:TTL=(?P<TTL>\d+)\s+)?ID=(?P<ID>\d+)\s+(?:(?P<DF>DF)\s+)?|(?:TC=(?P<TC>\d+)\s+)?(?:HOPLIMIT=(?P<HOPLIMIT>\d+)\s+)?(?:FLOWLBL=(?P<FLOWLBL>[0-9A-Fa-fx]+)\s+)? )PROTO=(?P<PROTO>[A-Za-z0-9]+)\s+(?:(?:SPT|SP)=(?P<SPT>\d+)\s+)?(?:(?:DPT|DP)=(?P<DPT>\d+)\s+)?(?:WINDOW=(?P<WINDOW>\d+)\s+)?(?:RES=(?P<RES>0x[0-9A-Fa-f]{2})\s+)?(?:(?P<TCP_Flags>(?:SYN|ACK|FIN|RST|PSH|URG|CWR|ECE)(?:\s+(?:SYN|ACK|FIN|RST|PSH|URG|CWR|ECE))*))?(?:\s+URGP=(?P<URGP>\d+))?(?:\s+TYPE=(?P<ICMP_TYPE>\d+))?(?:\s+CODE=(?P<ICMP_CODE>\d+))?(?:\s+SEQ=(?P<ICMP_SEQ>\d+))?(?:\s+LEN=(?P<L4_LEN>\d+))?\s*$' < /var/log/ufw.log
`
	fmt.Fprint(os.Stderr, msg)
}

func main() {
	if err := run(); err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		os.Exit(1)
	}
}

func run() error {
	pattern := flag.String("regexp", "", "regular expression with named capture groups, e.g. '(?P<ts>...) (?P<level>...)'")
	flag.Usage = usage
	flag.Parse()
	if strings.TrimSpace(*pattern) == "" {
		usage()
		return fmt.Errorf("flag -regexp is required")
	}
	re, err := regexp.Compile(*pattern)
	if err != nil {
		return fmt.Errorf("%w: %v", ErrInvalidRegexp, err)
	}
	groupNames := extractGroupNames(re)
	if len(groupNames) == 0 {
		return ErrNoNamedCaptureGroups
	}
	out := bufio.NewWriter(os.Stdout)
	err = processInput(os.Stdin, re, groupNames, out)
	if flushErr := out.Flush(); err == nil && flushErr != nil {
		err = flushErr
	}
	return err
}

func extractGroupNames(re *regexp.Regexp) []string {
	names := re.SubexpNames()[1:]
	ordered := make([]string, 0, len(names))
	for _, name := range names {
		if name != "" {
			ordered = append(ordered, name)
		}
	}
	return ordered
}

func processInput(input io.Reader, re *regexp.Regexp, groupNames []string, output io.Writer) error {
	inputReader, lineEnding, err := peekForLineEnding(input, logLineSizeMax)
	if err != nil {
		return err
	}
	sc := openInput(inputReader)
	firstLine := true
	for sc.Scan() {
		line := sc.Text()
		values, ok := processLine(line, re, groupNames)
		if !ok {
			continue
		}
		if firstLine {
			firstLine = false
			if err := writeCSVRow(output, groupNames, lineEnding); err != nil {
				return err
			}
		}
		if err := writeCSVRow(output, values, lineEnding); err != nil {
			return err
		}
	}
	return sc.Err()
}

func peekForLineEnding(input io.Reader, sizeMaxPeek int) (io.Reader, string, error) {
	inputBuffer := bufio.NewReader(input)
	sample, err := inputBuffer.Peek(sizeMaxPeek)
	if err != nil && err != io.EOF && !errors.Is(err, bufio.ErrBufferFull) {
		return nil, "", err
	}
	if idx := bytes.IndexByte(sample, '\n'); idx >= 0 {
		if idx > 0 && sample[idx-1] == '\r' {
			return inputBuffer, "\r\n", nil
		}
		return inputBuffer, "\n", nil
	}
	return inputBuffer, "\n", nil
}

func openInput(input io.Reader) *bufio.Scanner {
	inputScanner := bufio.NewScanner(input)
	buf := make([]byte, 0, logLineSizeMax)
	inputScanner.Buffer(buf, bufferSizeMax)
	return inputScanner
}

// Process a log line and returns CSV values + true if the line is valid, or nil + false if the line should be ignored.
func processLine(line string, re *regexp.Regexp, groupNames []string) ([]string, bool) {
	submatches := re.FindStringSubmatch(line)
	if submatches == nil {
		return nil, false
	}
	subNames := re.SubexpNames()
	values := make([]string, 0, len(groupNames))
	allEmpty := true
	for idxSubmatch := 1; idxSubmatch < len(submatches); idxSubmatch++ {
		name := subNames[idxSubmatch]
		if name == "" {
			continue
		}
		val := submatches[idxSubmatch]
		if val != "" {
			allEmpty = false
		}
		values = append(values, val)
	}
	if allEmpty {
		return nil, false
	}
	return values, true
}

func writeCSVRow(output io.Writer, values []string, lineEnding string) error {
	csvWriter := csv.NewWriter(output)
	csvWriter.Comma = csvSeparator
	csvWriter.UseCRLF = lineEnding == "\r\n"
	if err := csvWriter.Write(values); err != nil {
		return err
	}
	csvWriter.Flush()
	return csvWriter.Error()
}
