package main

import (
	"flag"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/frontier-buildathon/cairn/internal/app"
	"github.com/frontier-buildathon/cairn/internal/demo"
	"github.com/frontier-buildathon/cairn/internal/report"
)

const version = "0.1.0"

func main() {
	if err := run(os.Args[1:]); err != nil {
		fmt.Fprintln(os.Stderr, "cairn:", err)
		os.Exit(1)
	}
}

func run(args []string) error {
	if len(args) == 0 {
		printUsage()
		return nil
	}
	switch args[0] {
	case "analyze":
		return runAnalyze(args[1:])
	case "demo":
		return runDemo(args[1:])
	case "version", "--version", "-version":
		fmt.Println("CAIRN", version)
		return nil
	case "help", "--help", "-h":
		printUsage()
		return nil
	default:
		return fmt.Errorf("unknown command %q (use 'cairn help' for usage)", args[0])
	}
}

func runAnalyze(args []string) error {
	flags := flag.NewFlagSet("analyze", flag.ContinueOnError)
	flags.SetOutput(os.Stderr)
	caseDir := flags.String("case-dir", "", "directory containing auth logs and Compose files")
	output := flags.String("output", "report.html", "offline HTML report path")
	year := flags.Int("year", 0, "year to apply to syslog timestamps without a year")
	timezone := flags.String("timezone", "UTC", "IANA timezone for timestamps without an offset")
	if err := flags.Parse(args); err != nil {
		return err
	}
	if strings.TrimSpace(*caseDir) == "" {
		return fmt.Errorf("--case-dir is required")
	}
	location, err := time.LoadLocation(*timezone)
	if err != nil {
		return fmt.Errorf("load timezone %q: %w", *timezone, err)
	}
	if err := app.ValidateReportOutput(*caseDir, *output); err != nil {
		return err
	}
	data, err := app.AnalyzeCase(app.Options{CaseDir: *caseDir, Year: *year, Timezone: location})
	if err != nil {
		return err
	}
	if err := report.WriteHTML(*output, data); err != nil {
		return err
	}
	fmt.Printf("wrote %s (%d events, %d authentication findings, %d Compose findings)\n",
		*output, data.Summary.Events, data.Summary.AuthenticationFindings, data.Summary.ComposeFindings)
	return nil
}

func runDemo(args []string) error {
	flags := flag.NewFlagSet("demo", flag.ContinueOnError)
	flags.SetOutput(os.Stderr)
	destination := flags.String("out", "demo-case", "directory to receive the deterministic synthetic case")
	force := flags.Bool("force", false, "write the demo files into a non-empty directory")
	if err := flags.Parse(args); err != nil {
		return err
	}
	if err := demo.Generate(*destination, *force); err != nil {
		return err
	}
	fmt.Printf("wrote deterministic demo case to %s\n", *destination)
	return nil
}

func printUsage() {
	fmt.Print(`CAIRN - offline Linux authentication and Docker Compose triage

Usage:
  cairn demo [--out DIR] [--force]
  cairn analyze --case-dir DIR [--output report.html] [--year YEAR] [--timezone ZONE]
  cairn version

The analyzer reads only local case files and writes a self-contained HTML
report. It does not monitor systems, scan networks, or call external services.
`)
}
