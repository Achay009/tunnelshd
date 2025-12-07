package main

import (
	"flag"
	"fmt"
	"os"
)

const usage1 string = `Usage: %s [OPTIONS] <local port or address>
Options:
`

const usage2 string = `
Examples:
	tunnelshd 80
	tunnelshd -subdomain=example 8080
	tunnelshd -subdomain=example -authtoken=WMDNIAHDUWYBJbUB3 8080


Advanced usage: tunnelshd [OPTIONS] <command> [command args] [...]
Commands:
	tunnelshd help                    Print help
	tunnelshd version                 Print tunnelshd version

Examples:
	tunnelshd version

`

type Options struct {
	// authtoken string
	subdomain string
	command   string
}

func ParseArgs() (opts *Options, err error) {
	flag.Usage = func() {
		fmt.Fprintf(os.Stderr, usage1, os.Args[0])
		flag.PrintDefaults()
		fmt.Fprintf(os.Stderr, usage2)
	}

	// authtoken := flag.String(
	// 	"authtoken",
	// 	"",
	// 	"Authentication token for identifying a tunnelsh account")

	subdomain := flag.String(
		"subdomain",
		"",
		"Request a custom subdomain from the tunnelsh server.")

	flag.Parse()

	opts = &Options{
		subdomain: *subdomain,
		// authtoken: *authtoken,
		command: flag.Arg(0),
	}

	switch opts.command {
	case "version":
		fmt.Println("tunnelshd")
		fmt.Println(Full())
		os.Exit(0)
	case "help":
		flag.Usage()
		os.Exit(0)
	case "":
		err = fmt.Errorf("Error: Specify a local port to tunnel to, or " +
			"an tunnelsh command.\n\nExample: To expose port 80, run " +
			"'tunnelsh 80'")
		return

	default:
		if len(flag.Args()) > 1 {
			err = fmt.Errorf("You may only specify one port to tunnel to on the command line, got %d: %v",
				len(flag.Args()),
				flag.Args())
			return
		}

		// opts.command = "default"
		// opts.args = flag.Args()
	}

	return opts, nil
}
