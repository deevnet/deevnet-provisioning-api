// deevnet-kit is the Deevnet API's stand-in on a Raspberry Pi.
//
// A tenant prototypes on Deevnet, then moves its app to a Pi of its own (the
// image factory's pi-backend image). The Pi runs no API and no Terraform. It
// runs a broker and a log store that keep the same CONTRACT the app saw on
// Deevnet - the tenant's topic prefix, the reserved log level, the ingest and
// read tokens and the partition selector - and this program is how the Pi's
// owner manages them.
//
// It lives in this repository, not beside the image, so that it applies the
// API's own rules rather than a copy of them: topic patterns are prefixed and
// checked by internal/brokeracct, names by internal/tenant, and the log store's
// users are rendered by deevnet-log-user, the same program that renders them on
// Deevnet.
//
// What differs from Deevnet, stated rather than implied:
//
//   - The broker is Mosquitto, not VerneMQ. Accounts become a password file and
//     an ACL file; the rules that decide what goes in them are the API's.
//   - There is one tenant, and the Pi's owner is its operator. Nothing here
//     separates tenants from each other, because there is only one.
//   - There is no device registry. A device account names its device, and the
//     name is checked for shape only.
//   - The CA is the card's own, generated on first boot. Nothing Deevnet holds
//     can reach this Pi, and nothing on it was issued by Deevnet.
package main

import (
	"fmt"
	"os"
)

const usage = `deevnet-kit - the Deevnet tenant contract on a Pi of your own

  deevnet-kit init [--config FILE]     first boot: tenant, CA, tokens, service config
  deevnet-kit status                   services, endpoints and accounts
  deevnet-kit env                      print the app's environment (kit.env)
  deevnet-kit export DIR               write kit.env and site-ca.pem into DIR
  deevnet-kit account add NAME [--device DEV] [--publish P]... [--subscribe S]...
                                       [--password PW]
  deevnet-kit account list
  deevnet-kit account rm NAME
  deevnet-kit regen-certs              reissue the server certificate for this hostname
  deevnet-kit render                   rewrite the broker and log store config from state

Patterns are RELATIVE to the tenant, as they are on Deevnet: "sensors/+/telemetry"
becomes "<tenant>/sensors/+/telemetry". --password keeps a device's existing
password, so a device moved from Deevnet needs only the new broker host and CA.
`

func main() {
	if err := run(os.Args[1:]); err != nil {
		fmt.Fprintln(os.Stderr, "deevnet-kit:", err)
		os.Exit(1)
	}
}

func run(args []string) error {
	if len(args) == 0 {
		fmt.Print(usage)
		return nil
	}
	k := newKit("")
	switch args[0] {
	case "init":
		return k.cmdInit(args[1:])
	case "status":
		return k.cmdStatus()
	case "env":
		return k.cmdEnv(os.Stdout)
	case "export":
		if len(args) != 2 {
			return fmt.Errorf("export takes one directory")
		}
		return k.cmdExport(args[1])
	case "account":
		return k.cmdAccount(args[1:])
	case "regen-certs":
		return k.cmdRegenCerts()
	case "render":
		return k.renderAll(true)
	case "help", "-h", "--help":
		fmt.Print(usage)
		return nil
	default:
		return fmt.Errorf("unknown command %q; run deevnet-kit help", args[0])
	}
}
