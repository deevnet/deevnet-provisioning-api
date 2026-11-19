// tenant2backend is the Deevnet API's stand-in on a Raspberry Pi.
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
//   - The CA is the card's own, generated on first boot, until a Deevnet
//     certificate is installed (cert install, ADR-0041 §2). A Deevnet Pi's
//     certificate is the Tenant Service CA's, for the tenant's site-less
//     names, and it trusts the Deevnet Root. An owner leaving Deevnet makes
//     a PKI of their own with pki init, and moves to it with pki switch
//     (ADR-0041 §3, §4).
//   - Grafana's organisation is written by the same package the API uses
//     (internal/backend/grafana), so its data sources have the same UIDs and a
//     dashboard moves unchanged. The Pi's owner also holds the admin login.
//   - Metrics are Deevnet's store, behind the same vmauth, with the same
//     routes rendered by deevnet-log-user (CHG-0070, CHG-0072).
//   - A virtual machine's first boot asks on the console (setup) for what a
//     Pi's owner writes on the card, and writes it where init reads it
//     (CHG-0074). From init on, a VM is a Pi.
//   - Alert rules come from the tenant's own Terraform, exported as JSON, and
//     are sent to deevnet-log-user exactly as the API sends them, so they are
//     checked and rendered the same way (CHG-0071, CHG-0072). The phone reads
//     them on the Pi's own network.
package main

import (
	"fmt"
	"os"
	"path/filepath"
)

const usage = `tenant2backend - your tenant's backend on a machine of your own, keeping the Deevnet tenant contract

  tenant2backend setup [--config FILE]    a virtual machine's first boot, on the console: tenant,
                                          host name and your login, written where init reads them
  tenant2backend init [--config FILE]     first boot: tenant, CA, tokens, service config
  tenant2backend status                   services, endpoints and accounts
  tenant2backend env [--app NAME --password-file FILE]
                                          print the app's environment (kit.env)
  tenant2backend export DIR [--app NAME --password-file FILE]
                                          write kit.env and backend-ca.pem into DIR; with
                                          --app, kit.env carries that account's login
  tenant2backend account add NAME [--device DEV] [--publish P]... [--subscribe S]...
                                          [--password-file FILE | --password PW]
  tenant2backend account list
  tenant2backend account rm NAME
  tenant2backend names [list | set N... | add N... | rm N...]
                                          extra names and addresses for the server certificate
  tenant2backend regen-certs              reissue the server certificate for this hostname and
                                          those names, from the card's own CA, or your own once
                                          pki switch has run
  tenant2backend cert request             a Deevnet Pi: a new key, and its signing request for the
                                          Tenant Service CA
  tenant2backend cert install FULLCHAIN ROOT
                                          install what the Tenant Service CA signed; from then on
                                          everything here trusts the Deevnet Root. Also takes a
                                          renewal for the key already serving
  tenant2backend pki init --org ORG [--domain D]...
                                          a PKI of your own: a root on an encrypted USB stick, and
                                          an issuing CA on this Pi. Nothing served changes yet;
                                          export hands out both roots for your devices
  tenant2backend pki switch               once they hold both: this Pi serves a certificate from
                                          your CA, and trusts your root
  tenant2backend pki enroll DEVICE --out DIR [--csr FILE]
                                          a device's certificate from your CA
  tenant2backend pki issuing [--org ORG] [--domain D]...
                                          a new issuing CA from the root on the stick: a new card
  tenant2backend render                   rewrite the broker and log store config from state
  tenant2backend dashboards               ensure the tenant's Grafana organisation (each boot)
  tenant2backend alerts import FILE|-     load alert rule groups exported from your Terraform:
                                          terraform output -json alert_rules > rules.json
  tenant2backend alerts list              the groups loaded, and the ntfy topic of each
  tenant2backend alerts clear             remove every group; the phone's login stays
  tenant2backend alerts sync              write the groups again (each boot)
  tenant2backend notify                   what the phone's ntfy app needs: server, login, topics
  tenant2backend bucket add NAME --quota-gb N [--versioning] [--expire-days N]
                       [--noncurrent-expire-days N] [--public-read] [--key-file FILE]
                                          a bucket <tenant>-NAME, and its default write key;
                                          --key-file keeps a key from your Terraform
  tenant2backend bucket list
  tenant2backend bucket rm NAME [--force]
  tenant2backend bucket key add BUCKET KEY --access read|write [--key-file FILE]
  tenant2backend bucket key list BUCKET
  tenant2backend bucket key rm BUCKET KEY
                                          env and export take --bucket NAME[:KEY] for an app's key
  tenant2backend selftest                 prove the card end to end: TLS, a device log over
                                          MQTT, an app log, and both read back through Grafana

Patterns are RELATIVE to the tenant, as they are on Deevnet: "sensors/+/telemetry"
becomes "<tenant>/sensors/+/telemetry". --password-file (first line; - for
stdin) keeps an existing password, so a device or app moved from Deevnet needs
only the new broker host and CA. --password does the same, but leaves the
password in your shell history.
`

// legacyName is the tool's name before the rename (ADR-0045). The image keeps
// it as a link for one release; called by it, the tool says its new name.
const legacyName = "deevnet-kit"

func main() {
	if filepath.Base(os.Args[0]) == legacyName {
		fmt.Fprintln(os.Stderr, "note: deevnet-kit is now called tenant2backend; this name goes in the next release")
	}
	if err := run(os.Args[1:]); err != nil {
		fmt.Fprintln(os.Stderr, "tenant2backend:", err)
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
	case "setup":
		return k.cmdSetup(os.Stdin, os.Stdout, args[1:])
	case "init":
		return k.cmdInit(args[1:])
	case "status":
		return k.cmdStatus()
	case "env":
		return k.cmdEnv(os.Stdout, args[1:])
	case "export":
		return k.cmdExport(args[1:])
	case "account":
		return k.cmdAccount(args[1:])
	case "names":
		return k.cmdNames(args[1:])
	case "cert":
		return k.cmdCert(os.Stdout, args[1:])
	case "pki":
		return k.cmdPKI(os.Stdout, args[1:])
	case "regen-certs":
		return k.cmdRegenCerts()
	case "render":
		return k.renderAll(true)
	case "dashboards":
		return k.cmdDashboards()
	case "alerts":
		return k.cmdAlerts(os.Stdout, args[1:])
	case "notify":
		return k.cmdNotify(os.Stdout)
	case "bucket":
		return k.cmdBucket(os.Stdout, args[1:])
	case "selftest":
		return k.cmdSelftest()
	case "help", "-h", "--help":
		fmt.Print(usage)
		return nil
	default:
		return fmt.Errorf("unknown command %q; run tenant2backend help", args[0])
	}
}
