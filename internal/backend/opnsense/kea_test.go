package opnsense

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"

	"github.com/deevnet/deevnet-provisioning-api/internal/tenant"
)

const iotSubnetUUID = "subnet-iot"

// serveKea answers the Kea endpoints the way the forwarding ones are answered:
// the result strings are ApiMutableModelControllerBase's. The row and payload
// shapes are the ones the deevnet.net opnsense_dhcp role reads and writes.
func (f *fakeRouter) serveKea(w http.ResponseWriter, path string, body []byte) {
	reply := func(v any) { _ = json.NewEncoder(w).Encode(v) }
	switch {
	case path == "/kea/dhcpv4/search_subnet":
		reply(map[string]any{"rows": []map[string]string{
			{"uuid": "subnet-mgmt", "subnet": "10.20.99.0/24"},
			{"uuid": iotSubnetUUID, "subnet": "10.20.30.0/24"},
		}})
	case path == "/kea/dhcpv4/search_reservation":
		rows := []reservationRow{}
		for _, r := range f.reservations {
			rows = append(rows, r)
		}
		reply(map[string]any{"rows": rows, "rowCount": len(rows), "total": len(rows), "current": 1})
	case path == "/kea/dhcpv4/add_reservation" || strings.HasPrefix(path, "/kea/dhcpv4/set_reservation/"):
		var in reservationWrapper
		_ = json.Unmarshal(body, &in)
		r := in.Reservation
		// Kea ties a reservation to a subnet object, not to a CIDR.
		if r.Subnet != iotSubnetUUID || r.HWAddress == "" || r.IPAddress == "" {
			reply(map[string]any{"result": "failed", "validations": map[string]string{"reservation.subnet": "bad"}})
			return
		}
		uuid := strings.TrimPrefix(path, "/kea/dhcpv4/set_reservation/")
		if path == "/kea/dhcpv4/add_reservation" {
			f.next++
			uuid = fmt.Sprintf("res-%d", f.next)
		}
		f.reservations[uuid] = reservationRow{UUID: uuid, HWAddress: r.HWAddress, IPAddress: r.IPAddress, Hostname: r.Hostname, Description: r.Description}
		reply(map[string]string{"result": "saved", "uuid": uuid})
	case strings.HasPrefix(path, "/kea/dhcpv4/del_reservation/"):
		uuid := strings.TrimPrefix(path, "/kea/dhcpv4/del_reservation/")
		if _, ok := f.reservations[uuid]; !ok {
			reply(map[string]string{"result": "not found"})
			return
		}
		delete(f.reservations, uuid)
		reply(map[string]string{"result": "deleted"})
	case path == "/kea/service/reconfigure":
		f.keaReconfigures++
		reply(map[string]string{"status": "ok"})
	default:
		w.WriteHeader(http.StatusNotFound)
	}
}

func standReservation() tenant.Reservation {
	return tenant.Reservation{
		Subnet: "10.20.30.0/24", Address: "10.20.30.25", MAC: "aa:bb:cc:00:00:01",
		Hostname: "eds-stand-1", Description: "Deevnet API - eds/stand-1",
	}
}

func keaClient(t *testing.T) (*Client, *fakeRouter) {
	t.Helper()
	f := newFakeRouter()
	srv := httptest.NewServer(f)
	t.Cleanup(srv.Close)
	return New(srv.URL+"/api", "key", "secret", false), f
}

func TestReservationIsAddedOnceAndAppliedOnlyOnChange(t *testing.T) {
	c, f := keaClient(t)
	ctx := context.Background()

	if err := c.EnsureReservation(ctx, standReservation()); err != nil {
		t.Fatalf("ensure: %v", err)
	}
	if len(f.reservations) != 1 || f.keaReconfigures != 1 {
		t.Fatalf("rows %d reconfigures %d, want 1 and 1", len(f.reservations), f.keaReconfigures)
	}
	if f.reconfigures != 0 {
		t.Errorf("the resolver was reconfigured for a DHCP change")
	}
	// A second ensure of the same thing writes nothing and applies nothing:
	// every device apply would otherwise restart DHCP for the whole site.
	if err := c.EnsureReservation(ctx, standReservation()); err != nil {
		t.Fatal(err)
	}
	if len(f.reservations) != 1 || f.keaReconfigures != 1 {
		t.Errorf("rows %d reconfigures %d after an unchanged ensure", len(f.reservations), f.keaReconfigures)
	}
}

// The hardware behind a name was swapped: the same row takes the new MAC.
func TestAChangedMACUpdatesTheSameRow(t *testing.T) {
	c, f := keaClient(t)
	ctx := context.Background()
	if err := c.EnsureReservation(ctx, standReservation()); err != nil {
		t.Fatal(err)
	}
	r := standReservation()
	r.MAC = "aa:bb:cc:00:00:02"
	if err := c.EnsureReservation(ctx, r); err != nil {
		t.Fatal(err)
	}
	if len(f.reservations) != 1 || f.keaReconfigures != 2 {
		t.Fatalf("rows %d reconfigures %d, want the one row rewritten", len(f.reservations), f.keaReconfigures)
	}
	for _, row := range f.reservations {
		if row.HWAddress != "aa:bb:cc:00:00:02" || row.IPAddress != "10.20.30.25" {
			t.Errorf("row = %+v", row)
		}
	}
}

// Inventory's hosts are in the same table. Their MACs and addresses are not
// the API's to take, and their rows are never rewritten.
func TestAnotherOwnersMACOrAddressIsAConflict(t *testing.T) {
	pi := reservationRow{UUID: "pi", HWAddress: "DC:A6:32:00:00:01", IPAddress: "10.20.30.11",
		Hostname: "dv02rpi001p01", Description: "Ansible managed - dv02rpi001p01 (eth0)"}

	t.Run("its MAC, whatever the case", func(t *testing.T) {
		c, f := keaClient(t)
		f.reservations["pi"] = pi
		r := standReservation()
		r.MAC = "dc:a6:32:00:00:01"
		err := c.EnsureReservation(context.Background(), r)
		if !errors.Is(err, tenant.ErrAddressConflict) {
			t.Fatalf("err = %v, want ErrAddressConflict", err)
		}
		if len(f.reservations) != 1 || f.reservations["pi"] != pi || f.keaReconfigures != 0 {
			t.Errorf("inventory's row was touched: %v", f.reservations)
		}
	})
	t.Run("its address", func(t *testing.T) {
		c, f := keaClient(t)
		f.reservations["pi"] = pi
		r := standReservation()
		r.Address = "10.20.30.11"
		if err := c.EnsureReservation(context.Background(), r); !errors.Is(err, tenant.ErrAddressConflict) {
			t.Fatalf("err = %v, want ErrAddressConflict", err)
		}
	})
	// A host with an interface on another network may carry the same MAC there.
	t.Run("the same MAC on another subnet is not one", func(t *testing.T) {
		c, f := keaClient(t)
		f.reservations["mgmt"] = reservationRow{UUID: "mgmt", HWAddress: "aa:bb:cc:00:00:01", IPAddress: "10.20.99.40",
			Description: "Ansible managed - elsewhere (eth0)"}
		if err := c.EnsureReservation(context.Background(), standReservation()); err != nil {
			t.Fatalf("err = %v", err)
		}
	})
}

func TestRemoveDeletesOnlyItsOwnRow(t *testing.T) {
	c, f := keaClient(t)
	ctx := context.Background()
	f.reservations["pi"] = reservationRow{UUID: "pi", HWAddress: "dc:a6:32:00:00:01", IPAddress: "10.20.30.11",
		Description: "Ansible managed - dv02rpi001p01 (eth0)"}
	if err := c.EnsureReservation(ctx, standReservation()); err != nil {
		t.Fatal(err)
	}
	if err := c.RemoveReservation(ctx, "Deevnet API - eds/stand-1"); err != nil {
		t.Fatal(err)
	}
	if _, ok := f.reservations["pi"]; !ok || len(f.reservations) != 1 {
		t.Fatalf("rows = %v, want only inventory's left", f.reservations)
	}
	// Removing one that is not there is not an error, and applies nothing.
	before := f.keaReconfigures
	if err := c.RemoveReservation(ctx, "Deevnet API - eds/stand-1"); err != nil || f.keaReconfigures != before {
		t.Errorf("removing an absent row: %v, reconfigures %d -> %d", err, before, f.keaReconfigures)
	}
}

// OPNsense answers 200 with "result":"failed". A subnet the server does not
// have is caught before that, and neither applies anything.
func TestARejectedReservationIsAnError(t *testing.T) {
	c, f := keaClient(t)
	ctx := context.Background()
	r := standReservation()
	r.MAC = ""
	if err := c.EnsureReservation(ctx, r); err == nil || f.keaReconfigures != 0 {
		t.Fatalf("err = %v reconfigures %d, want a failure and no reconfigure", err, f.keaReconfigures)
	}
	r = standReservation()
	r.Subnet, r.Address = "10.20.31.0/24", "10.20.31.25"
	if err := c.EnsureReservation(ctx, r); err == nil || len(f.reservations) != 0 {
		t.Fatalf("err = %v rows %d, want a failure for a subnet the server lacks", err, len(f.reservations))
	}
}

// Read-only against a real router, with the same variables as
// TestListAgainstARealRouter. It lists subnets and reservations; it never
// writes. This is what confirms the row shapes above against the live build.
func TestKeaReadsAgainstARealRouter(t *testing.T) {
	u := os.Getenv("DEEVNET_TEST_OPNSENSE_URL")
	if u == "" {
		t.Skip("DEEVNET_TEST_OPNSENSE_URL not set")
	}
	c := New(u, os.Getenv("DEEVNET_TEST_OPNSENSE_KEY"), os.Getenv("DEEVNET_TEST_OPNSENSE_SECRET"),
		os.Getenv("DEEVNET_TEST_OPNSENSE_INSECURE") == "true")
	ctx := context.Background()
	rows, err := c.reservations(ctx)
	if err != nil {
		t.Fatalf("reservations: %v", err)
	}
	for _, r := range rows {
		if r.UUID == "" || r.HWAddress == "" || r.IPAddress == "" {
			t.Errorf("a row is missing a field this client reads: %+v", r)
		}
		t.Logf("%s %s %s (%s)", r.IPAddress, r.HWAddress, r.Hostname, r.Description)
	}
	if cidr := os.Getenv("DEEVNET_TEST_OPNSENSE_SUBNET"); cidr != "" {
		uuid, err := c.subnetUUID(ctx, cidr)
		if err != nil {
			t.Fatalf("subnet %s: %v", cidr, err)
		}
		t.Logf("%s -> %s", cidr, uuid)
	}
}
