package opnsense

import (
	"context"
	"fmt"
	"net/netip"
	"strings"

	"github.com/deevnet/deevnet-provisioning-api/internal/tenant"
)

// Tenants' device address reservations on the router's Kea DHCP server
// (ADR-0035).
//
// The endpoints and payload are the ones the deevnet.net opnsense_dhcp role
// already drives for inventory's hosts: kea/dhcpv4/{search,add,set,del}_reservation,
// a reservation wrapped in a "reservation" object and tied to its subnet by the
// subnet's uuid, and kea/service/reconfigure to apply.
//
// Two writers share that table, and the description is what keeps them apart.
// The role's rows start "Ansible managed" and its prune matches only those; the
// API's start "Deevnet API - ". This client finds its own row by its exact
// description, and refuses to reserve a MAC or an address that any other row on
// the subnet already holds, whoever wrote it.

type reservationRow struct {
	UUID        string `json:"uuid"`
	HWAddress   string `json:"hw_address"`
	IPAddress   string `json:"ip_address"`
	Hostname    string `json:"hostname"`
	Description string `json:"description"`
}

type reservationWrapper struct {
	Reservation reservationBody `json:"reservation"`
}

type reservationBody struct {
	Subnet      string `json:"subnet"`
	HWAddress   string `json:"hw_address"`
	IPAddress   string `json:"ip_address"`
	Hostname    string `json:"hostname"`
	Description string `json:"description"`
}

// reservations returns every reservation on the server, all subnets.
func (c *Client) reservations(ctx context.Context) ([]reservationRow, error) {
	var resp struct {
		Rows *[]reservationRow `json:"rows"`
	}
	if err := c.post(ctx, "/kea/dhcpv4/search_reservation", map[string]int{"current": 1, "rowCount": 10000}, &resp); err != nil {
		return nil, err
	}
	// A build without this endpoint would see no conflicts and report success.
	if resp.Rows == nil {
		return nil, fmt.Errorf("search_reservation returned no rows collection")
	}
	return *resp.Rows, nil
}

// subnetUUID resolves a CIDR to the uuid Kea's subnet object carries. The
// subnet is inventory's to create (ADR-0009); one that is not there is an error
// here, never something to make.
func (c *Client) subnetUUID(ctx context.Context, cidr string) (string, error) {
	var resp struct {
		Rows *[]struct {
			UUID   string `json:"uuid"`
			Subnet string `json:"subnet"`
		} `json:"rows"`
	}
	if err := c.post(ctx, "/kea/dhcpv4/search_subnet", map[string]int{"current": 1, "rowCount": 1000}, &resp); err != nil {
		return "", err
	}
	if resp.Rows == nil {
		return "", fmt.Errorf("search_subnet returned no rows collection")
	}
	for _, r := range *resp.Rows {
		if r.Subnet == cidr {
			return r.UUID, nil
		}
	}
	return "", fmt.Errorf("the DHCP server has no subnet %s", cidr)
}

// EnsureReservation makes the reservation with r's description match r.
func (c *Client) EnsureReservation(ctx context.Context, r tenant.Reservation) error {
	subnet, err := netip.ParsePrefix(r.Subnet)
	if err != nil {
		return fmt.Errorf("subnet %q: %w", r.Subnet, err)
	}
	rows, err := c.reservations(ctx)
	if err != nil {
		return err
	}
	var own *reservationRow
	for i, row := range rows {
		if row.Description == r.Description {
			own = &rows[i]
			continue
		}
		// Another row's address places it on a subnet; one on some other subnet
		// may carry the same MAC, which is a host with two interfaces.
		addr, err := netip.ParseAddr(row.IPAddress)
		if err != nil || !subnet.Contains(addr) {
			continue
		}
		if row.IPAddress == r.Address {
			return fmt.Errorf("%s is reserved by %q: %w", r.Address, row.Description, tenant.ErrAddressConflict)
		}
		if strings.EqualFold(row.HWAddress, r.MAC) {
			return fmt.Errorf("%s holds %s by %q: %w", r.MAC, row.IPAddress, row.Description, tenant.ErrAddressConflict)
		}
	}
	if own != nil && strings.EqualFold(own.HWAddress, r.MAC) && own.IPAddress == r.Address && own.Hostname == r.Hostname {
		return nil
	}

	uuid, err := c.subnetUUID(ctx, r.Subnet)
	if err != nil {
		return err
	}
	body := reservationWrapper{Reservation: reservationBody{
		Subnet: uuid, HWAddress: r.MAC, IPAddress: r.Address, Hostname: r.Hostname, Description: r.Description,
	}}
	if own == nil {
		if err := c.write(ctx, "/kea/dhcpv4/add_reservation", body, "saved"); err != nil {
			return fmt.Errorf("add reservation %s: %w", r.Address, err)
		}
	} else if err := c.write(ctx, "/kea/dhcpv4/set_reservation/"+own.UUID, body, "saved"); err != nil {
		return fmt.Errorf("set reservation %s: %w", r.Address, err)
	}
	return c.reconfigure(ctx, "kea")
}

// RemoveReservation deletes the reservation with this description.
func (c *Client) RemoveReservation(ctx context.Context, description string) error {
	rows, err := c.reservations(ctx)
	if err != nil {
		return err
	}
	changed := false
	for _, row := range rows {
		if row.Description != description {
			continue
		}
		var res result
		if err := c.post(ctx, "/kea/dhcpv4/del_reservation/"+row.UUID, map[string]string{}, &res); err != nil {
			return fmt.Errorf("delete reservation %s: %w", row.IPAddress, err)
		}
		if res.Result != "deleted" && res.Result != "not found" {
			return fmt.Errorf("delete reservation %s: result %q", row.IPAddress, res.Result)
		}
		changed = true
	}
	if changed {
		return c.reconfigure(ctx, "kea")
	}
	return nil
}
