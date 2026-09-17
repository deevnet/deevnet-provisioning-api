package proxmox

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strconv"
	"strings"

	"github.com/deevnet/deevnet-provisioning-api/internal/tenant"
)

// The tenant network (ADR-0015 §11): the EVPN zone, its VNets and the subnet
// that modules/tenant used to build. Field names are Proxmox's own:
// vrf-vxlan, exitnodes, exitnodes-primary.

// Ensure builds or corrects a tenant's network and applies SDN.
func (c *Client) Ensure(ctx context.Context, n tenant.NetworkSpec) error {
	changed := false

	var zone struct {
		Zone       string  `json:"zone"`
		Controller string  `json:"controller"`
		VRFVXLAN   flexInt `json:"vrf-vxlan"`
		Nodes      string  `json:"nodes"`
		ExitNodes  string  `json:"exitnodes"`
	}
	err := c.get(ctx, "/cluster/sdn/zones/"+url.PathEscape(n.Zone), &zone)
	switch {
	case errors.Is(err, errNotFound):
		if err := c.post(ctx, "/cluster/sdn/zones", map[string]string{
			"zone":              n.Zone,
			"type":              "evpn",
			"controller":        n.Controller,
			"vrf-vxlan":         strconv.Itoa(n.VRFVNI),
			"nodes":             n.Node,
			"exitnodes":         n.Node,
			"exitnodes-primary": n.Node,
		}); err != nil {
			return fmt.Errorf("create zone %s: %w", n.Zone, err)
		}
		changed = true
	case err != nil:
		return fmt.Errorf("read zone %s: %w", n.Zone, err)
	default:
		// An existing zone on another VNI is another tenant's, or this tenant's
		// numbering moved. Either way the API does not quietly rewrite it.
		if int(zone.VRFVXLAN) != n.VRFVNI {
			return fmt.Errorf("zone %s carries VRF VNI %d, expected %d", n.Zone, zone.VRFVXLAN, n.VRFVNI)
		}
	}

	for _, v := range n.VNets {
		var have struct {
			VNet string  `json:"vnet"`
			Zone string  `json:"zone"`
			Tag  flexInt `json:"tag"`
		}
		err := c.get(ctx, "/cluster/sdn/vnets/"+url.PathEscape(v.ID), &have)
		switch {
		case errors.Is(err, errNotFound):
			if err := c.post(ctx, "/cluster/sdn/vnets", map[string]string{
				"vnet": v.ID,
				"zone": n.Zone,
				"tag":  strconv.Itoa(v.Tag),
			}); err != nil {
				return fmt.Errorf("create vnet %s: %w", v.ID, err)
			}
			changed = true
		case err != nil:
			return fmt.Errorf("read vnet %s: %w", v.ID, err)
		default:
			if have.Zone != n.Zone || int(have.Tag) != v.Tag {
				return fmt.Errorf("vnet %s belongs to zone %q with tag %d, expected %q and %d", v.ID, have.Zone, have.Tag, n.Zone, v.Tag)
			}
		}
	}

	if n.Subnet != "" && len(n.VNets) > 0 {
		vnet := n.VNets[0].ID
		var subnets []struct {
			Subnet string `json:"subnet"`
			CIDR   string `json:"cidr"`
		}
		if err := c.get(ctx, "/cluster/sdn/vnets/"+url.PathEscape(vnet)+"/subnets", &subnets); err != nil && !errors.Is(err, errNotFound) {
			return fmt.Errorf("read subnets of %s: %w", vnet, err)
		}
		found := false
		for _, s := range subnets {
			// Proxmox returns the subnet id as <zone>-<cidr with - for / and .>,
			// and cidr as the CIDR itself, depending on version; match either.
			if s.CIDR == n.Subnet || strings.HasSuffix(s.Subnet, strings.NewReplacer("/", "-", ".", "-").Replace(n.Subnet)) {
				found = true
			}
		}
		if !found {
			// SNAT is what keeps the perimeter from learning tenant subnets
			// (ADR-0001, ADR-0003).
			if err := c.post(ctx, "/cluster/sdn/vnets/"+url.PathEscape(vnet)+"/subnets", map[string]string{
				"type":    "subnet",
				"subnet":  n.Subnet,
				"gateway": n.Gateway,
				"snat":    "1",
			}); err != nil {
				return fmt.Errorf("create subnet %s: %w", n.Subnet, err)
			}
			changed = true
		}
	}

	if changed {
		return c.Apply(ctx)
	}
	return nil
}

// Remove deletes the tenant's subnet, VNets and zone, then applies SDN.
func (c *Client) Remove(ctx context.Context, n tenant.NetworkSpec) error {
	changed := false
	for _, v := range n.VNets {
		var subnets []struct {
			Subnet string `json:"subnet"`
		}
		if err := c.get(ctx, "/cluster/sdn/vnets/"+url.PathEscape(v.ID)+"/subnets", &subnets); err == nil {
			for _, s := range subnets {
				if err := c.delete(ctx, "/cluster/sdn/vnets/"+url.PathEscape(v.ID)+"/subnets/"+url.PathEscape(s.Subnet)); err != nil && !errors.Is(err, errNotFound) {
					return fmt.Errorf("delete subnet %s: %w", s.Subnet, err)
				}
				changed = true
			}
		}
		if err := c.delete(ctx, "/cluster/sdn/vnets/"+url.PathEscape(v.ID)); err != nil && !errors.Is(err, errNotFound) {
			return fmt.Errorf("delete vnet %s: %w", v.ID, err)
		} else if err == nil {
			changed = true
		}
	}
	if err := c.delete(ctx, "/cluster/sdn/zones/"+url.PathEscape(n.Zone)); err != nil && !errors.Is(err, errNotFound) {
		return fmt.Errorf("delete zone %s: %w", n.Zone, err)
	} else if err == nil {
		changed = true
	}
	if changed {
		return c.Apply(ctx)
	}
	return nil
}

// Apply commits pending SDN configuration. It is cluster-wide, so the service
// serialises calls to it (ADR-0015 §11).
func (c *Client) Apply(ctx context.Context) error {
	var upid string
	if err := c.request(ctx, http.MethodPut, "/cluster/sdn", nil, &upid); err != nil {
		return fmt.Errorf("apply sdn: %w", err)
	}
	// The apply task runs on a node; without a node in the UPID there is
	// nothing to poll, and Proxmox has already taken the configuration.
	if node := upidNode(upid); node != "" {
		return c.waitTask(ctx, node, upid)
	}
	return nil
}

// upidNode picks the node out of UPID:<node>:....
func upidNode(upid string) string {
	parts := strings.Split(upid, ":")
	if len(parts) < 2 || parts[0] != "UPID" {
		return ""
	}
	return parts[1]
}
