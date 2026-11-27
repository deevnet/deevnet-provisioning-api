package proxmox

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/deevnet/deevnet-provisioning-api/internal/tenant"
)

// Workloads (ADR-0015 §12): a VM cloned from the site template into the
// tenant's VNet, addressed by cloud-init from its index.

type vmEntry struct {
	VMID     flexInt `json:"vmid"`
	Name     string  `json:"name"`
	Template flexInt `json:"template"`
	Status   string  `json:"status"`
}

// EnsureWorkload creates the VM when it is absent, and adopts it when a VM
// with that id already carries the tenant's name.
func (c *Client) EnsureWorkload(ctx context.Context, w tenant.WorkloadSpec) error {
	vms, err := c.listVMs(ctx, w.Node)
	if err != nil {
		return err
	}
	for _, vm := range vms {
		if int(vm.VMID) != w.VMID {
			continue
		}
		if vm.Name != w.Name {
			return fmt.Errorf("VMID %d on %s is %q, not %q", w.VMID, w.Node, vm.Name, w.Name)
		}
		// Adopted: configuration is re-applied, which is what makes a restore
		// after a lost registry converge.
		return c.configureWorkload(ctx, w, vm.Status != "running")
	}

	tmpl, err := newestTemplate(vms, w.TemplatePrefix)
	if err != nil {
		return err
	}
	clone := map[string]string{
		"newid": strconv.Itoa(w.VMID),
		"name":  w.Name,
		"full":  "1",
	}
	if w.Storage != "" {
		clone["storage"] = w.Storage
	}
	if err := c.postTask(ctx, w.Node, fmt.Sprintf("/nodes/%s/qemu/%d/clone", url.PathEscape(w.Node), tmpl), clone); err != nil {
		return fmt.Errorf("clone %d into %d: %w", tmpl, w.VMID, err)
	}
	if err := c.profileWorkload(ctx, w); err != nil {
		return err
	}
	return c.configureWorkload(ctx, w, true)
}

// profileWorkload puts a VM just cloned on the site's VM hardware profile
// (ADR-0046) before its first start: the disk controller, and the options of
// the disk the workload boots from. A clone inherits the template's, and a
// template built before the profile is on LSI (INC-0006).
//
// Only a new clone: an adopted VM's hardware is never changed here. A running
// VM would hold the change pending until some later restart, which no one
// chose; moving an existing workload is a change record.
func (c *Client) profileWorkload(ctx context.Context, w tenant.WorkloadSpec) error {
	var cfg map[string]any
	path := fmt.Sprintf("/nodes/%s/qemu/%d/config", url.PathEscape(w.Node), w.VMID)
	if err := c.get(ctx, path, &cfg); err != nil {
		return fmt.Errorf("read %d's configuration: %w", w.VMID, err)
	}
	drive, _ := cfg[w.Disk].(string)
	if drive == "" {
		return fmt.Errorf("profile %d: the clone has no %s", w.VMID, w.Disk)
	}
	if err := c.post(ctx, path, map[string]string{
		"scsihw": w.SCSIHW,
		w.Disk:   profileDrive(drive, w.DiskOptions),
	}); err != nil {
		return fmt.Errorf("profile %d: %w", w.VMID, err)
	}
	// Read back before the first start: a write the node accepted but did not
	// apply would otherwise leave a workload running off the profile.
	cfg = nil
	if err := c.get(ctx, path, &cfg); err != nil {
		return fmt.Errorf("read back %d's configuration: %w", w.VMID, err)
	}
	if diffs := offProfile(cfg, w); len(diffs) > 0 {
		return fmt.Errorf("profile %d: not on the profile after it was set: %s", w.VMID, strings.Join(diffs, "; "))
	}
	return nil
}

// offProfile names each way a workload's configuration differs from the
// profile it was given: its controller, and each of the profile's options on
// the disk it boots from. Nothing, when it is on the profile.
func offProfile(cfg map[string]any, w tenant.WorkloadSpec) []string {
	var diffs []string
	if got, _ := cfg["scsihw"].(string); got != w.SCSIHW {
		diffs = append(diffs, fmt.Sprintf("scsihw is %q, profile %q", got, w.SCSIHW))
	}
	drive, _ := cfg[w.Disk].(string)
	have := map[string]string{}
	for _, p := range strings.Split(drive, ",")[1:] {
		k, v, _ := strings.Cut(p, "=")
		have[k] = v
	}
	for _, o := range strings.Split(w.DiskOptions, ",") {
		k, v, _ := strings.Cut(o, "=")
		if have[k] != v {
			diffs = append(diffs, fmt.Sprintf("%s %s is %q, profile %q", w.Disk, k, have[k], v))
		}
	}
	return diffs
}

// profileDrive keeps a drive's volume and every option the profile does not
// set (its size among them), and gives it the profile's options:
// "local-lvm:vm-2040-disk-0,size=32G" with "iothread=1,discard=on" becomes
// "local-lvm:vm-2040-disk-0,size=32G,iothread=1,discard=on".
func profileDrive(drive, options string) string {
	parts := strings.Split(drive, ",")
	set := map[string]bool{}
	for _, o := range strings.Split(options, ",") {
		k, _, _ := strings.Cut(o, "=")
		set[k] = true
	}
	out := []string{parts[0]}
	for _, p := range parts[1:] {
		k, _, _ := strings.Cut(p, "=")
		if !set[k] {
			out = append(out, p)
		}
	}
	return strings.Join(append(out, strings.Split(options, ",")...), ",")
}

func (c *Client) configureWorkload(ctx context.Context, w tenant.WorkloadSpec, start bool) error {
	cfg := map[string]string{
		"cores":     strconv.Itoa(w.Cores),
		"memory":    strconv.Itoa(w.MemoryMB),
		"agent":     "enabled=1",
		"onboot":    "1",
		"net0":      fmt.Sprintf("virtio=%s,bridge=%s", w.MAC, w.Bridge),
		"ipconfig0": fmt.Sprintf("ip=%s,gw=%s", w.Address, w.Gateway),
		"tags":      strings.Join(w.Tags, ";"),
		// Proxmox defaults ciupgrade on, which makes cloud-init run a full
		// package upgrade on first boot: hundreds of packages, minutes long,
		// and in CHG-0028 it took a workload's network down half way. The
		// template is built up to date; later updates are the tenant's.
		"ciupgrade": "0",
	}
	if w.Nameserver != "" {
		cfg["nameserver"] = w.Nameserver
	}
	if len(w.SSHKeys) > 0 {
		// Proxmox takes the authorized_keys file URL-encoded in one parameter
		// and decodes it with uri_unescape, which turns %XX back but leaves
		// '+' as '+'. QueryEscape writes a space as '+', so every key arrived
		// with its spaces gone; spell spaces %20 (a literal '+' is already %2B).
		cfg["sshkeys"] = strings.ReplaceAll(url.QueryEscape(strings.Join(w.SSHKeys, "\n")+"\n"), "+", "%20")
	}
	if w.CIUser != "" {
		cfg["ciuser"] = w.CIUser
	}
	if err := c.post(ctx, fmt.Sprintf("/nodes/%s/qemu/%d/config", url.PathEscape(w.Node), w.VMID), cfg); err != nil {
		return fmt.Errorf("configure %d: %w", w.VMID, err)
	}

	if w.DiskGB > 0 {
		// Growing only: Proxmox refuses to shrink, and so does this.
		err := c.request(ctx, http.MethodPut, fmt.Sprintf("/nodes/%s/qemu/%d/resize", url.PathEscape(w.Node), w.VMID),
			map[string]string{"disk": w.Disk, "size": strconv.Itoa(w.DiskGB) + "G"}, nil)
		// "disk size is smaller" comes back when the template is already larger.
		if err != nil && !strings.Contains(err.Error(), "smaller") {
			return fmt.Errorf("resize %d: %w", w.VMID, err)
		}
	}

	if start {
		if err := c.postTask(ctx, w.Node, fmt.Sprintf("/nodes/%s/qemu/%d/status/start", url.PathEscape(w.Node), w.VMID), nil); err != nil {
			return fmt.Errorf("start %d: %w", w.VMID, err)
		}
	}
	return nil
}

// RemoveWorkload stops and deletes the VM. An absent VM is not an error.
func (c *Client) RemoveWorkload(ctx context.Context, node string, vmid int) error {
	vms, err := c.listVMs(ctx, node)
	if err != nil {
		return err
	}
	var found *vmEntry
	for i := range vms {
		if int(vms[i].VMID) == vmid {
			found = &vms[i]
		}
	}
	if found == nil {
		return nil
	}
	if found.Status == "running" {
		if err := c.postTask(ctx, node, fmt.Sprintf("/nodes/%s/qemu/%d/status/stop", url.PathEscape(node), vmid), nil); err != nil {
			return fmt.Errorf("stop %d: %w", vmid, err)
		}
	}
	var upid string
	if err := c.request(ctx, http.MethodDelete, fmt.Sprintf("/nodes/%s/qemu/%d", url.PathEscape(node), vmid), nil, &upid); err != nil {
		return fmt.Errorf("delete %d: %w", vmid, err)
	}
	return c.waitTask(ctx, node, upid)
}

func (c *Client) listVMs(ctx context.Context, node string) ([]vmEntry, error) {
	var vms []vmEntry
	if err := c.get(ctx, "/nodes/"+url.PathEscape(node)+"/qemu", &vms); err != nil {
		return nil, fmt.Errorf("list VMs on %s: %w", node, err)
	}
	return vms, nil
}

// newestTemplate picks the highest-versioned template whose name starts with
// prefix, comparing the numbers in the name rather than the string: a plain
// sort puts 44-1.9 above 44-1.10. This is the rule proxmox_vm follows.
func newestTemplate(vms []vmEntry, prefix string) (int, error) {
	var candidates []vmEntry
	for _, vm := range vms {
		if vm.Template == 1 && strings.HasPrefix(vm.Name, prefix) {
			candidates = append(candidates, vm)
		}
	}
	if len(candidates) == 0 {
		return 0, fmt.Errorf("no template on this node whose name starts with %q", prefix)
	}
	sort.Slice(candidates, func(i, j int) bool {
		return versionLess(candidates[i].Name, candidates[j].Name)
	})
	return int(candidates[len(candidates)-1].VMID), nil
}

func versionLess(a, b string) bool {
	na, nb := numbersIn(a), numbersIn(b)
	for i := 0; i < len(na) && i < len(nb); i++ {
		if na[i] != nb[i] {
			return na[i] < nb[i]
		}
	}
	if len(na) != len(nb) {
		return len(na) < len(nb)
	}
	return a < b
}

func numbersIn(s string) []int {
	var out []int
	cur := ""
	for _, r := range s {
		if r >= '0' && r <= '9' {
			cur += string(r)
			continue
		}
		if cur != "" {
			n, _ := strconv.Atoi(cur)
			out = append(out, n)
			cur = ""
		}
	}
	if cur != "" {
		n, _ := strconv.Atoi(cur)
		out = append(out, n)
	}
	return out
}

// postTask runs a call that answers with a task id, and waits for it.
func (c *Client) postTask(ctx context.Context, node, path string, body map[string]string) error {
	var upid string
	if err := c.request(ctx, http.MethodPost, path, body, &upid); err != nil {
		return err
	}
	return c.waitTask(ctx, node, upid)
}

// waitTask polls a Proxmox task to completion and fails on a non-OK exit.
func (c *Client) waitTask(ctx context.Context, node, upid string) error {
	if upid == "" {
		return nil
	}
	deadline := time.Now().Add(c.taskTimeout())
	for {
		var st struct {
			Status     string `json:"status"`
			ExitStatus string `json:"exitstatus"`
		}
		if err := c.get(ctx, fmt.Sprintf("/nodes/%s/tasks/%s/status", url.PathEscape(node), url.PathEscape(upid)), &st); err != nil {
			return fmt.Errorf("task %s: %w", upid, err)
		}
		if st.Status == "stopped" {
			if st.ExitStatus != "OK" {
				return fmt.Errorf("task %s: %s", upid, st.ExitStatus)
			}
			return nil
		}
		if time.Now().After(deadline) {
			return fmt.Errorf("task %s did not finish within %s", upid, c.taskTimeout())
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(2 * time.Second):
		}
	}
}

func (c *Client) taskTimeout() time.Duration {
	if c.TaskTimeout > 0 {
		return c.TaskTimeout
	}
	return 10 * time.Minute
}

var errNotFound = errors.New("proxmox: not found")
