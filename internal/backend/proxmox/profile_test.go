package proxmox

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"

	"github.com/deevnet/deevnet-provisioning-api/internal/tenant"
	"github.com/deevnet/deevnet-provisioning-api/internal/tenant/tenanttest"
)

func TestProfileDrive(t *testing.T) {
	opts := "iothread=1,discard=on,cache=none"
	for _, tc := range []struct{ drive, want string }{
		// A clone of a template built before ADR-0046.
		{"local-lvm:vm-2040-disk-0,size=32G", "local-lvm:vm-2040-disk-0,size=32G," + opts},
		// The profile's options replace the drive's own; the others stay.
		{"local-lvm:vm-2040-disk-0,cache=writeback,discard=ignore,replicate=0,size=32G",
			"local-lvm:vm-2040-disk-0,replicate=0,size=32G," + opts},
		// Already on the profile: the same drive back.
		{"local-lvm:vm-2040-disk-0,size=32G," + opts, "local-lvm:vm-2040-disk-0,size=32G," + opts},
	} {
		if got := profileDrive(tc.drive, opts); got != tc.want {
			t.Errorf("profileDrive(%q)\n got %q\nwant %q", tc.drive, got, tc.want)
		}
	}
}

// fakeNode answers just enough of the PVE API for EnsureWorkload, and records
// every write in order.
type fakeNode struct {
	vms    []map[string]any
	config map[string]any
	mu     sync.Mutex
	writes []string // "<path> <form>"
}

func (f *fakeNode) handler(t *testing.T) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		reply := func(v any) {
			b, _ := json.Marshal(map[string]any{"data": v})
			_, _ = w.Write(b)
		}
		p := r.URL.Path
		if r.Method != http.MethodGet {
			_ = r.ParseForm()
			f.mu.Lock()
			f.writes = append(f.writes, p+" "+r.PostForm.Encode())
			f.mu.Unlock()
		}
		switch {
		case r.Method == http.MethodGet && strings.HasSuffix(p, "/qemu"):
			reply(f.vms)
		case r.Method == http.MethodGet && strings.HasSuffix(p, "/config"):
			reply(f.config)
		case r.Method == http.MethodGet && strings.Contains(p, "/tasks/"):
			reply(map[string]string{"status": "stopped", "exitstatus": "OK"})
		case strings.HasSuffix(p, "/clone"), strings.HasSuffix(p, "/status/start"):
			reply("UPID:hv02:0000:0000:0000:task::root@pam:")
		default:
			reply(nil)
		}
	})
}

func workload() tenant.WorkloadSpec {
	s := tenanttest.MobileSite()
	return tenant.WorkloadSpec{Name: "tdemo-backend", Node: "hv02", VMID: 2040, Cores: 2, MemoryMB: 2048,
		MAC: "02:00:00:00:00:01", Bridge: "tdemo0", Address: "10.20.129.10/24", Gateway: "10.20.129.1",
		Disk: s.Disk, SCSIHW: s.SCSIHW, DiskOptions: s.DiskOptions, TemplatePrefix: "fedora-tenant-"}
}

// A new workload is cloned from a template that may predate the profile (on
// LSI), so it is put on the profile before it first starts (ADR-0046,
// INC-0006).
func TestNewWorkloadIsOnTheProfileBeforeItStarts(t *testing.T) {
	f := &fakeNode{
		vms:    []map[string]any{{"vmid": 102, "name": "fedora-tenant-44-1.7", "template": 1, "status": "stopped"}},
		config: map[string]any{"scsihw": "lsi", "scsi0": "local-lvm:vm-2040-disk-0,size=32G"},
	}
	srv := httptest.NewServer(f.handler(t))
	defer srv.Close()
	c := New(srv.URL, "t@pve!x", "s", tenanttest.MobileSite(), false)
	if err := c.EnsureWorkload(context.Background(), workload()); err != nil {
		t.Fatal(err)
	}
	profiled, started := -1, -1
	for i, wr := range f.writes {
		switch {
		case strings.Contains(wr, "/qemu/2040/config ") && strings.Contains(wr, "scsihw=virtio-scsi-single"):
			profiled = i
			if !strings.Contains(wr, "scsi0=local-lvm%3Avm-2040-disk-0%2Csize%3D32G%2Ciothread%3D1%2Cdiscard%3Don%2Ccache%3Dnone") {
				t.Errorf("the disk is not on the profile: %s", wr)
			}
		case strings.HasSuffix(strings.Fields(wr)[0], "/status/start"):
			started = i
		}
	}
	if profiled < 0 {
		t.Fatalf("no write put the workload on the profile: %q", f.writes)
	}
	if started < 0 || started < profiled {
		t.Fatalf("started at write %d, profiled at %d: the profile must come first (%q)", started, profiled, f.writes)
	}
}

// An adopted workload is reconfigured, but its hardware is not: a running VM
// would hold a controller change pending until some later restart.
func TestAdoptedWorkloadKeepsItsHardware(t *testing.T) {
	f := &fakeNode{
		vms:    []map[string]any{{"vmid": 2040, "name": "tdemo-backend", "status": "running"}},
		config: map[string]any{"scsihw": "lsi", "scsi0": "local-lvm:vm-2040-disk-0,size=32G"},
	}
	srv := httptest.NewServer(f.handler(t))
	defer srv.Close()
	c := New(srv.URL, "t@pve!x", "s", tenanttest.MobileSite(), false)
	if err := c.EnsureWorkload(context.Background(), workload()); err != nil {
		t.Fatal(err)
	}
	for _, wr := range f.writes {
		if strings.Contains(wr, "scsihw=") || strings.Contains(wr, "scsi0=") {
			t.Fatalf("an adopted workload's hardware was written: %s", wr)
		}
	}
}
