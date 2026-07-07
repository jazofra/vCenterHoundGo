package collector

import (
	"context"
	"log"
	"os"
	"testing"

	"vcenterhoundgo/internal/config"
	"vcenterhoundgo/internal/graph"

	"github.com/vmware/govmomi"
	"github.com/vmware/govmomi/simulator"
	"github.com/vmware/govmomi/vim25"
)

// TestCollectSessionsAndEvents drives the session/event collectors against the
// govmomi simulator (vcsim) to confirm they run end-to-end and produce nodes
// and edges without error.
func TestCollectSessionsAndEvents(t *testing.T) {
	simulator.Test(func(ctx context.Context, vc *vim25.Client) {
		gb := graph.NewBuilder()
		c := &VCenterCollector{
			Config: config.Config{
				Host:            "vcsim",
				User:            "collector-svc", // not the sim's session user, so it isn't filtered
				CollectEvents:   true,
				EventsSinceDays: 365,
			},
			Client:       &govmomi.Client{Client: vc},
			Context:      ctx,
			Graph:        gb,
			Logger:       log.New(os.Stdout, "test: ", 0),
			sessionUsers: make(map[string]bool),
		}

		// Should not panic and should record the simulator's active session.
		c.CollectSessions()
		if len(c.sessionUsers) == 0 {
			t.Error("expected at least one active session to be recorded")
		}

		// Should page through event history without error.
		c.CollectEvents()

		data := gb.Export()

		var hasSession int
		for _, e := range data.Edges {
			if e.Kind == "vCenter_HasSession" {
				hasSession++
			}
		}
		if hasSession == 0 {
			t.Error("expected at least one vCenter_HasSession edge")
		}

		t.Logf("nodes=%d edges=%d hasSession=%d", len(data.Nodes), len(data.Edges), hasSession)
	})
}
