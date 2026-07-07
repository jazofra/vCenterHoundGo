package collector

import (
	"fmt"
	"reflect"
	"sort"
	"strings"
	"time"

	"github.com/vmware/govmomi/event"
	"github.com/vmware/govmomi/property"
	"github.com/vmware/govmomi/vim25/mo"
	"github.com/vmware/govmomi/vim25/types"
)

// consoleEventTypes are the event types that represent interactive console
// (MKS / VMRC / web console) access to a VM. These are the strongest
// "someone is actually using this VM" signal.
var consoleEventTypes = map[string]bool{
	"VmAcquiredMksTicketEvent": true,
	"VmAcquiredTicketEvent":    true,
}

// vmUsageEventTypes are the VM-scoped event types we collect to build
// AccessedVM edges. They cover console access plus lifecycle operations
// that indicate a principal is operating the VM.
var vmUsageEventTypes = []string{
	"VmAcquiredMksTicketEvent",
	"VmAcquiredTicketEvent",
	"VmPoweredOnEvent",
	"VmPoweredOffEvent",
	"VmResettingEvent",
	"VmSuspendedEvent",
	"VmReconfiguredEvent",
	"VmGuestRebootEvent",
	"VmGuestShutdownEvent",
	"VmRelocatedEvent",
	"VmMigratedEvent",
}

// loginEventTypes are the session event types used to build historical
// HasSession edges (who has authenticated to vCenter).
var loginEventTypes = []string{
	"UserLoginSessionEvent",
}

// isServiceAccount returns true for principals that should be excluded from
// session/event collection: the collector's own account, empty names, and
// well-known vCenter service/system accounts that generate event noise.
func (c *VCenterCollector) isServiceAccount(userName string) bool {
	if userName == "" {
		return true
	}
	lower := strings.ToLower(userName)

	// The account we are collecting with.
	if strings.EqualFold(userName, c.Config.User) {
		return true
	}

	serviceMarkers := []string{
		"vpxd-", "vpxd-extension", "vsphere-webclient", "vpxuser",
		"machine-", "com.vmware", "vmware-vsm", "waiter-", "vstats",
		"hydra", "wcp-", "vlcm-", "vsan-", "vpostgres",
	}
	for _, m := range serviceMarkers {
		if strings.Contains(lower, m) {
			return true
		}
	}
	return false
}

// ensureUserPrincipal creates (or reuses) a vCenter_User node for the given
// principal, mirroring the identity parsing used by permission collection, and
// emits a SyncsTovCenterUser edge when the principal's domain resolves to a
// known AD domain. Returns the node ID.
func (c *VCenterCollector) ensureUserPrincipal(principal string) string {
	principalID := fmt.Sprintf("user:%s:%s", c.Config.Host, principal)

	var domain, username string
	if parts := strings.Split(principal, "\\"); len(parts) > 1 {
		domain = parts[0]
		username = parts[1]
	} else if partsAt := strings.Split(principal, "@"); len(partsAt) > 1 {
		username = partsAt[0]
		domain = partsAt[1]
	} else {
		username = principal
		domain = "local"
	}

	c.Graph.EnsureNode([]string{"User"}, principalID, map[string]any{
		"name":     principal,
		"username": username,
		"domain":   domain,
		"isGroup":  false,
		"tags":     []string{},
	})

	// Link to the corresponding AD user if the domain is known.
	if fqdn, ok := c.DomainMap[strings.ToUpper(domain)]; ok {
		adPrincipalID := fmt.Sprintf("%s@%s", strings.ToUpper(username), fqdn)
		c.Graph.AddRawEdgeWithMatch("SyncsTovCenterUser", adPrincipalID, "name", principalID, "", nil)
	}

	return principalID
}

// CollectSessions retrieves the currently active vCenter sessions and creates
// HasSession edges (User -> vCenter) plus login enrichment on the User nodes.
func (c *VCenterCollector) CollectSessions() {
	c.Logger.Println("Collecting active vCenter sessions...")

	smRef := c.Client.ServiceContent.SessionManager
	if smRef == nil {
		c.Logger.Println("SessionManager not available.")
		return
	}

	var sm mo.SessionManager
	pc := property.DefaultCollector(c.Client.Client)
	if err := pc.RetrieveOne(c.Context, *smRef, []string{"sessionList", "currentSession"}, &sm); err != nil {
		// Viewing all sessions requires the Sessions.TerminateSession privilege;
		// without it we can still record our own session.
		c.Logger.Printf("Failed to retrieve session list (need Sessions privilege for full list): %v", err)
	}

	sessions := sm.SessionList
	if len(sessions) == 0 && sm.CurrentSession != nil {
		sessions = []types.UserSession{*sm.CurrentSession}
	}

	// Aggregate by principal, keeping the most recent login.
	latest := make(map[string]types.UserSession)
	for _, s := range sessions {
		if s.ExtensionSession != nil && *s.ExtensionSession {
			continue
		}
		if c.isServiceAccount(s.UserName) {
			continue
		}
		if prev, ok := latest[s.UserName]; !ok || s.LoginTime.After(prev.LoginTime) {
			latest[s.UserName] = s
		}
	}

	vcID := fmt.Sprintf("vcenter:%s", c.Config.Host)
	c.Debugf("Found %d active non-service sessions (%d distinct principals)", len(sessions), len(latest))

	for principal, s := range latest {
		principalID := c.ensureUserPrincipal(principal)
		c.sessionUsers[principal] = true

		c.Graph.EnsureNode([]string{"User"}, principalID, map[string]any{
			"isActive":       true,
			"lastLogin":      s.LoginTime.Format(time.RFC3339),
			"lastActiveTime": s.LastActiveTime.Format(time.RFC3339),
			"lastLoginIp":    s.IpAddress,
			"userAgent":      s.UserAgent,
		})

		c.Graph.AddEdge("HAS_SESSION", principalID, vcID, map[string]any{
			"source":         "active",
			"ipAddress":      s.IpAddress,
			"userAgent":      s.UserAgent,
			"loginTime":      s.LoginTime.Format(time.RFC3339),
			"lastActiveTime": s.LastActiveTime.Format(time.RFC3339),
		})
	}
}

// vmUsage accumulates AccessedVM edge data for a (user, vm) pair.
type vmUsage struct {
	count      int
	lastSeen   time.Time
	console    bool
	eventTypes map[string]bool
}

// loginUsage accumulates historical HasSession data for a principal.
type loginUsage struct {
	count    int
	lastSeen time.Time
	ips      map[string]bool
}

// CollectEvents queries vCenter event history over the configured window and
// builds AccessedVM edges (User -> VM) and historical HasSession edges
// (User -> vCenter) for principals without an active session.
func (c *VCenterCollector) CollectEvents() {
	days := c.Config.EventsSinceDays
	if days <= 0 {
		days = 30
	}
	since := time.Now().AddDate(0, 0, -days)
	c.Logger.Printf("Collecting events since %s (%d days)...", since.Format("2006-01-02"), days)

	em := event.NewManager(c.Client.Client)

	eventTypes := append([]string{}, vmUsageEventTypes...)
	eventTypes = append(eventTypes, loginEventTypes...)

	filter := types.EventFilterSpec{
		EventTypeId: eventTypes,
		Time: &types.EventFilterSpecByTime{
			BeginTime: &since,
		},
		Entity: &types.EventFilterSpecByEntity{
			Entity:    c.Client.ServiceContent.RootFolder,
			Recursion: types.EventFilterSpecRecursionOptionAll,
		},
	}

	hc, err := em.CreateCollectorForEvents(c.Context, filter)
	if err != nil {
		c.Logger.Printf("Failed to create event collector: %v", err)
		return
	}
	defer hc.Destroy(c.Context)

	if err := hc.SetPageSize(c.Context, 1000); err != nil {
		c.Debugf("SetPageSize failed: %v", err)
	}
	// Rewind positions the scrollable view at the oldest matching event so
	// ReadNextEvents walks the full window forward in time.
	if err := hc.Rewind(c.Context); err != nil {
		c.Debugf("Rewind failed: %v", err)
	}

	vmUsageMap := make(map[string]*vmUsage)  // user\x00vmMoid -> usage
	loginMap := make(map[string]*loginUsage) // user -> login usage
	const maxEvents = 500000                 // safety cap for very large histories
	total := 0

	for {
		events, err := hc.ReadNextEvents(c.Context, 1000)
		if err != nil {
			c.Logger.Printf("Error reading events: %v", err)
			break
		}
		if len(events) == 0 {
			break
		}
		for _, be := range events {
			c.processEvent(be, vmUsageMap, loginMap)
		}
		total += len(events)
		if total >= maxEvents {
			c.Logger.Printf("Reached event cap (%d); stopping event collection", maxEvents)
			break
		}
	}
	c.Debugf("Processed %d events", total)

	c.emitAccessedVMEdges(vmUsageMap)
	c.emitHistoricalSessionEdges(loginMap)
}

// eventTypeName returns the concrete event struct name (e.g. "VmPoweredOnEvent").
func eventTypeName(be types.BaseEvent) string {
	t := reflect.TypeOf(be)
	if t == nil {
		return ""
	}
	if t.Kind() == reflect.Ptr {
		t = t.Elem()
	}
	return t.Name()
}

func (c *VCenterCollector) processEvent(be types.BaseEvent, vmUsageMap map[string]*vmUsage, loginMap map[string]*loginUsage) {
	e := be.GetEvent()
	user := e.UserName
	if c.isServiceAccount(user) {
		return
	}
	typeName := eventTypeName(be)

	// VM-scoped usage event.
	if e.Vm != nil && e.Vm.Vm.Value != "" {
		key := user + "\x00" + e.Vm.Vm.Value
		u, ok := vmUsageMap[key]
		if !ok {
			u = &vmUsage{eventTypes: make(map[string]bool)}
			vmUsageMap[key] = u
		}
		u.count++
		u.eventTypes[typeName] = true
		if consoleEventTypes[typeName] {
			u.console = true
		}
		if e.CreatedTime.After(u.lastSeen) {
			u.lastSeen = e.CreatedTime
		}
		return
	}

	// Login session event.
	if typeName == "UserLoginSessionEvent" {
		lu, ok := loginMap[user]
		if !ok {
			lu = &loginUsage{ips: make(map[string]bool)}
			loginMap[user] = lu
		}
		lu.count++
		if e.CreatedTime.After(lu.lastSeen) {
			lu.lastSeen = e.CreatedTime
		}
		if le, ok := be.(*types.UserLoginSessionEvent); ok && le.IpAddress != "" {
			lu.ips[le.IpAddress] = true
		}
	}
}

func (c *VCenterCollector) emitAccessedVMEdges(vmUsageMap map[string]*vmUsage) {
	c.Debugf("Emitting %d AccessedVM edges", len(vmUsageMap))
	for key, u := range vmUsageMap {
		parts := strings.SplitN(key, "\x00", 2)
		if len(parts) != 2 {
			continue
		}
		principal, vmMoid := parts[0], parts[1]

		principalID := c.ensureUserPrincipal(principal)
		vmID := c.makeID("vm", vmMoid)
		// Ensure the VM node exists (it normally does from infra collection).
		c.Graph.EnsureNode([]string{"VM"}, vmID, map[string]any{"moid": vmMoid, "tags": []string{}})

		evTypes := make([]string, 0, len(u.eventTypes))
		for t := range u.eventTypes {
			evTypes = append(evTypes, t)
		}
		sort.Strings(evTypes)

		c.Graph.AddEdge("ACCESSED_VM", principalID, vmID, map[string]any{
			"eventCount":    u.count,
			"lastSeen":      u.lastSeen.Format(time.RFC3339),
			"consoleAccess": u.console,
			"eventTypes":    evTypes,
		})
	}
}

func (c *VCenterCollector) emitHistoricalSessionEdges(loginMap map[string]*loginUsage) {
	vcID := fmt.Sprintf("vcenter:%s", c.Config.Host)
	emitted := 0
	for principal, lu := range loginMap {
		// Skip principals that already have a live session edge.
		if c.sessionUsers[principal] {
			continue
		}
		principalID := c.ensureUserPrincipal(principal)

		ips := make([]string, 0, len(lu.ips))
		for ip := range lu.ips {
			ips = append(ips, ip)
		}
		sort.Strings(ips)

		c.Graph.EnsureNode([]string{"User"}, principalID, map[string]any{
			"lastLogin":      lu.lastSeen.Format(time.RFC3339),
			"loginCount":     lu.count,
			"loginSourceIps": ips,
		})

		c.Graph.AddEdge("HAS_SESSION", principalID, vcID, map[string]any{
			"source":     "historical",
			"loginCount": lu.count,
			"lastLogin":  lu.lastSeen.Format(time.RFC3339),
			"sourceIps":  ips,
		})
		emitted++
	}
	c.Debugf("Emitted %d historical HasSession edges", emitted)
}
