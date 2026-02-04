package collector

import (
	"context"
	"fmt"
	"log"
	"net/url"
	"os"
	"strconv"
	"strings"

	"vcenterhoundgo/internal/config"
	"vcenterhoundgo/internal/graph"

	"github.com/vmware/govmomi"
	"github.com/vmware/govmomi/object"
	"github.com/vmware/govmomi/property"
	"github.com/vmware/govmomi/view"
	"github.com/vmware/govmomi/vim25/methods"
	"github.com/vmware/govmomi/vim25/mo"
	"github.com/vmware/govmomi/vim25/types"
	"golang.org/x/sync/errgroup"
)

type VCenterCollector struct {
	Config      config.Config
	Client      *govmomi.Client
	Context     context.Context
	Graph       *graph.Builder
	TagMap      map[string][]string
	DomainMap   map[string]string // NetBIOS -> FQDN
	ComputerMap map[string]string // hostname -> objectid (from BloodHound API)
	Logger      *log.Logger
}

func NewCollector(cfg config.Config, gb *graph.Builder, domainMap map[string]string, computerMap map[string]string) *VCenterCollector {
	if domainMap == nil {
		domainMap = make(map[string]string)
	}
	if computerMap == nil {
		computerMap = make(map[string]string)
	}
	return &VCenterCollector{
		Config:      cfg,
		Graph:       gb,
		TagMap:      make(map[string][]string),
		DomainMap:   domainMap,
		ComputerMap: computerMap,
		Logger:      log.New(os.Stdout, "vCenterHound: ", log.Ldate|log.Ltime),
	}
}

func (c *VCenterCollector) Connect() error {
	c.Context = context.Background()
	u, err := url.Parse(fmt.Sprintf("https://%s:%d/sdk", c.Config.Host, c.Config.Port))
	if err != nil {
		return err
	}

	u.User = url.UserPassword(c.Config.User, c.Config.Password)

	c.Logger.Printf("Connecting to %s...", c.Config.Host)

	c.Client, err = govmomi.NewClient(c.Context, u, true)
	if err != nil {
		if strings.Contains(err.Error(), "Incorrect user name or password") {
			return fmt.Errorf("authentication failed: Incorrect user name or password for %s", c.Config.Host)
		}
		return err
	}

	c.Logger.Printf("Connected to %s", c.Config.Host)
	return nil
}

func (c *VCenterCollector) Debugf(format string, v ...any) {
	if c.Config.Debug {
		c.Logger.Printf("[DEBUG] "+format, v...)
	}
}

func (c *VCenterCollector) Collect() {
	// 1. Collect Tags (REST)
	tagColl := NewTagCollector(c.Config, c.Logger)
	c.TagMap = tagColl.Collect()

	// 2. Collect Infrastructure
	// We run this first to ensure all entity nodes (VMs, Hosts) are created with their proper Tags.
	// This step is internally parallelized.
	c.CollectInfrastructure()

	// 3. Collect Permissions
	// This creates User/Group nodes and adds edges to infrastructure entities.
	c.CollectPermissions()

	// 4. Collect Group Memberships
	// This depends on Group nodes existing from the Permission step.
	c.CollectGroupMemberships()
}

// Helpers
func (c *VCenterCollector) makeID(kind string, moid string) string {
	return fmt.Sprintf("%s:%s:%s", strings.ToLower(kind), c.Config.Host, moid)
}

func (c *VCenterCollector) ensureNodeWithTags(kinds []string, id string, props map[string]any, moid string) {
	if tags, ok := c.TagMap[moid]; ok {
		props["tags"] = tags
	} else {
		props["tags"] = []string{}
	}
	c.Graph.EnsureNode(kinds, id, props)
}

// tryComputerSync attempts to create a RepresentsVM or RepresentsHost edge from an AD Computer to a vCenter VM/Host.
// It returns true if a match was found.
// hostname: the guest hostname or ESXi FQDN (e.g., "PUPUENGWS001.vms.ad.varian.com")
// nodeID: the vCenter node ID (e.g., "vm:vcenter:vm-12345")
// edgeKind: "RepresentsVM" or "RepresentsHost"
func (c *VCenterCollector) tryComputerSync(hostname string, nodeID string, edgeKind string) bool {
	if !c.Config.SyncComputers || hostname == "" {
		return false
	}

	hostname = strings.ToUpper(hostname)
	shortName := strings.Split(hostname, ".")[0]

	// Try to match using the ComputerMap if we have it (API mode)
	if len(c.ComputerMap) > 0 {
		// Try full hostname first, then short name
		if objectID, ok := c.ComputerMap[hostname]; ok {
			c.Debugf("Syncing AD Computer %s to vCenter node %s (API match)", hostname, nodeID)
			c.Graph.AddRawEdgeWithMatch(edgeKind, objectID, "objectid", nodeID, "", nil)
			return true
		}
		if objectID, ok := c.ComputerMap[shortName]; ok {
			c.Debugf("Syncing AD Computer %s to vCenter node %s (API match - short name)", shortName, nodeID)
			c.Graph.AddRawEdgeWithMatch(edgeKind, objectID, "objectid", nodeID, "", nil)
			return true
		}
		return false
	}

	// Static mode: generate the expected AD Computer name and create the edge
	// Try to determine the domain from the hostname
	var computerFQDN string
	parts := strings.Split(hostname, ".")

	if len(parts) > 1 {
		// Hostname already has a domain, use it
		computerFQDN = hostname
	} else if len(c.Config.TargetDomains) > 0 {
		// Use the first target domain
		computerFQDN = shortName + "." + c.Config.TargetDomains[0]
	} else {
		// No domain info available
		return false
	}

	// Verify the domain is in our target domains list
	hostDomain := strings.ToUpper(strings.Join(parts[1:], "."))
	domainMatch := false
	for _, d := range c.Config.TargetDomains {
		if strings.EqualFold(hostDomain, d) || len(parts) == 1 {
			domainMatch = true
			break
		}
	}

	if !domainMatch && len(parts) > 1 {
		return false
	}

	c.Debugf("Syncing AD Computer %s to vCenter node %s (static match)", computerFQDN, nodeID)
	c.Graph.AddRawEdgeWithMatch(edgeKind, computerFQDN, "name", nodeID, "", nil)
	return true
}

// --- Infrastructure ---
func (c *VCenterCollector) CollectInfrastructure() {
	c.Logger.Println("Collecting infrastructure...")

	m := view.NewManager(c.Client.Client)
	v, err := m.CreateContainerView(c.Context, c.Client.ServiceContent.RootFolder, []string{"Datacenter"}, true)
	if err != nil {
		c.Logger.Printf("Error creating view: %v", err)
		return
	}
	defer v.Destroy(c.Context)

	var datacenters []mo.Datacenter
	err = v.Retrieve(c.Context, []string{"Datacenter"}, nil, &datacenters)
	if err != nil {
		return
	}
	c.Debugf("Found %d Datacenters", len(datacenters))

	vcID := fmt.Sprintf("vcenter:%s", c.Config.Host)
	c.Graph.EnsureNode([]string{"vCenter"}, vcID, map[string]any{"name": c.Config.Host, "tags": []string{}})

	rootFolderID := c.makeID("folder", c.Client.ServiceContent.RootFolder.Value)
	c.ensureNodeWithTags([]string{"RootFolder", "Folder"}, rootFolderID, map[string]any{"name": "rootFolder", "moid": c.Client.ServiceContent.RootFolder.Value}, c.Client.ServiceContent.RootFolder.Value)
	c.Graph.AddEdge("CONTAINS", vcID, rootFolderID, nil)

	for _, dc := range datacenters {
		dcID := c.makeID("datacenter", dc.Reference().Value)
		c.ensureNodeWithTags([]string{"Datacenter"}, dcID, map[string]any{"name": dc.Name, "moid": dc.Reference().Value}, dc.Reference().Value)

		if dc.Parent != nil {
			parentID := c.makeID("folder", dc.Parent.Value)
			c.Graph.AddEdge("CONTAINS", parentID, dcID, nil)
		}
	}

	// Parallelize entity retrieval
	var g errgroup.Group

	kinds := []struct {
		Name  string
		Props []string
	}{
		{"Folder", []string{"name", "parent", "childEntity"}},
		{"ClusterComputeResource", []string{"name", "parent", "host", "datastore", "resourcePool", "summary", "configuration"}},
		{"HostSystem", []string{"name", "parent", "vm", "datastore", "network", "summary", "config.product", "runtime"}},
		{"VirtualMachine", []string{"name", "parent", "datastore", "network", "config", "guest", "runtime", "summary"}},
		{"Datastore", []string{"name", "parent", "summary", "info"}},
		{"Network", []string{"name", "parent", "host", "summary"}},
		{"DistributedVirtualPortgroup", []string{"name", "parent", "host", "config", "summary"}},
		{"VmwareDistributedVirtualSwitch", []string{"name", "parent", "summary"}},
		{"ResourcePool", []string{"name", "parent", "vm", "resourcePool"}},
		{"VirtualApp", []string{"name", "parent", "vm", "vAppConfig"}},
	}

	for _, k := range kinds {
		k := k // capture
		g.Go(func() error {
			c.collectEntities(k.Name, k.Props)
			return nil
		})
	}

	g.Wait()
}

func (c *VCenterCollector) collectEntities(kind string, props []string) {
	c.Debugf("Starting collection for kind: %s", kind)
	m := view.NewManager(c.Client.Client)
	v, err := m.CreateContainerView(c.Context, c.Client.ServiceContent.RootFolder, []string{kind}, true)
	if err != nil {
		return
	}
	defer v.Destroy(c.Context)

	switch kind {
	case "Folder":
		var folders []mo.Folder
		v.Retrieve(c.Context, []string{kind}, props, &folders)
		for _, f := range folders {
			id := c.makeID("folder", f.Reference().Value)
			c.ensureNodeWithTags([]string{"Folder"}, id, map[string]any{"name": f.Name, "moid": f.Reference().Value}, f.Reference().Value)
			if f.Parent != nil {
				pKind := f.Parent.Type
				if pKind == "Datacenter" {
					c.Graph.AddEdge("CONTAINS", c.makeID("datacenter", f.Parent.Value), id, nil)
				} else if pKind == "Folder" {
					c.Graph.AddEdge("CONTAINS", c.makeID("folder", f.Parent.Value), id, nil)
				}
			}
		}
	case "ClusterComputeResource":
		var clusters []mo.ClusterComputeResource
		v.Retrieve(c.Context, []string{kind}, props, &clusters)
		for _, cl := range clusters {
			id := c.makeID("cluster", cl.Reference().Value)
			properties := map[string]any{"name": cl.Name, "moid": cl.Reference().Value}
			if cl.Summary != nil {
				s := cl.Summary.GetComputeResourceSummary()
				properties["totalCpu"] = s.TotalCpu
				properties["totalMemory"] = s.TotalMemory
				properties["numHosts"] = s.NumHosts
				properties["effectiveCpu"] = s.EffectiveCpu
				properties["effectiveMemory"] = s.EffectiveMemory
				properties["numCpuCores"] = s.NumCpuCores
				properties["numCpuThreads"] = s.NumCpuThreads
			}

			// Configuration
			properties["drsEnabled"] = false
			properties["haEnabled"] = false
			if cl.Configuration.DrsConfig.Enabled != nil {
				properties["drsEnabled"] = *cl.Configuration.DrsConfig.Enabled
			}
			if cl.Configuration.DasConfig.Enabled != nil {
				properties["haEnabled"] = *cl.Configuration.DasConfig.Enabled
			}

			c.ensureNodeWithTags([]string{"Cluster"}, id, properties, cl.Reference().Value)
			if cl.Parent != nil {
				c.Graph.AddEdge("CONTAINS", c.makeID("folder", cl.Parent.Value), id, nil)
			}
		}
	case "HostSystem":
		var hosts []mo.HostSystem
		v.Retrieve(c.Context, []string{kind}, props, &hosts)
		for _, h := range hosts {
			id := c.makeID("esxi_host", h.Reference().Value)
			properties := map[string]any{"name": h.Name, "moid": h.Reference().Value}
			if h.Summary.Hardware != nil {
				properties["vendor"] = h.Summary.Hardware.Vendor
				properties["model"] = h.Summary.Hardware.Model
				properties["numCpuCores"] = h.Summary.Hardware.NumCpuCores
				properties["memorySize"] = h.Summary.Hardware.MemorySize
				properties["cpuModel"] = h.Summary.Hardware.CpuModel
				properties["cpuMhz"] = h.Summary.Hardware.CpuMhz
				properties["numCpuThreads"] = h.Summary.Hardware.NumCpuThreads
			}

			if h.Config != nil {
				properties["version"] = h.Config.Product.Version
				properties["build"] = h.Config.Product.Build
			}

			if h.Summary.Runtime != nil {
				properties["connectionState"] = string(h.Summary.Runtime.ConnectionState)
				properties["powerState"] = string(h.Summary.Runtime.PowerState)
				properties["inMaintenanceMode"] = h.Summary.Runtime.InMaintenanceMode
			}

			// isStandalone: if parent is ComputeResource (not Cluster)
			isStandalone := false
			if h.Parent != nil && h.Parent.Type == "ComputeResource" {
				isStandalone = true
			}
			properties["isStandalone"] = isStandalone

			c.ensureNodeWithTags([]string{"ESXiHost"}, id, properties, h.Reference().Value)
			if h.Parent != nil && h.Parent.Type == "ClusterComputeResource" {
				c.Graph.AddEdge("CONTAINS", c.makeID("cluster", h.Parent.Value), id, nil)
			}

			// Try to sync ESXi host to AD Computer
			// ESXi hosts usually have FQDN as their name (e.g., pu-esx01.vms.ad.varian.com)
			c.tryComputerSync(h.Name, id, "RepresentsHost")
		}
	case "VirtualMachine":
		var vms []mo.VirtualMachine
		v.Retrieve(c.Context, []string{kind}, props, &vms)
		for _, vm := range vms {
			id := c.makeID("vm", vm.Reference().Value)
			props := map[string]any{"name": vm.Name, "moid": vm.Reference().Value}

			// Safe access to Runtime properties (embedded struct in Summary)
			props["powerState"] = string(vm.Summary.Runtime.PowerState)
			props["connectionState"] = string(vm.Summary.Runtime.ConnectionState)

			// BootTime is a *time.Time
			if vm.Summary.Runtime.BootTime != nil {
				props["bootTime"] = vm.Summary.Runtime.BootTime.String()
			}

			if vm.Config != nil {
				cfg := vm.Config
				props["guestFullName"] = cfg.GuestFullName
				props["uuid"] = cfg.Uuid
				props["isTemplate"] = cfg.Template
				props["guestId"] = cfg.GuestId
				props["version"] = cfg.Version

				// Hardware is a value struct, but check parent Config
				if cfg.Hardware.NumCPU > 0 {
					props["numCPU"] = cfg.Hardware.NumCPU
				}
				if cfg.Hardware.NumCoresPerSocket > 0 {
					props["numCoresPerSocket"] = cfg.Hardware.NumCoresPerSocket
				}
				if cfg.Hardware.MemoryMB > 0 {
					props["memoryMB"] = cfg.Hardware.MemoryMB
				}
			}

			if vm.Guest != nil {
				gst := vm.Guest
				props["hostName"] = gst.HostName
				// ipAddress is single, but user requested ipAddresses[]
				ips := make([]string, 0)
				macs := make([]string, 0)
				if gst.Net != nil {
					for _, nic := range gst.Net {
						if nic.IpAddress != nil {
							ips = append(ips, nic.IpAddress...)
						}
						if nic.MacAddress != "" {
							macs = append(macs, nic.MacAddress)
						}
					}
				}
				props["ipAddresses"] = ips
				props["macAddresses"] = macs
				props["toolsStatus"] = string(gst.ToolsStatus)
				props["toolsVersion"] = gst.ToolsVersion
			}

			if vm.Summary.Storage != nil {
				props["storageCommitted"] = strconv.FormatInt(vm.Summary.Storage.Committed, 10)
				props["storageUncommitted"] = strconv.FormatInt(vm.Summary.Storage.Uncommitted, 10)
				// storageTotalUsed logic: typically committed space
				props["storageTotalUsed"] = strconv.FormatInt(vm.Summary.Storage.Committed, 10)
			}

			c.ensureNodeWithTags([]string{"VM"}, id, props, vm.Reference().Value)

			// Add CONTAINS edge from parent folder to VM
			if vm.Parent != nil {
				parentKind := c.mapEntityType(vm.Parent.Type)
				c.Graph.AddEdge("CONTAINS", c.makeID(parentKind, vm.Parent.Value), id, nil)
			}

			if vm.Runtime.Host != nil {
				c.Graph.AddEdge("HOSTS", c.makeID("esxi_host", vm.Runtime.Host.Value), id, nil)
			}
			for _, ds := range vm.Datastore {
				c.Graph.AddEdge("USES_DATASTORE", id, c.makeID("datastore", ds.Value), nil)
			}
			for _, net := range vm.Network {
				netKind := "network"
				if net.Type == "DistributedVirtualPortgroup" {
					netKind = "dvportgroup"
				}
				c.Graph.AddEdge("USES_NETWORK", id, c.makeID(netKind, net.Value), nil)
			}

			// Try to sync VM to AD Computer using guest hostname
			if vm.Guest != nil && vm.Guest.HostName != "" {
				c.tryComputerSync(vm.Guest.HostName, id, "RepresentsVM")
			}
		}
	case "Datastore":
		var dss []mo.Datastore
		v.Retrieve(c.Context, []string{kind}, props, &dss)
		for _, ds := range dss {
			id := c.makeID("datastore", ds.Reference().Value)
			props := map[string]any{"name": ds.Name, "moid": ds.Reference().Value}
			props["url"] = ds.Summary.Url
			props["type"] = ds.Summary.Type
			props["capacity"] = ds.Summary.Capacity
			props["freeSpace"] = ds.Summary.FreeSpace
			props["accessible"] = ds.Summary.Accessible
			props["multipleHostAccess"] = ds.Summary.MultipleHostAccess

			// VMFS-specific properties
			if ds.Info != nil {
				if vmfsInfo, ok := ds.Info.(*types.VmfsDatastoreInfo); ok && vmfsInfo.Vmfs != nil {
					props["vmfsVersion"] = vmfsInfo.Vmfs.Version
					props["blockSizeMb"] = vmfsInfo.Vmfs.BlockSizeMb
				}
			}

			c.ensureNodeWithTags([]string{"Datastore"}, id, props, ds.Reference().Value)
			// Datastores are usually contained in a datastore folder under a datacenter
			if ds.Parent != nil {
				parentKind := c.mapEntityType(ds.Parent.Type)
				c.Graph.AddEdge("CONTAINS", c.makeID(parentKind, ds.Parent.Value), id, nil)
			}
		}
	case "Network":
		var nets []mo.Network
		v.Retrieve(c.Context, []string{kind}, props, &nets)
		for _, net := range nets {
			id := c.makeID("network", net.Reference().Value)
			props := map[string]any{
				"name": net.Name,
				"moid": net.Reference().Value,
				"type": "Network",
				"kind": "Network",
			}

			if net.Summary != nil {
				if netSummary, ok := net.Summary.(*types.NetworkSummary); ok {
					props["accessible"] = netSummary.Accessible
					if netSummary.Network != nil {
						props["network"] = netSummary.Network.Value
					}
				}
			}

			c.ensureNodeWithTags([]string{"Network"}, id, props, net.Reference().Value)
			// Networks are contained in a network folder under a datacenter
			if net.Parent != nil {
				parentKind := c.mapEntityType(net.Parent.Type)
				c.Graph.AddEdge("CONTAINS", c.makeID(parentKind, net.Parent.Value), id, nil)
			}
		}
	case "DistributedVirtualPortgroup":
		var dvps []mo.DistributedVirtualPortgroup
		v.Retrieve(c.Context, []string{kind}, props, &dvps)
		for _, dvp := range dvps {
			id := c.makeID("dvportgroup", dvp.Reference().Value)
			props := map[string]any{
				"name": dvp.Name,
				"moid": dvp.Reference().Value,
				"type": "DistributedVirtualPortgroup",
				"kind": "DVPortgroup",
			}

			// Config properties
			if dvp.Config.Key != "" {
				props["key"] = dvp.Config.Key
			}
			props["numPorts"] = dvp.Config.NumPorts
			if dvp.Config.AutoExpand != nil {
				props["autoExpand"] = *dvp.Config.AutoExpand
			}

			// VLAN ID from default port config
			if dvp.Config.DefaultPortConfig != nil {
				if portConfig, ok := dvp.Config.DefaultPortConfig.(*types.VMwareDVSPortSetting); ok && portConfig.Vlan != nil {
					if vlanSpec, ok := portConfig.Vlan.(*types.VmwareDistributedVirtualSwitchVlanIdSpec); ok {
						props["vlanId"] = vlanSpec.VlanId
					}
				}
			}

			// Accessible from summary
			if dvp.Summary != nil {
				// The summary is a PortgroupConnecteeInfo which doesn't have accessible directly
				// but we can mark it as accessible if it exists
				props["accessible"] = true
			}

			c.ensureNodeWithTags([]string{"DVPortgroup", "Network"}, id, props, dvp.Reference().Value)
			// DVPortgroups are contained in the network folder but belong to a DVSwitch
			if dvp.Config.DistributedVirtualSwitch != nil {
				c.Graph.AddEdge("CONTAINS", c.makeID("dvswitch", dvp.Config.DistributedVirtualSwitch.Value), id, nil)
			}
		}
	case "VmwareDistributedVirtualSwitch":
		var dvss []mo.VmwareDistributedVirtualSwitch
		v.Retrieve(c.Context, []string{kind}, props, &dvss)
		for _, dvs := range dvss {
			id := c.makeID("dvswitch", dvs.Reference().Value)
			c.ensureNodeWithTags([]string{"DVSwitch"}, id, map[string]any{"name": dvs.Name, "moid": dvs.Reference().Value}, dvs.Reference().Value)
			// DVSwitches are contained in a network folder
			if dvs.Parent != nil {
				parentKind := c.mapEntityType(dvs.Parent.Type)
				c.Graph.AddEdge("CONTAINS", c.makeID(parentKind, dvs.Parent.Value), id, nil)
			}
		}
	case "ResourcePool":
		var rps []mo.ResourcePool
		v.Retrieve(c.Context, []string{kind}, props, &rps)
		for _, rp := range rps {
			id := c.makeID("resource_pool", rp.Reference().Value)
			c.ensureNodeWithTags([]string{"ResourcePool"}, id, map[string]any{"name": rp.Name, "moid": rp.Reference().Value}, rp.Reference().Value)
			if rp.Parent != nil {
				// ResourcePools can be nested under other ResourcePools, or under a Cluster/Host
				parentKind := c.mapEntityType(rp.Parent.Type)
				c.Graph.AddEdge("CONTAINS", c.makeID(parentKind, rp.Parent.Value), id, nil)
			}
		}
	case "VirtualApp":
		var vapps []mo.VirtualApp
		v.Retrieve(c.Context, []string{kind}, props, &vapps)
		for _, vapp := range vapps {
			id := c.makeID("vapp", vapp.Reference().Value)
			c.ensureNodeWithTags([]string{"vApp"}, id, map[string]any{"name": vapp.Name, "moid": vapp.Reference().Value}, vapp.Reference().Value)
			if vapp.Parent != nil {
				// vApps are typically children of ResourcePools
				parentKind := c.mapEntityType(vapp.Parent.Type)
				c.Graph.AddEdge("CONTAINS", c.makeID(parentKind, vapp.Parent.Value), id, nil)
			}
			// vApp contains VMs - add CONTAINS edges
			for _, vmRef := range vapp.Vm {
				c.Graph.AddEdge("CONTAINS", id, c.makeID("vm", vmRef.Value), nil)
			}
		}
	}
}

// --- Permissions ---
func (c *VCenterCollector) CollectPermissions() {
	c.Logger.Println("Collecting permissions...")
	am := object.NewAuthorizationManager(c.Client.Client)

	// Fetch all privileges to map ID -> Name and Group
	// Since govmomi 0.52.0 might not have FetchPrivilegeList in AuthorizationManager object wrapper,
	// we will try to fetch the AuthorizationManager properties directly.
	// But `object.AuthorizationManager` wrapper usually exposes helper methods.
	// If `PrivilegeList` is not available, we use PropertyCollector.

	// Attempt to get privilege list from AuthorizationManager property "privilegeList"
	var amMo mo.AuthorizationManager
	pc := property.DefaultCollector(c.Client.Client)
	err := pc.RetrieveOne(c.Context, *c.Client.ServiceContent.AuthorizationManager, []string{"privilegeList"}, &amMo)

	privMap := make(map[string]types.AuthorizationPrivilege)
	if err == nil {
		for _, p := range amMo.PrivilegeList {
			privMap[p.PrivId] = p
		}
	} else {
		c.Logger.Printf("Failed to retrieve privilege list: %v", err)
	}

	// Roles
	roles, err := am.RoleList(c.Context)
	if err != nil {
		c.Logger.Printf("Failed to list roles: %v", err)
		return
	}
	c.Debugf("Found %d Roles", len(roles))

	// Build role privilege info for HAS_PERMISSION edges
	type rolePrivInfo struct {
		privilegeIds    []string
		privilegeNames  []string
		privilegeGroups []string
	}
	rolePrivilegesMap := make(map[int32]rolePrivInfo)

	for _, role := range roles {
		roleID := fmt.Sprintf("role:%s:%d", c.Config.Host, role.RoleId)

		groups := make([]string, 0)
		seenGroups := make(map[string]bool)
		privIds := make([]string, 0, len(role.Privilege))
		privNames := make([]string, 0, len(role.Privilege))

		for _, privStr := range role.Privilege {
			privIds = append(privIds, privStr)
			privName := privStr
			if pInfo, ok := privMap[privStr]; ok {
				privName = pInfo.Name
				if pInfo.PrivGroupName != "" && !seenGroups[pInfo.PrivGroupName] {
					seenGroups[pInfo.PrivGroupName] = true
					groups = append(groups, pInfo.PrivGroupName)
				}
			}
			privNames = append(privNames, privName)
		}

		// Store privilege info for this role
		rolePrivilegesMap[role.RoleId] = rolePrivInfo{
			privilegeIds:    privIds,
			privilegeNames:  privNames,
			privilegeGroups: groups,
		}

		c.Graph.EnsureNode([]string{"Role"}, roleID, map[string]any{
			"name":            role.Name,
			"roleId":          role.RoleId,
			"privilegeCount":  len(role.Privilege),
			"privilegeGroups": groups,
			"tags":            []string{},
		})
		for _, privStr := range role.Privilege {
			privID := fmt.Sprintf("privilege:%s:%s", c.Config.Host, privStr)

			privName := privStr
			privGroup := ""
			if pInfo, ok := privMap[privStr]; ok {
				privName = pInfo.Name
				privGroup = pInfo.PrivGroupName
			}

			c.Graph.EnsureNode([]string{"Privilege"}, privID, map[string]any{
				"name":   privName,
				"privId": privStr,
				"group":  privGroup,
				"tags":   []string{},
			})
			c.Graph.AddEdge("HAS_PRIVILEGE", roleID, privID, nil)
		}
	}

	// Permissions
	perms, err := am.RetrieveAllPermissions(c.Context)
	if err != nil {
		c.Logger.Printf("Failed to retrieve permissions: %v", err)
		return
	}
	c.Debugf("Found %d Permissions", len(perms))

	roleMap := make(map[int32]string)
	for _, r := range roles {
		roleMap[r.RoleId] = r.Name
	}

	for _, perm := range perms {
		principal := perm.Principal
		isGroup := perm.Group

		var kind, prefix string
		if isGroup {
			kind = "Group"
			prefix = "group"
		} else {
			kind = "User"
			prefix = "user"
		}

		principalID := fmt.Sprintf("%s:%s:%s", prefix, c.Config.Host, principal)

		parts := strings.Split(principal, "\\")
		var domain, username string
		if len(parts) > 1 {
			domain = parts[0]
			username = parts[1]
		} else {
			partsAt := strings.Split(principal, "@")
			if len(partsAt) > 1 {
				domain = partsAt[1]
				username = partsAt[0]
			} else {
				username = principal
				domain = "local"
			}
		}

		c.Graph.EnsureNode([]string{kind}, principalID, map[string]any{
			"name":     principal,
			"username": username,
			"domain":   domain,
			"isGroup":  isGroup,
		})

		// SyncsToVCenterUser / SyncsToVCenterGroup Edge
		if fqdn, ok := c.DomainMap[strings.ToUpper(domain)]; ok {
			adPrincipalID := fmt.Sprintf("%s@%s", strings.ToUpper(username), fqdn)

			if !isGroup {
				c.Debugf("Syncing vCenter user %s to AD user %s", principal, adPrincipalID)
				c.Graph.AddRawEdgeWithMatch("SyncsTovCenterUser", adPrincipalID, "name", principalID, "", nil)
			} else {
				c.Debugf("Syncing vCenter group %s to AD group %s", principal, adPrincipalID)
				c.Graph.AddRawEdgeWithMatch("SyncsTovCenterGroup", adPrincipalID, "name", principalID, "", nil)
			}
		}

		roleName := roleMap[perm.RoleId]
		if roleName == "" {
			roleName = fmt.Sprintf("Role_%d", perm.RoleId)
		}

		if strings.EqualFold(roleName, "no access") || strings.EqualFold(roleName, "noaccess") {
			continue
		}

		entityKind := c.mapEntityType(perm.Entity.Type)
		entityID := c.makeID(entityKind, perm.Entity.Value)

		c.Graph.EnsureNode([]string{c.mapEntityKind(perm.Entity.Type)}, entityID, map[string]any{"moid": perm.Entity.Value, "tags": []string{}})

		props := map[string]any{
			"roleId":    perm.RoleId,
			"roleName":  roleName,
			"propagate": perm.Propagate,
		}

		// Add privilege details from the role
		if privInfo, ok := rolePrivilegesMap[perm.RoleId]; ok {
			props["privilegeIds"] = privInfo.privilegeIds
			props["privilegeNames"] = privInfo.privilegeNames
			props["privilegeGroups"] = privInfo.privilegeGroups
			props["privilegeCount"] = len(privInfo.privilegeIds)
		}

		c.Graph.AddEdge("HAS_PERMISSION", principalID, entityID, props)
	}
}

func (c *VCenterCollector) mapEntityType(vimType string) string {
	switch vimType {
	case "VirtualMachine":
		return "vm"
	case "HostSystem":
		return "esxi_host"
	case "ClusterComputeResource":
		return "cluster"
	case "ComputeResource":
		return "cluster" // Standalone hosts use ComputeResource as parent
	case "Datacenter":
		return "datacenter"
	case "Datastore":
		return "datastore"
	case "Network":
		return "network"
	case "Folder":
		return "folder"
	case "ResourcePool":
		return "resource_pool"
	case "VirtualApp":
		return "vapp"
	case "DistributedVirtualPortgroup":
		return "dvportgroup"
	case "VmwareDistributedVirtualSwitch":
		return "dvswitch"
	default:
		return strings.ToLower(vimType)
	}
}

func (c *VCenterCollector) mapEntityKind(vimType string) string {
	switch vimType {
	case "HostSystem":
		return "ESXiHost"
	case "ClusterComputeResource":
		return "Cluster"
	case "DistributedVirtualPortgroup":
		return "DVPortgroup"
	case "VmwareDistributedVirtualSwitch":
		return "DVSwitch"
	case "VirtualApp":
		return "vApp"
	default:
		return vimType
	}
}

func (c *VCenterCollector) CollectGroupMemberships() {
	c.Logger.Println("Collecting group memberships...")

	udRef := c.Client.ServiceContent.UserDirectory
	if udRef == nil {
		c.Logger.Println("UserDirectory not available.")
		return
	}

	data := c.Graph.Export()

	var groups []string
	for _, node := range data.Nodes {
		for _, kind := range node.Kinds {
			if kind == "vCenter_Group" {
				if name, ok := node.Properties["name"].(string); ok {
					groups = append(groups, name)
				}
				break
			}
		}
	}

	if len(groups) == 0 {
		c.Debugf("No groups found to analyze memberships for")
		return
	}

	c.Logger.Printf("Analyzing memberships for %d groups...", len(groups))

	for _, groupName := range groups {
		c.Debugf("Querying members for group: %s", groupName)
		req := types.RetrieveUserGroups{
			This:           *udRef,
			SearchStr:      "",
			ExactMatch:     false,
			FindUsers:      true,
			FindGroups:     true,
			BelongsToGroup: groupName,
		}

		resp, err := methods.RetrieveUserGroups(c.Context, c.Client.Client, &req)
		if err != nil {
			if strings.Contains(groupName, "\\") {
				parts := strings.SplitN(groupName, "\\", 2)
				req.Domain = parts[0]
				req.BelongsToGroup = parts[1]
				resp, err = methods.RetrieveUserGroups(c.Context, c.Client.Client, &req)
			}
		}

		if err != nil {
			continue
		}

		parentGID := fmt.Sprintf("group:%s:%s", c.Config.Host, groupName)

		for _, res := range resp.Returnval {
			searchResult, ok := res.(*types.UserSearchResult)
			if !ok {
				continue
			}
			memberPrincipal := searchResult.Principal
			isGroup := searchResult.Group

			var kind, prefix string
			if isGroup {
				kind = "Group"
				prefix = "group"
			} else {
				kind = "User"
				prefix = "user"
			}

			memberID := fmt.Sprintf("%s:%s:%s", prefix, c.Config.Host, memberPrincipal)

			parts := strings.Split(memberPrincipal, "\\")
			var domain, username string
			if len(parts) > 1 {
				domain = parts[0]
				username = parts[1]
			} else {
				username = memberPrincipal
				domain = "local"
			}

			c.Graph.EnsureNode([]string{kind}, memberID, map[string]any{
				"name":     memberPrincipal,
				"username": username,
				"domain":   domain,
				"isGroup":  isGroup,
				"tags":     []string{},
			})

			c.Graph.AddEdge("MEMBER_OF", memberID, parentGID, nil)
		}
	}
}
