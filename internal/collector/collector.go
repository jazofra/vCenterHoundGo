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
	Config    config.Config
	Client    *govmomi.Client
	Context   context.Context
	Graph     *graph.Builder
	TagMap    map[string][]string
	DomainMap map[string]string // NetBIOS -> FQDN
	Logger    *log.Logger
}

func NewCollector(cfg config.Config, gb *graph.Builder, domainMap map[string]string) *VCenterCollector {
	if domainMap == nil {
		domainMap = make(map[string]string)
	}
	return &VCenterCollector{
		Config:    cfg,
		Graph:     gb,
		TagMap:    make(map[string][]string),
		DomainMap: domainMap,
		Logger:    log.New(os.Stdout, "vCenterHound: ", log.Ldate|log.Ltime),
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

			properties["version"] = h.Config.Product.Version
			properties["build"] = h.Config.Product.Build
			properties["connectionState"] = string(h.Summary.Runtime.ConnectionState)
			properties["powerState"] = string(h.Summary.Runtime.PowerState)
			properties["inMaintenanceMode"] = h.Summary.Runtime.InMaintenanceMode

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
		}
	case "VirtualMachine":
		var vms []mo.VirtualMachine
		v.Retrieve(c.Context, []string{kind}, props, &vms)
		for _, vm := range vms {
			id := c.makeID("vm", vm.Reference().Value)
			props := map[string]any{"name": vm.Name, "moid": vm.Reference().Value}

			props["powerState"] = string(vm.Summary.Runtime.PowerState)
			props["connectionState"] = string(vm.Summary.Runtime.ConnectionState)
			if !vm.Summary.Runtime.BootTime.IsZero() {
				props["bootTime"] = vm.Summary.Runtime.BootTime.String()
			}

			if vm.Config != nil {
				props["guestFullName"] = vm.Config.GuestFullName
				props["uuid"] = vm.Config.Uuid
				props["isTemplate"] = vm.Config.Template
				props["guestId"] = vm.Config.GuestId
				props["version"] = vm.Config.Version
				if vm.Config.Hardware.NumCPU > 0 {
					props["numCPU"] = vm.Config.Hardware.NumCPU
				}
				if vm.Config.Hardware.NumCoresPerSocket > 0 {
					props["numCoresPerSocket"] = vm.Config.Hardware.NumCoresPerSocket
				}
				if vm.Config.Hardware.MemoryMB > 0 {
					props["memoryMB"] = vm.Config.Hardware.MemoryMB
				}
			}

			if vm.Guest != nil {
				props["hostName"] = vm.Guest.HostName
				// ipAddress is single, but user requested ipAddresses[]
				var ips []string
				var macs []string
				for _, nic := range vm.Guest.Net {
					ips = append(ips, nic.IpAddress...)
					if nic.MacAddress != "" {
						macs = append(macs, nic.MacAddress)
					}
				}
				// Remove duplicates from macs if any?
				props["ipAddresses"] = ips
				props["macAddresses"] = macs
				props["toolsStatus"] = string(vm.Guest.ToolsStatus)
				props["toolsVersion"] = vm.Guest.ToolsVersion
			}

			if vm.Summary.Storage != nil {
				props["storageCommitted"] = strconv.FormatInt(vm.Summary.Storage.Committed, 10)
				props["storageUncommitted"] = strconv.FormatInt(vm.Summary.Storage.Uncommitted, 10)
				// storageTotalUsed logic: typically committed space
				props["storageTotalUsed"] = strconv.FormatInt(vm.Summary.Storage.Committed, 10)
			}

			c.ensureNodeWithTags([]string{"VM"}, id, props, vm.Reference().Value)

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
			c.ensureNodeWithTags([]string{"Datastore"}, id, props, ds.Reference().Value)
		}
	case "Network":
		var nets []mo.Network
		v.Retrieve(c.Context, []string{kind}, props, &nets)
		for _, net := range nets {
			id := c.makeID("network", net.Reference().Value)
			c.ensureNodeWithTags([]string{"Network"}, id, map[string]any{"name": net.Name, "moid": net.Reference().Value, "type": "Network"}, net.Reference().Value)
		}
	case "DistributedVirtualPortgroup":
		var dvps []mo.DistributedVirtualPortgroup
		v.Retrieve(c.Context, []string{kind}, props, &dvps)
		for _, dvp := range dvps {
			id := c.makeID("dvportgroup", dvp.Reference().Value)
			c.ensureNodeWithTags([]string{"DVPortgroup", "Network"}, id, map[string]any{"name": dvp.Name, "moid": dvp.Reference().Value, "type": "DistributedVirtualPortgroup"}, dvp.Reference().Value)
		}
	case "VmwareDistributedVirtualSwitch":
		var dvss []mo.VmwareDistributedVirtualSwitch
		v.Retrieve(c.Context, []string{kind}, props, &dvss)
		for _, dvs := range dvss {
			id := c.makeID("dvswitch", dvs.Reference().Value)
			c.ensureNodeWithTags([]string{"DVSwitch"}, id, map[string]any{"name": dvs.Name, "moid": dvs.Reference().Value}, dvs.Reference().Value)
		}
	case "ResourcePool":
		var rps []mo.ResourcePool
		v.Retrieve(c.Context, []string{kind}, props, &rps)
		for _, rp := range rps {
			id := c.makeID("resource_pool", rp.Reference().Value)
			c.ensureNodeWithTags([]string{"ResourcePool"}, id, map[string]any{"name": rp.Name, "moid": rp.Reference().Value}, rp.Reference().Value)
			if rp.Parent != nil && rp.Parent.Type == "ResourcePool" {
				c.Graph.AddEdge("CONTAINS", c.makeID("resource_pool", rp.Parent.Value), id, nil)
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

	for _, role := range roles {
		roleID := fmt.Sprintf("role:%s:%d", c.Config.Host, role.RoleId)

		var groups []string
		seenGroups := make(map[string]bool)

		for _, privStr := range role.Privilege {
			if pInfo, ok := privMap[privStr]; ok {
				if pInfo.PrivGroupName != "" && !seenGroups[pInfo.PrivGroupName] {
					seenGroups[pInfo.PrivGroupName] = true
					groups = append(groups, pInfo.PrivGroupName)
				}
			}
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
				"name":        privName,
				"privId":      privStr,
				"group":       privGroup,
				"tags":        []string{},
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
