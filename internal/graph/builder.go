package graph

import (
	"encoding/json"
	"fmt"
	"sort"
	"strings"
	"sync"
)

// GraphNode represents a node in the graph
type GraphNode struct {
	Kinds      []string       `json:"kinds"`
	ID         string         `json:"id"`
	Properties map[string]any `json:"properties"`
}

// GraphEdge represents an edge in the graph
type GraphEdge struct {
	Kind         string         `json:"kind"`
	StartID      string         `json:"start"`
	StartMatchBy string         `json:"-"` // Internal use, not direct JSON
	EndID        string         `json:"end"`
	EndMatchBy   string         `json:"-"` // Internal use, not direct JSON
	Properties   map[string]any `json:"properties"`
}

// MarshalJSON custom marshaling for Edge to match BloodHound format
func (e GraphEdge) MarshalJSON() ([]byte, error) {
	type EdgeValue struct {
		Value   string `json:"value"`
		MatchBy string `json:"match_by,omitempty"`
	}
	return json.Marshal(&struct {
		Kind       string         `json:"kind"`
		Start      EdgeValue      `json:"start"`
		End        EdgeValue      `json:"end"`
		Properties map[string]any `json:"properties"`
	}{
		Kind: e.Kind,
		Start: EdgeValue{
			Value:   e.StartID,
			MatchBy: e.StartMatchBy,
		},
		End: EdgeValue{
			Value:   e.EndID,
			MatchBy: e.EndMatchBy,
		},
		Properties: e.Properties,
	})
}

// GraphData structure for export
type GraphData struct {
	Nodes []GraphNode `json:"nodes"`
	Edges []GraphEdge `json:"edges"`
}

// Builder manages the graph construction in a thread-safe manner
type Builder struct {
	nodesByID   map[string]GraphNode
	edges       []GraphEdge
	edgeKeys    map[string]bool
	nodeTypeMap map[string]string
	edgeTypeMap map[string]string

	mu sync.RWMutex
}

// NewBuilder initializes a new graph builder
func NewBuilder() *Builder {
	return &Builder{
		nodesByID: make(map[string]GraphNode),
		edges:     make([]GraphEdge, 0),
		edgeKeys:  make(map[string]bool),
		nodeTypeMap: map[string]string{
			"vCenter":           "vCenter",
			"RootFolder":        "RootFolder",
			"Datacenter":        "Datacenter",
			"Cluster":           "Cluster",
			"ESXiHost":          "ESXiHost",
			"ResourcePool":      "ResourcePool",
			"vApp":              "vApp",
			"VM":                "VM",
			"VMTemplate":        "VMTemplate",
			"Datastore":         "Datastore",
			"DatastoreCluster":  "DatastoreCluster",
			"Network":           "Network",
			"StandardPortgroup": "StandardPortgroup",
			"DVSwitch":          "DVSwitch",
			"DVPortgroup":       "DVPortgroup",
			"Principal":         "Principal",
			"User":              "User",
			"Group":             "Group",
			"Privilege":         "Privilege",
			"Role":              "Role",
			"Folder":            "Folder",
			"IdentityDomain":    "IdentityDomain",
		},
		edgeTypeMap: map[string]string{
			"CONTAINS":              "Contains",
			"HOSTS":                 "Hosts",
			"HAS_PERMISSION":        "HasPermission",
			"MEMBER_OF":             "MemberOf",
			"USES_DATASTORE":        "UsesDatastore",
			"USES_NETWORK":          "UsesNetwork",
			"HAS_DATASTORE":         "HasDatastore",
			"HAS_NETWORK":           "HasNetwork",
			"MOUNTS":                "Mounts",
			"HAS_PRIVILEGE":         "HasPrivilege",
			"SYNCS_TO_VCENTER_USER": "SyncsToVCenterUser",
		},
	}
}

// FormatNodeKind formats the kind string with the proper prefix
func (gb *Builder) FormatNodeKind(kind string) string {
	mapped, ok := gb.nodeTypeMap[kind]
	if !ok {
		mapped = kind
	}
	// Clean kind name
	cleaned := strings.ReplaceAll(mapped, ".", "_")
	cleaned = strings.ReplaceAll(cleaned, "-", "_")
	cleaned = strings.ReplaceAll(cleaned, " ", "_")
	return "vCenter_" + cleaned
}

// FormatEdgeKind formats the edge kind string with the proper prefix
func (gb *Builder) FormatEdgeKind(kind string) string {
	mapped, ok := gb.edgeTypeMap[kind]
	if !ok {
		mapped = kind
	}
	return "vCenter_" + mapped
}

// EnsureNode adds or updates a node in the graph (Thread-Safe)
func (gb *Builder) EnsureNode(kinds []string, id string, props map[string]any) {
	gb.mu.Lock()
	defer gb.mu.Unlock()

	if existing, ok := gb.nodesByID[id]; ok {
		// Update existing properties
		for k, v := range props {
			if _, exists := existing.Properties[k]; !exists {
				existing.Properties[k] = v
			}
		}
		gb.nodesByID[id] = existing
		return
	}

	formattedKinds := make([]string, len(kinds))
	for i, k := range kinds {
		formattedKinds[i] = gb.FormatNodeKind(k)
	}

	gb.nodesByID[id] = GraphNode{
		Kinds:      formattedKinds,
		ID:         id,
		Properties: props,
	}
}

// AddRawNode adds a node without vCenter_ prefix (e.g., AD User) (Thread-Safe)
func (gb *Builder) AddRawNode(kinds []string, id string, props map[string]any) {
	gb.mu.Lock()
	defer gb.mu.Unlock()

	if _, ok := gb.nodesByID[id]; ok {
		return
	}
	gb.nodesByID[id] = GraphNode{
		Kinds:      kinds,
		ID:         id,
		Properties: props,
	}
}

// AddEdge adds an edge to the graph (Thread-Safe) - applies vCenter prefix
func (gb *Builder) AddEdge(kind, startID, endID string, props map[string]any) {
	gb.addEdgeInternal(gb.FormatEdgeKind(kind), startID, "", endID, "", props)
}

// AddRawEdge adds an edge to the graph without prefixing the kind
func (gb *Builder) AddRawEdge(kind, startID, endID string, props map[string]any) {
	gb.addEdgeInternal(kind, startID, "", endID, "", props)
}

// AddRawEdgeWithMatch adds an edge with specific match_by criteria
func (gb *Builder) AddRawEdgeWithMatch(kind, startID, startMatch, endID, endMatch string, props map[string]any) {
	gb.addEdgeInternal(kind, startID, startMatch, endID, endMatch, props)
}

func (gb *Builder) addEdgeInternal(kind, startID, startMatch, endID, endMatch string, props map[string]any) {
	if props == nil {
		props = make(map[string]any)
	}

	// Create deduplication key
	var propKeys []string
	for k := range props {
		propKeys = append(propKeys, k)
	}
	sort.Strings(propKeys)

	var propStr strings.Builder
	for _, k := range propKeys {
		propStr.WriteString(fmt.Sprintf("%s:%v|", k, props[k]))
	}

	// Include match_by in the key to ensure uniqueness if needed (though unlikely to overlap with same IDs)
	edgeKey := fmt.Sprintf("%s:%s:%s:%s:%s:%s", kind, startID, startMatch, endID, endMatch, propStr.String())

	gb.mu.Lock()
	defer gb.mu.Unlock()

	if gb.edgeKeys[edgeKey] {
		return
	}
	gb.edgeKeys[edgeKey] = true

	gb.edges = append(gb.edges, GraphEdge{
		Kind:         kind,
		StartID:      startID,
		StartMatchBy: startMatch,
		EndID:        endID,
		EndMatchBy:   endMatch,
		Properties:   props,
	})
}

// Export returns the current graph data
func (gb *Builder) Export() GraphData {
	gb.mu.RLock()
	defer gb.mu.RUnlock()

	nodes := make([]GraphNode, 0, len(gb.nodesByID))
	for _, n := range gb.nodesByID {
		nodes = append(nodes, n)
	}

	return GraphData{
		Nodes: nodes,
		Edges: gb.edges,
	}
}
