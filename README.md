# vCenterHound

Export vCenter data (hosts, VMs, permissions, users, groups, tags) into a BloodHound-compatible JSON file for security analysis and attack path visualization.

🚀 **Now in Go!** This version replaces the original Python script, offering significant performance improvements and new features like REST API tag collection and BloodHound Enterprise integration.

## Features

*   **High Performance**: Go implementation with concurrent processing for large environments.
*   **Comprehensive Collection**:
    *   **Infrastructure**: Datacenters, Clusters, ESXi Hosts, Resource Pools, VMs, Datastores, Networks.
    *   **Permissions**: Roles, Privileges, Users, Groups, and complex permission assignments.
    *   **Tags**: vCenter Tags collected via REST API (associated with VMs/Hosts).
*   **Active Directory Sync**: Automatically links vCenter users/groups to Active Directory nodes in BloodHound by resolving NetBIOS domains to FQDNs via BloodHound Enterprise API.
*   **Group Memberships**: Resolves nested group memberships including SSO and local groups.
*   **BloodHound Compatible**: Generates a standard graph JSON file with custom nodes/edges defined in `model.json`.

## Installation

### Requirements
*   Go 1.21 or later

### Build from Source

```bash
git clone https://github.com/jazofra/vCenterHoundGo
cd vCenterHoundGo
go build -o vCenterHound.exe cmd/vcenterhoundgo/main.go
```

## Usage

### 1. Upload Model to BloodHound
Before importing data, you must register the custom node/edge types in BloodHound. Use the provided `model.json`.

(Use `update_custom_nodes_to_bloodhound.py` if available, or upload via BloodHound API).

### 2. Run Collector

**Basic Run:**
```bash
./vCenterHound -s vc.example.com -u administrator@vsphere.local -p "Password!"
```

**With Active Directory Sync (BloodHound Enterprise):**
This mode fetches available domains from BloodHound to map vCenter NetBIOS names (e.g., `CORP`) to FQDNs (e.g., `CORP.LOCAL`), creating `SyncsTovCenterUser` edges.

```bash
./vCenterHound \
  -s vc.example.com \
  -u administrator@vsphere.local \
  -p "Password!" \
  --bh-url https://bloodhound.example.com \
  --bh-key-id "YOUR_KEY_ID" \
  --bh-key-secret "YOUR_KEY_SECRET"
```

**Debug Mode:**
Enable detailed logging and stats.
```bash
./vCenterHound -s vc.example.com ... --debug
```

### Command-Line Arguments

*   `-s`: vCenter server(s) (comma-separated).
*   `-u`: vCenter username.
*   `-p`: vCenter password.
*   `-P`: vCenter port (default 443).
*   `-o`: Output file path (default `vcenter_graph.json`).
*   `--debug`: Enable debug logging.
*   `--bh-url`: BloodHound Enterprise URL (for AD sync).
*   `--bh-key-id`: BloodHound API Key ID.
*   `--bh-key-secret`: BloodHound API Key Secret.

## Edge Types

| Edge Type | Source | Target | Description |
|-----------|--------|--------|-------------|
| `vCenter_Contains` | Folder/DC/Cluster | Entity | Hierarchical containment |
| `vCenter_Hosts` | ESXiHost | VM | VM execution location |
| `vCenter_HasPermission` | User/Group | Entity | Direct permission assignment |
| `vCenter_MemberOf` | User/Group | Group | Group membership |
| `vCenter_UsesDatastore` | VM | Datastore | Storage dependency |
| `vCenter_UsesNetwork` | VM | Network | Network connection |
| `vCenter_HasPrivilege` | Role | Privilege | Role definition |
| `SyncsTovCenterUser` | User (AD) | vCenter_User | Sync relationship (AD -> vCenter) |
| `SyncsTovCenterGroup` | Group (AD)| vCenter_Group| Sync relationship (AD -> vCenter) |

## Data Flow Diagram

Relationship visualization between vCenter entities and inferred external AD objects:

```mermaid
flowchart TD
    User["fa:fa-user User (AD)"] -. SyncsTovCenterUser .-> VCUser["fa:fa-user vCenter_User"]
    Group["fa:fa-users Group (AD)"] -. SyncsTovCenterGroup .-> VCGroup["fa:fa-users vCenter_Group"]

    VCUser -- vCenter_MemberOf --> VCGroup
    VCGroup -- vCenter_MemberOf --> VCGroup

    VCUser == vCenter_HasPermission ==> Entity
    VCGroup == vCenter_HasPermission ==> Entity

    subgraph Infrastructure
        Folder["fa:fa-folder Folder"] -- vCenter_Contains --> DC["fa:fa-building Datacenter"]
        DC -- vCenter_Contains --> Cluster["fa:fa-cubes Cluster"]
        Cluster -- vCenter_Contains --> Host["fa:fa-microchip ESXiHost"]
        Host -- vCenter_Hosts --> VM["fa:fa-desktop VM"]

        VM -. vCenter_UsesDatastore .-> DS["fa:fa-hdd Datastore"]
        VM -. vCenter_UsesNetwork .-> Net["fa:fa-network-wired Network"]
    end

    Entity -- represents --> Folder & DC & Cluster & Host & VM & DS & Net

    style User fill:#17E625,stroke:#0B8A14,stroke-width:2px
    style Group fill:#FFED29,stroke:#CCB900,stroke-width:2px
    style VCUser fill:#FF8E40,stroke:#CC7133,stroke-width:2px
    style VCGroup fill:#C06EFF,stroke:#9A58CC,stroke-width:2px
    style VM fill:#9EECFF,stroke:#7EBCCF,stroke-width:2px
```

## Useful Cypher Queries

### 1. Find Users with Direct Access to VMs
Identify users who have been granted direct permissions on Virtual Machines.

```cypher
MATCH (u:vCenter_User)-[r:vCenter_HasPermission]->(vm:vCenter_VM)
RETURN u.name, r.roleName, vm.name
```

### 2. Find AD Users with Path to vCenter
Find Active Directory users who can control vCenter entities via synchronization.

```cypher
MATCH (ad:User)-[:SyncsTovCenterUser]->(vc:vCenter_User)-[:vCenter_HasPermission]->(n)
RETURN ad.name, vc.name, labels(n)[0] as EntityType, n.name
```

### 3. Find Users with Admin-like Access (Root Folder)
Users with permissions on the Root Folder likely have access to the entire vCenter environment.

```cypher
MATCH (u)-[r:vCenter_HasPermission]->(f:vCenter_RootFolder)
RETURN u.name, r.roleName, f.name
```

### 4. Find VMs Accessible by a Specific Group
List all VMs that a specific group (e.g., "Developers") can access.

```cypher
MATCH (g:vCenter_Group {name: "Developers"})-[:vCenter_HasPermission]->(n)
OPTIONAL MATCH (n)-[:vCenter_Contains*]->(vm:vCenter_VM)
RETURN vm.name, n.name as PermissionScope
```

### 5. Find All Non-AD Users (Local vCenter Users)
Identify users that are local to vCenter and not synced from Active Directory.

```cypher
MATCH (u:vCenter_User)
WHERE NOT (u)<-[:SyncsTovCenterUser]-(:User)
RETURN u.name
```

### 6. Map VMs to their ESXi Hosts
Simple infrastructure mapping.

```cypher
MATCH (h:vCenter_ESXiHost)-[:vCenter_Hosts]->(vm:vCenter_VM)
RETURN h.name, count(vm) as VMCount, collect(vm.name) as VMs
```

## Acknowledgments

This tool is a Go port and enhancement of the original [vCenterHound](https://github.com/MorDavid/vCenterHound) by **Mor David**.

Original Author: Mor David (https://github.com/MorDavid)
Go Port & Enhancements: Javier Azofra Ovejero
