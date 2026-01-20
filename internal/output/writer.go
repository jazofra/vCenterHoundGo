package output

import (
	"encoding/json"
	"os"
	"vcenterhoundgo/internal/graph"
)

// Metadata contains optional metadata for the output file
type Metadata struct {
	SourceKind string `json:"source_kind"`
}

// Output structure for JSON file
type Output struct {
	Metadata Metadata        `json:"metadata"`
	Graph    graph.GraphData `json:"graph"`
}

// WriteToFile writes the graph data to a JSON file
func WriteToFile(data graph.GraphData, filename string) error {
	out := Output{
		Metadata: Metadata{
			SourceKind: "vCenterHound",
		},
		Graph: data,
	}

	file, err := os.Create(filename)
	if err != nil {
		return err
	}
	defer file.Close()

	enc := json.NewEncoder(file)
	enc.SetIndent("", "  ")
	return enc.Encode(out)
}
