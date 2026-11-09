package identity

import (
	"fmt"
	"path"
)

// LoadTrustFiles reads and checks the agent copy of server-id,
// endpoints.json, agent-ca.pem and controlplane-ca.pem from ConfigDir.
// Every file goes through ReadRootFile's R10e checks; any failure means the
// agent makes no connection (R10e) and enrolls nothing (§4.1).
func LoadTrustFiles() (TrustFiles, error) {
	return loadTrustFiles("/", ConfigDir[1:], 0)
}

// LoadExecutorBinding reads the executor binding file from ConfigDir under
// R10e and decodes it (R12, R12b). The agent reads it only to enroll.
func LoadExecutorBinding() (ExecutorBinding, error) {
	data, err := readOwnedFile("/", path.Join(ConfigDir[1:], FileExecutorBinding), 0, ExecutorBindingFileSize)
	if err != nil {
		return ExecutorBinding{}, err
	}
	b, err := ParseExecutorBinding(data)
	if err != nil {
		return ExecutorBinding{}, fmt.Errorf("%s: %w", FileExecutorBinding, err)
	}
	return b, nil
}

// loadTrustFiles is LoadTrustFiles with readOwnedFile's test seams.
// On failure it returns the zero TrustFiles, never a partial one.
func loadTrustFiles(start, rel string, owner int) (TrustFiles, error) {
	tf, err := readTrustFiles(start, rel, owner)
	if err != nil {
		return TrustFiles{}, err
	}
	return tf, nil
}

func readTrustFiles(start, rel string, owner int) (TrustFiles, error) {
	var tf TrustFiles
	read := func(name string, maxBytes int64) ([]byte, error) {
		return readOwnedFile(start, path.Join(rel, name), owner, maxBytes)
	}
	data, err := read(FileServerID, maxServerIDFileBytes)
	if err != nil {
		return tf, err
	}
	if tf.ServerID, err = ParseServerIDFile(data); err != nil {
		return tf, fmt.Errorf("%s: %w", FileServerID, err)
	}
	if data, err = read(FileEndpoints, maxEndpointsBytes); err != nil {
		return tf, err
	}
	if tf.Endpoints, err = ParseEndpoints(data); err != nil {
		return tf, fmt.Errorf("%s: %w", FileEndpoints, err)
	}
	if data, err = read(FileAgentCA, maxAgentCABytes); err != nil {
		return tf, err
	}
	if tf.AgentCA, err = ParseAgentCA(data); err != nil {
		return tf, fmt.Errorf("%s: %w", FileAgentCA, err)
	}
	if data, err = read(FileControlPlaneCA, maxControlPlaneBytes); err != nil {
		return tf, err
	}
	if tf.ControlPlaneCAs, err = ParseControlPlaneCAs(data); err != nil {
		return tf, fmt.Errorf("%s: %w", FileControlPlaneCA, err)
	}
	return tf, nil
}
