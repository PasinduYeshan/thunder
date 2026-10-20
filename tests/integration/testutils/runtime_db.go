// Copyright 2026 The ThunderID Authors
// SPDX-License-Identifier: Apache-2.0

package testutils

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
)

// QueryRuntimeDB runs one SQL statement against the runtime persistent database and returns the
// trimmed CLI output: sqlite3 for SQLite, psql for Postgres, connecting as the deployment's
// database.runtime_persistent section says. It writes as well as reads, for tests that must see or
// shape what the server stores outside its APIs. Statements must be valid in both dialects.
func QueryRuntimeDB(sqlQuery string) (string, error) {
	ensureInitialized()
	switch dbType {
	case "sqlite":
		return querySQLiteRuntimeDB(sqlQuery)
	case "postgres":
		return queryPostgresRuntimeDB(sqlQuery)
	default:
		return "", fmt.Errorf("QueryRuntimeDB supports sqlite and postgres, current db type: %s", dbType)
	}
}

// DeleteRuntimeRow removes an entity's runtime row, so the entity reads as one governance has never
// acted on.
func DeleteRuntimeRow(entityID string) error {
	_, err := QueryRuntimeDB(fmt.Sprintf(`DELETE FROM "ENTITY_RUNTIME_DATA" WHERE ENTITY_ID = '%s';`, entityID))
	return err
}

func querySQLiteRuntimeDB(sqlQuery string) (string, error) {
	dbPath, err := filepath.Abs(filepath.Join(extractedProductHome, DatabaseFileBasePath, "runtime_persistent.db"))
	if err != nil {
		return "", fmt.Errorf("failed to resolve the runtime persistent database path: %v", err)
	}
	// The server holds the database open in WAL mode, so wait out its locks rather than fail on them.
	cmd := exec.Command("sqlite3", "-cmd", ".timeout 10000", dbPath, sqlQuery)
	out, err := cmd.CombinedOutput()
	if err != nil {
		return "", fmt.Errorf("sqlite3 query failed: %v: %s", err, strings.TrimSpace(string(out)))
	}
	return strings.TrimSpace(string(out)), nil
}

func queryPostgresRuntimeDB(sqlQuery string) (string, error) {
	section, err := ReadDeploymentConfigKey("database")
	if err != nil {
		return "", err
	}
	database, _ := section.(map[string]interface{})
	persistent, _ := database["runtime_persistent"].(map[string]interface{})
	conn, _ := persistent["postgres"].(map[string]interface{})
	if conn == nil {
		return "", fmt.Errorf("deployment.yaml has no database.runtime_persistent.postgres section")
	}
	value := func(key string) string { return fmt.Sprint(conn[key]) }

	cmd := exec.Command("psql", "-X", "-q", "-At", "-v", "ON_ERROR_STOP=1",
		"-h", value("hostname"), "-p", value("port"), "-U", value("username"), "-d", value("name"),
		"-c", sqlQuery)
	cmd.Env = append(os.Environ(), "PGPASSWORD="+value("password"))
	out, err := cmd.CombinedOutput()
	if err != nil {
		return "", fmt.Errorf("psql query failed: %v: %s", err, strings.TrimSpace(string(out)))
	}
	return strings.TrimSpace(string(out)), nil
}
