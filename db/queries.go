/*
 * Copyright 2019 Travis Ralston <travis@t2bot.io>
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *    http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package db

import (
	"database/sql"
)

var statements = map[string]*sql.Stmt{}

const selectAllSelfKeys = "selectAllSelfKeys"
const selectActiveSelfKeyIds = "selectActiveSelfKeyIds"
const selectSelfKey = "selectSelfKey"
const insertActiveSelfKey = "insertActiveSelfKey"
const selectRemoteServer = "selectRemoteServer"
const selectRemoteKeys = "selectRemoteKeys"
const selectRemoteSignatures = "selectRemoteSignatures"
const deleteRemoteKeys = "deleteRemoteKeys"
const deleteRemoteSignatures = "deleteRemoteSignatures"
const upsertRemoteServer = "upsertRemoteServer"
const insertRemoteKey = "insertRemoteKey"
const insertRemoteSignature = "insertRemoteSignature"
const countKnownServers = "countKnownServers"
const noteOriginFailure = "noteOriginFailure"
const resetOriginProbe = "resetOriginProbe"
const selectOriginProbeCandidates = "selectOriginProbeCandidates"

var queries = map[string]string{
	selectAllSelfKeys:      "SELECT key_id, public_key_b64, private_key_b64, expires_ts FROM self_keys;",
	selectActiveSelfKeyIds: "SELECT key_id FROM self_keys WHERE expires_ts = 0;",
	selectSelfKey:          "SELECT public_key_b64, private_key_b64, expires_ts FROM self_keys WHERE key_id = $1;",
	insertActiveSelfKey:    "INSERT INTO self_keys (key_id, public_key_b64, private_key_b64) VALUES ($1, $2, $3);",
	selectRemoteServer:     "SELECT updated_ts, valid_until_ts, nonstandard_json, COALESCE(obtained_via_notary, ''), origin_failures, next_origin_attempt_ts FROM remote_servers WHERE server_name = $1",
	selectRemoteKeys:       "SELECT key_id, public_key_b64, expires_ts FROM remote_keys WHERE server_name = $1",
	selectRemoteSignatures: "SELECT key_id, signature_b64 FROM remote_signatures WHERE server_name = $1",
	deleteRemoteKeys:       "DELETE FROM remote_keys WHERE server_name = $1;",
	deleteRemoteSignatures: "DELETE FROM remote_signatures WHERE server_name = $1;",
	// Deliberately does not touch origin_failures / next_origin_attempt_ts: a
	// notary-sourced store runs *after* noteOriginFailure has scheduled the next
	// origin probe, and must not wipe that schedule. Origin-sourced stores clear
	// it explicitly via resetOriginProbe.
	upsertRemoteServer: "INSERT INTO remote_servers (server_name, updated_ts, valid_until_ts, nonstandard_json, obtained_via_notary) VALUES ($1, $2, $3, $4, $5) ON CONFLICT (server_name) DO UPDATE SET updated_ts = $2, valid_until_ts = $3, nonstandard_json = $4, obtained_via_notary = $5;",

	// noteOriginFailure records a failed origin probe and when the next one is
	// due. It inserts when the server is unknown, so the very first failure for a
	// never-seen server is rate-limited too, rather than needing a separate
	// negative-cache write to create the row.
	noteOriginFailure: `
		INSERT INTO remote_servers (server_name, updated_ts, valid_until_ts, nonstandard_json, origin_failures, next_origin_attempt_ts)
		VALUES ($1, $2, 0, '{}', $3, $4)
		ON CONFLICT (server_name) DO UPDATE SET updated_ts = $2, origin_failures = $3, next_origin_attempt_ts = $4;`,

	// selectOriginProbeCandidates lists servers whose origin is due another probe.
	// A next_origin_attempt_ts above zero is precisely "the origin has failed and
	// has not recovered since": a successful direct fetch resets it to zero, so a
	// healed server drops out of this sweep on its own and a healthy one never
	// appears in it. Oldest due first, so nothing can be starved by a busy tail.
	selectOriginProbeCandidates: `
		SELECT server_name FROM remote_servers
		WHERE next_origin_attempt_ts > 0 AND next_origin_attempt_ts <= $1
		ORDER BY next_origin_attempt_ts
		LIMIT $2;`,

	// resetOriginProbe clears the backoff after the origin answers us directly.
	resetOriginProbe:      "UPDATE remote_servers SET origin_failures = 0, next_origin_attempt_ts = 0 WHERE server_name = $1;",
	insertRemoteKey:       "INSERT INTO remote_keys (server_name, key_id, public_key_b64, expires_ts) VALUES ($1, $2, $3, $4);",
	insertRemoteSignature: "INSERT INTO remote_signatures (server_name, key_id, signature_b64) VALUES ($1, $2, $3);",

	// Every remote_servers row falls in exactly one bucket, so the three counts
	// sum to the total number of servers we know of. A row with no keys at all is
	// a negative-cache entry - neither the origin nor any notary could resolve it
	// - which is why "direct" is not simply obtained_via_notary IS NULL. Rows
	// obtained via a notary always carry keys.
	countKnownServers: `
		SELECT
			COUNT(*) FILTER (WHERE rs.obtained_via_notary IS NULL AND EXISTS (
				SELECT 1 FROM remote_keys rk WHERE rk.server_name = rs.server_name)),
			COUNT(*) FILTER (WHERE rs.obtained_via_notary IS NOT NULL),
			COUNT(*) FILTER (WHERE rs.obtained_via_notary IS NULL AND NOT EXISTS (
				SELECT 1 FROM remote_keys rk WHERE rk.server_name = rs.server_name))
		FROM remote_servers rs;`,
}
