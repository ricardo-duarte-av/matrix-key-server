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
	"encoding/json"

	"github.com/t2bot/matrix-key-server/db/models"
)

func GetAllOwnKeys() ([]*models.OwnKey, error) {
	r, err := statements[selectAllSelfKeys].Query()
	if err == sql.ErrNoRows {
		return make([]*models.OwnKey, 0), nil
	}
	if err != nil {
		return nil, err
	}

	var results []*models.OwnKey
	for r.Next() {
		v := &models.OwnKey{}
		err = r.Scan(&v.ID, &v.PublicKey, &v.PrivateKey, &v.ExpiresTs)
		if err != nil {
			return nil, err
		}
		results = append(results, v)
	}

	return results, nil
}

func GetOwnActiveKeyIds() ([]models.KeyID, error) {
	r, err := statements[selectActiveSelfKeyIds].Query()
	if err == sql.ErrNoRows {
		return make([]models.KeyID, 0), nil
	}
	if err != nil {
		return nil, err
	}

	var results []models.KeyID
	for r.Next() {
		var v models.KeyID
		err = r.Scan(&v)
		if err != nil {
			return nil, err
		}
		results = append(results, v)
	}

	return results, nil
}

func GetOwnKey(id models.KeyID) (*models.OwnKey, error) {
	r := statements[selectSelfKey].QueryRow(id)

	var key = &models.OwnKey{ID: id}

	err := r.Scan(&key.PublicKey, &key.PrivateKey, &key.ExpiresTs)
	if err == sql.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}

	return key, nil
}

func AddOwnActiveKey(id models.KeyID, publicKey models.UnpaddedBase64EncodedData, privateKey models.UnpaddedBase64EncodedData) error {
	_, err := statements[insertActiveSelfKey].Exec(id, publicKey, privateKey)
	if err != nil {
		return err
	}
	return nil
}

func GetRemoteServerMetadata(serverName models.ServerName) (*models.RemoteServer, error) {
	r := statements[selectRemoteServer].QueryRow(serverName)

	var server = &models.RemoteServer{ServerName: serverName}
	var jsonOut string

	err := r.Scan(&server.UpdatedTs, &server.ValidUntilTs, &jsonOut, &server.ObtainedViaNotary,
		&server.OriginFailures, &server.NextOriginAttemptTs)
	if err == sql.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}

	addl := models.AdditionalJSON{}
	err = json.Unmarshal([]byte(jsonOut), &addl)
	if err != nil {
		return nil, err
	}

	server.NonStandardJSON = addl
	return server, nil
}

func UpsertRemoteServer(serverName models.ServerName, updatedTs models.Timestamp, validUntilTs models.Timestamp, additionalJson models.AdditionalJSON, obtainedViaNotary string) error {
	j, err := json.Marshal(additionalJson)
	if err != nil {
		return err
	}
	// Store direct fetches as NULL rather than an empty string.
	var notary sql.NullString
	if obtainedViaNotary != "" {
		notary = sql.NullString{String: obtainedViaNotary, Valid: true}
	}
	_, err = statements[upsertRemoteServer].Exec(serverName, updatedTs, validUntilTs, string(j), notary)
	if err != nil {
		return err
	}
	return nil
}

// NoteOriginFailure records a failed origin probe: the new consecutive failure
// count and when the origin may be probed again. It creates the row when the
// server is not yet known, so a server nobody can resolve is rate-limited from
// its very first failure rather than being re-probed on every request.
func NoteOriginFailure(serverName models.ServerName, updatedTs models.Timestamp, failures int, nextAttemptTs models.Timestamp) error {
	_, err := statements[noteOriginFailure].Exec(serverName, updatedTs, failures, nextAttemptTs)
	return err
}

// GetOriginProbeCandidates returns up to limit servers whose origin is due for
// another probe, oldest due first. These are exactly the servers currently being
// answered from a notary copy or from nothing at all.
func GetOriginProbeCandidates(now models.Timestamp, limit int) ([]models.ServerName, error) {
	rows, err := statements[selectOriginProbeCandidates].Query(now, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	servers := make([]models.ServerName, 0)
	for rows.Next() {
		var s models.ServerName
		if err = rows.Scan(&s); err != nil {
			return nil, err
		}
		servers = append(servers, s)
	}
	return servers, rows.Err()
}

// ResetOriginProbe clears the origin backoff after a successful direct fetch, so
// a server that recovers is treated as healthy again immediately.
func ResetOriginProbe(serverName models.ServerName) error {
	_, err := statements[resetOriginProbe].Exec(serverName)
	return err
}

func DeleteRemoteServerKeys(serverName models.ServerName) error {
	_, err := statements[deleteRemoteKeys].Exec(serverName)
	if err != nil {
		return err
	}
	return nil
}

func DeleteRemoteServerSignatures(serverName models.ServerName) error {
	_, err := statements[deleteRemoteSignatures].Exec(serverName)
	if err != nil {
		return err
	}
	return nil
}

func AddRemoteServerKey(serverName models.ServerName, keyId models.KeyID, publicKey models.UnpaddedBase64EncodedData, expiresTs models.Timestamp) error {
	_, err := statements[insertRemoteKey].Exec(serverName, keyId, publicKey, expiresTs)
	if err != nil {
		return err
	}
	return nil
}

func AddRemoteServerSignature(serverName models.ServerName, keyId models.KeyID, signature models.UnpaddedBase64EncodedData) error {
	_, err := statements[insertRemoteSignature].Exec(serverName, keyId, signature)
	if err != nil {
		return err
	}
	return nil
}

func GetAllRemoteServerKeys(serverName models.ServerName) ([]*models.RemoteKey, error) {
	r, err := statements[selectRemoteKeys].Query(serverName)
	if err == sql.ErrNoRows {
		return make([]*models.RemoteKey, 0), nil
	}
	if err != nil {
		return nil, err
	}

	var results []*models.RemoteKey
	for r.Next() {
		v := &models.RemoteKey{ServerName: serverName}
		err = r.Scan(&v.ID, &v.PublicKey, &v.ExpiresTs)
		if err != nil {
			return nil, err
		}
		results = append(results, v)
	}

	return results, nil
}

// CountKnownServers returns how many cached remote servers we last reached
// directly at their origin, how many we could only reach through a trusted
// notary, and how many neither the origin nor any notary could resolve. The
// three counts partition remote_servers, so they sum to the total number of
// servers we know of.
func CountKnownServers() (direct int64, viaNotary int64, unreachable int64, err error) {
	r := statements[countKnownServers].QueryRow()
	err = r.Scan(&direct, &viaNotary, &unreachable)
	return direct, viaNotary, unreachable, err
}

func GetAllRemoteServerSignatures(serverName models.ServerName) ([]*models.RemoteSignature, error) {
	r, err := statements[selectRemoteSignatures].Query(serverName)
	if err == sql.ErrNoRows {
		return make([]*models.RemoteSignature, 0), nil
	}
	if err != nil {
		return nil, err
	}

	var results []*models.RemoteSignature
	for r.Next() {
		v := &models.RemoteSignature{ServerName: serverName}
		err = r.Scan(&v.KeyID, &v.Signature)
		if err != nil {
			return nil, err
		}
		results = append(results, v)
	}

	return results, nil
}
