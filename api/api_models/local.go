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

package api_models

import (
	"errors"

	"github.com/t2bot/matrix-key-server/db/models"
)

type Signatures map[string]map[string]string

type VerifyKey struct {
	Key models.UnpaddedBase64EncodedData `json:"key"`
}

type OldVerifyKey struct {
	Key       models.UnpaddedBase64EncodedData `json:"key"`
	ExpiredTs models.Timestamp                 `json:"expired_ts"`
}

type ServerKeyResult struct {
	*ServerKeyResultUnsigned
	Signatures Signatures `json:"signatures"`
}

type ServerKeyResultUnsigned struct {
	ServerName    string                        `json:"server_name"`
	ValidUntilTs  int64                         `json:"valid_until_ts"`
	VerifyKeys    map[models.KeyID]VerifyKey    `json:"verify_keys"`
	OldVerifyKeys map[models.KeyID]OldVerifyKey `json:"old_verify_keys"`
}

// Validate reports whether a decoded server-key object is structurally usable.
//
// ServerKeyResultUnsigned is embedded by pointer, and encoding/json only
// allocates it when the payload carries at least one of its fields. A response
// that carries none - an error body like {"errcode":"M_UNRECOGNIZED",...}, or a
// bare {} - therefore unmarshals "successfully" into a result whose embedded
// pointer is nil, and the first field access panics. Callers must run every
// freshly-unmarshalled result through this before touching its fields.
func (r *ServerKeyResult) Validate() error {
	if r.ServerKeyResultUnsigned == nil {
		return errors.New("response carries no server key fields")
	}
	if r.ServerName == "" {
		return errors.New("response has an empty server_name")
	}
	if len(r.VerifyKeys) == 0 {
		return errors.New("response has no verify_keys")
	}
	return nil
}
