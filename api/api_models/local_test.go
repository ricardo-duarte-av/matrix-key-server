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
	"encoding/json"
	"testing"
)

// TestValidateRejectsResponsesWithoutKeyFields covers the crash loop where an
// origin answered /_matrix/key/v2/server with an error document. Because
// ServerKeyResultUnsigned is embedded by pointer, such a body unmarshals without
// error but leaves the embedded struct nil, and the first field access segfaults.
func TestValidateRejectsResponsesWithoutKeyFields(t *testing.T) {
	tests := []struct {
		name    string
		body    string
		wantErr bool
	}{
		{
			// Exactly what pony.cx and matrix.criticalbasics.xyz return.
			name:    "matrix error document",
			body:    `{"errcode":"M_UNRECOGNIZED","error":"Unrecognized request"}`,
			wantErr: true,
		},
		{
			name:    "empty object",
			body:    `{}`,
			wantErr: true,
		},
		{
			name:    "signatures only, no key fields",
			body:    `{"signatures":{"example.org":{"ed25519:abc":"sig"}}}`,
			wantErr: true,
		},
		{
			name:    "key fields present but server_name empty",
			body:    `{"valid_until_ts":123,"verify_keys":{"ed25519:abc":{"key":"AAAA"}}}`,
			wantErr: true,
		},
		{
			name:    "no verify_keys to trust",
			body:    `{"server_name":"example.org","valid_until_ts":123,"verify_keys":{}}`,
			wantErr: true,
		},
		{
			name:    "well-formed response",
			body:    `{"server_name":"example.org","valid_until_ts":123,"verify_keys":{"ed25519:abc":{"key":"AAAA"}}}`,
			wantErr: false,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			keyInfo := ServerKeyResult{}
			if err := json.Unmarshal([]byte(tc.body), &keyInfo); err != nil {
				t.Fatalf("body should unmarshal cleanly, that is the whole trap: %v", err)
			}

			err := keyInfo.Validate()
			if tc.wantErr && err == nil {
				t.Fatalf("Validate() accepted an unusable response")
			}
			if !tc.wantErr && err != nil {
				t.Fatalf("Validate() rejected a good response: %v", err)
			}

			// A validated result must be safe to read fields from - the access
			// that used to panic.
			if err == nil {
				_ = keyInfo.ServerName
			}
		})
	}
}
