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

package keys

import (
	"crypto/rand"
	"encoding/json"
	"testing"

	"github.com/t2bot/matrix-key-server/api/api_models"
	"github.com/t2bot/matrix-key-server/db/models"
	"github.com/t2bot/matrix-key-server/signing"
	"golang.org/x/crypto/ed25519"
)

const (
	testTarget      = "deadserver.example"
	testNotary      = "matrix.org"
	testOriginKeyId = "ed25519:origin"
	testNotaryKeyId = "ed25519:notary"
)

func genKey(t *testing.T) (ed25519.PublicKey, ed25519.PrivateKey) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("failed to generate key: %v", err)
	}
	return pub, priv
}

// buildNotaryResponse constructs a server-key object for testTarget, optionally
// signed by the origin and/or the notary, and returns the parsed struct + raw JSON
// as verifyNotaryResult would receive them.
func buildNotaryResponse(t *testing.T, originPub ed25519.PublicKey, originPriv ed25519.PrivateKey, signOrigin bool, notaryPriv ed25519.PrivateKey, signNotary bool) (api_models.ServerKeyResult, json.RawMessage) {
	obj := map[string]interface{}{
		"server_name":    testTarget,
		"valid_until_ts": int64(1600000000000),
		"verify_keys": map[string]interface{}{
			testOriginKeyId: map[string]interface{}{
				"key": signing.EncodeUnpaddedBase64ToString(originPub),
			},
		},
		"old_verify_keys": map[string]interface{}{},
	}

	signed := obj
	var err error
	if signOrigin {
		signed, err = signing.SignObject(signed, testTarget, models.KeyID(testOriginKeyId), originPriv)
		if err != nil {
			t.Fatalf("origin sign failed: %v", err)
		}
	}
	if signNotary {
		signed, err = signing.SignObject(signed, testNotary, models.KeyID(testNotaryKeyId), notaryPriv)
		if err != nil {
			t.Fatalf("notary sign failed: %v", err)
		}
	}

	raw, err := json.Marshal(signed)
	if err != nil {
		t.Fatalf("marshal failed: %v", err)
	}
	keyInfo := api_models.ServerKeyResult{}
	if err = json.Unmarshal(raw, &keyInfo); err != nil {
		t.Fatalf("unmarshal failed: %v", err)
	}
	return keyInfo, raw
}

func TestVerifyNotaryResult_Valid(t *testing.T) {
	originPub, originPriv := genKey(t)
	notaryPub, notaryPriv := genKey(t)
	keyInfo, raw := buildNotaryResponse(t, originPub, originPriv, true, notaryPriv, true)
	notaryPubKeys := map[string]ed25519.PublicKey{testNotaryKeyId: notaryPub}

	verified, _, err := verifyNotaryResult(testNotary, keyInfo, raw, notaryPubKeys)
	if err != nil {
		t.Fatalf("expected success, got: %v", err)
	}

	// Re-sign-only: the notary's signature must be dropped, the origin's kept.
	if _, ok := verified.Signatures[testNotary]; ok {
		t.Error("notary signature should have been stripped from the stored result")
	}
	if len(verified.Signatures[testTarget]) == 0 {
		t.Error("origin self-signature should have been kept")
	}
}

func TestVerifyNotaryResult_MissingNotarySignature(t *testing.T) {
	originPub, originPriv := genKey(t)
	notaryPub, _ := genKey(t)
	// Origin-signed only: no notary counter-signature.
	keyInfo, raw := buildNotaryResponse(t, originPub, originPriv, true, nil, false)
	notaryPubKeys := map[string]ed25519.PublicKey{testNotaryKeyId: notaryPub}

	if _, _, err := verifyNotaryResult(testNotary, keyInfo, raw, notaryPubKeys); err == nil {
		t.Fatal("expected rejection when the notary did not sign, got nil")
	}
}

func TestVerifyNotaryResult_MissingOriginSignature(t *testing.T) {
	originPub, _ := genKey(t)
	_, notaryPriv := genKey(t)
	notaryPub := notaryPriv.Public().(ed25519.PublicKey)
	// Notary-signed only: no origin self-signature.
	keyInfo, raw := buildNotaryResponse(t, originPub, nil, false, notaryPriv, true)
	notaryPubKeys := map[string]ed25519.PublicKey{testNotaryKeyId: notaryPub}

	if _, _, err := verifyNotaryResult(testNotary, keyInfo, raw, notaryPubKeys); err == nil {
		t.Fatal("expected rejection when the origin did not self-sign, got nil")
	}
}

func TestVerifyNotaryResult_WrongNotaryKey(t *testing.T) {
	originPub, originPriv := genKey(t)
	_, notaryPriv := genKey(t)
	keyInfo, raw := buildNotaryResponse(t, originPub, originPriv, true, notaryPriv, true)

	// A different key is presented as the notary's, so its signature must fail.
	wrongPub, _ := genKey(t)
	notaryPubKeys := map[string]ed25519.PublicKey{testNotaryKeyId: wrongPub}

	if _, _, err := verifyNotaryResult(testNotary, keyInfo, raw, notaryPubKeys); err == nil {
		t.Fatal("expected rejection when the notary key does not match, got nil")
	}
}

func TestNotaryVerifyKeys_IncludesExpired(t *testing.T) {
	currentPub, _ := genKey(t)
	oldPub, _ := genKey(t)
	cached := &models.CachedRemoteKeys{
		Keys: []*models.RemoteKey{
			{ID: "ed25519:current", PublicKey: models.UnpaddedBase64EncodedData(signing.EncodeUnpaddedBase64ToString(currentPub)), ExpiresTs: 0},
			{ID: "ed25519:old", PublicKey: models.UnpaddedBase64EncodedData(signing.EncodeUnpaddedBase64ToString(oldPub)), ExpiresTs: 1576767829750},
		},
	}

	out, err := notaryVerifyKeys(cached)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	// A notary that cached a long-dead server may have counter-signed with a key
	// that has since expired, so old_verify_keys must be usable for verification.
	if _, ok := out["ed25519:old"]; !ok {
		t.Error("expired notary key should be included for verification")
	}
	if _, ok := out["ed25519:current"]; !ok {
		t.Error("current notary key should be included for verification")
	}
}

func TestVerifyNotaryResult_TamperedPayload(t *testing.T) {
	originPub, originPriv := genKey(t)
	notaryPub, notaryPriv := genKey(t)
	keyInfo, raw := buildNotaryResponse(t, originPub, originPriv, true, notaryPriv, true)
	notaryPubKeys := map[string]ed25519.PublicKey{testNotaryKeyId: notaryPub}

	// Tamper with the payload after signing; both signatures must now fail.
	keyInfo.ValidUntilTs += 1

	if _, _, err := verifyNotaryResult(testNotary, keyInfo, raw, notaryPubKeys); err == nil {
		t.Fatal("expected rejection when the payload was tampered, got nil")
	}
}
