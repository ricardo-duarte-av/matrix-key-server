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

package models

type KeyID string
type UnpaddedBase64EncodedData string
type Timestamp int64
type ServerName string
type AdditionalJSON map[string]interface{}

type OwnKey struct {
	ID         KeyID
	PublicKey  UnpaddedBase64EncodedData
	PrivateKey UnpaddedBase64EncodedData
	ExpiresTs  Timestamp
}

type RemoteServer struct {
	ServerName      ServerName
	UpdatedTs       Timestamp
	ValidUntilTs    Timestamp
	NonStandardJSON AdditionalJSON

	// ObtainedViaNotary is empty when these keys were fetched directly from the
	// origin server, or the server_name of the trusted notary they were fetched
	// through when the origin was unreachable.
	ObtainedViaNotary string
}

type RemoteKey struct {
	ServerName ServerName
	ID         KeyID
	PublicKey  UnpaddedBase64EncodedData
	ExpiresTs  Timestamp
}

type RemoteSignature struct {
	ServerName ServerName
	KeyID      KeyID
	Signature  UnpaddedBase64EncodedData
}

type CachedRemoteKeys struct {
	*RemoteServer
	Signatures []*RemoteSignature
	Keys       []*RemoteKey
}
