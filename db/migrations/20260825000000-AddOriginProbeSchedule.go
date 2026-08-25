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

package migrations

import (
	"database/sql"
)

// Up20260825000000AddOriginProbeSchedule records when we may next probe a
// server's origin, and how many consecutive times it has failed.
//
// These describe the origin's *reachability*, never the key data we hold, and
// nothing on the serving path reads them. Keeping them separate is the point:
// obtained_via_notary previously doubled as a "this server is gone" signal, so a
// single transient 502 from a live server froze it out of origin re-checks for a
// day. Reachability now has its own state, and the keys stay whatever they are.
func Up20260825000000AddOriginProbeSchedule(db *sql.DB) error {
	_, err := db.Exec("ALTER TABLE remote_servers ADD COLUMN origin_failures INT NOT NULL DEFAULT 0;")
	if err != nil {
		return err
	}
	_, err = db.Exec("ALTER TABLE remote_servers ADD COLUMN next_origin_attempt_ts BIGINT NOT NULL DEFAULT 0;")
	return err
}
