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

import "testing"

func TestCanServeCachedKeys(t *testing.T) {
	const now = int64(1_000_000_000_000)
	const day = int64(86_400_000)

	tests := []struct {
		name         string
		updatedTs    int64
		validUntilTs int64
		minValidTs   int64
		want         bool
	}{
		{
			name:         "fresh keys with future validity are served",
			updatedTs:    now - day,      // fetched yesterday
			validUntilTs: now + 10*day,   // valid well into the future
			minValidTs:   now,
			want:         true,
		},
		{
			name:         "halfway-dead cache is refetched once cooldown elapsed",
			updatedTs:    now - 2*3600_000, // last tried 2h ago (> 1h cooldown)
			validUntilTs: now - day,        // already expired
			minValidTs:   now,
			want:         false,
		},
		{
			name:         "expired keys are still served during the cooldown",
			updatedTs:    now - 60_000, // tried 1 minute ago
			validUntilTs: now - day,    // expired: the dead-server case
			minValidTs:   now,
			want:         true,
		},
		{
			name:         "caller minimum higher than cache is served during cooldown",
			updatedTs:    now - 60_000,
			validUntilTs: now + day, // not expired, but below the caller's minimum
			minValidTs:   now + 5*day,
			want:         true,
		},
		{
			name:         "caller minimum higher than cache is refetched after cooldown",
			updatedTs:    now - 2*3600_000,
			validUntilTs: now + day,
			minValidTs:   now + 5*day,
			want:         false,
		},
		{
			name:         "record beyond 7-day lifespan is refetched",
			updatedTs:    now - 8*day, // older than remoteKeyLifespanMs
			validUntilTs: now + 10*day,
			minValidTs:   now,
			want:         false,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := canServeCachedKeys(tc.updatedTs, tc.validUntilTs, tc.minValidTs, now)
			if got != tc.want {
				t.Errorf("canServeCachedKeys(updated=%d, valid=%d, min=%d, now=%d) = %v, want %v",
					tc.updatedTs, tc.validUntilTs, tc.minValidTs, now, got, tc.want)
			}
		})
	}
}
