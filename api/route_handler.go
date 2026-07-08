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

package api

import (
	"encoding/json"
	"fmt"
	"net/http"
	"time"

	"github.com/sirupsen/logrus"
	"github.com/t2bot/matrix-key-server/api/common"
	"github.com/t2bot/matrix-key-server/metrics"
)

type handler struct {
	h      func(r *http.Request, entry *logrus.Entry) interface{}
	action string
}

func (h handler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	start := time.Now()
	contextLog := logrus.WithFields(logrus.Fields{
		"method":   r.Method,
		"host":     r.Host,
		"resource": r.URL.Path,
	})
	contextLog.Info("Received request")

	w.Header().Set("Server", "matrix-key-server")

	// Process response
	res := h.h(r, contextLog)
	if res == nil {
		res = &common.EmptyResponse{}
	}

	contextLog.Info(fmt.Sprintf("Replying with result: %T %+v", res, res))

	statusCode := http.StatusOK
	if errResp, ok := res.(*common.ErrorResponse); ok {
		statusCode = errResp.HttpStatus
	}

	// Order is important: Set headers before sending responses
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(statusCode)

	encoder := json.NewEncoder(w)
	if err := encoder.Encode(res); err != nil {
		contextLog.Warnf("Failed to encode response: %v", err)
	}

	metrics.ObserveHTTPRequest(h.action, r.Method, statusCode, time.Since(start))
}
