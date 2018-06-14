/*
 * Copyright (c) 2018 Miguel Ángel Ortuño.
 * See the LICENSE file for more information.
 */

package s2s

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
)

func dialbackKey(to, from, streamID, secret string) string {
	h := sha256.New()
	h.Write([]byte(secret))
	hm := hmac.New(sha256.New, []byte(hex.EncodeToString(h.Sum(nil))))
	hm.Write([]byte(fmt.Sprintf("%s %s %s", to, from, streamID)))
	return hex.EncodeToString(hm.Sum(nil))
}
