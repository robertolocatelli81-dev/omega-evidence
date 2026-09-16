//go:build go1.27

package oeverify

import "crypto/mldsa"

const PQSupported = true

// mldsaVerify: pure ML-DSA-65, EMPTY context (the profile; JDK/KMS-compatible), Go >= 1.27 standard library.
func mldsaVerify(pkRaw, msg, sig []byte) bool {
	pub, err := mldsa.NewPublicKey(mldsa.MLDSA65(), pkRaw)
	if err != nil {
		return false
	}
	return mldsa.Verify(pub, msg, sig, nil) == nil
}
