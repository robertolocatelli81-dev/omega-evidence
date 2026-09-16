//go:build !go1.27

package oeverify

const PQSupported = false

func mldsaVerify(pkRaw, msg, sig []byte) bool { return false }
