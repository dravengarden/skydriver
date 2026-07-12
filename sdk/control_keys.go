package sdk

import (
	"encoding/base64"
	"fmt"

	"github.com/dravengarden/carrack/cryptostream"
)

func decodeGrantedEpochKey(encoded, operationKind string) (cryptostream.EpochKey, error) {
	decoded, err := base64.RawURLEncoding.DecodeString(encoded)
	if err != nil || len(decoded) != len(cryptostream.EpochKey{}) {
		return cryptostream.EpochKey{}, fmt.Errorf(
			"%w: invalid %s epoch key",
			ErrControlPlaneResponse,
			operationKind,
		)
	}

	var combined byte
	for _, value := range decoded {
		combined |= value
	}

	if combined == 0 {
		return cryptostream.EpochKey{}, fmt.Errorf(
			"%w: zero %s epoch key",
			ErrControlPlaneResponse,
			operationKind,
		)
	}

	return cryptostream.EpochKey(decoded), nil
}
