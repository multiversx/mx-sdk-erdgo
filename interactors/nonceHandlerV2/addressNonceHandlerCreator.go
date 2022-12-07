package nonceHandlerV2

import (
	"github.com/ElrondNetwork/elrond-sdk-erdgo/core"
	"github.com/ElrondNetwork/elrond-sdk-erdgo/interactors"
)

// AddressNonceHandlerCreator is used to create addressNonceHandler instances
type AddressNonceHandlerCreator struct{}

// Create will create
func (anhc *AddressNonceHandlerCreator) Create(proxy interactors.Proxy, address core.AddressHandler) (interactors.AddressNonceHandler, error) {
	return NewAddressNonceHandler(proxy, address)
}

// IsInterfaceNil returns true if there is no value under the interface
func (anhc *AddressNonceHandlerCreator) IsInterfaceNil() bool {
	return anhc == nil
}
