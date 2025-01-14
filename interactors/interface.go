package interactors

import (
	"context"

	"github.com/multiversx/mx-chain-core-go/data/transaction"
	"github.com/multiversx/mx-sdk-go/core"
	"github.com/multiversx/mx-sdk-go/data"
)

// Proxy holds the primitive functions that the multiversx proxy engine supports & implements
// dependency inversion: blockchain package is considered inner business logic, this package is considered "plugin"
type Proxy interface {
	GetNetworkConfig(ctx context.Context) (*data.NetworkConfig, error)
	GetAccount(ctx context.Context, address core.AddressHandler) (*data.Account, error)
	SendTransaction(ctx context.Context, tx *transaction.FrontendTransaction) (string, error)
	SendTransactions(ctx context.Context, txs []*transaction.FrontendTransaction) ([]string, error)
	IsInterfaceNil() bool
}

// TxBuilder defines the component able to build & sign a transaction
type TxBuilder interface {
	ApplyUserSignature(cryptoHolder core.CryptoComponentsHolder, tx *transaction.FrontendTransaction) error
	ApplyGuardianSignature(cryptoHolderGuardian core.CryptoComponentsHolder, tx *transaction.FrontendTransaction) error
	ApplyRelayerSignature(relayerCryptoHolder core.CryptoComponentsHolder, tx *transaction.FrontendTransaction) error
	IsInterfaceNil() bool
}

// AddressNonceHandler defines the component able to handler address nonces
type AddressNonceHandler interface {
	ApplyNonceAndGasPrice(ctx context.Context, tx *transaction.FrontendTransaction) error
	ReSendTransactionsIfRequired(ctx context.Context) error
	SendTransaction(ctx context.Context, tx *transaction.FrontendTransaction) (string, error)
	DropTransactions()
	IsInterfaceNil() bool
}

// TransactionNonceHandlerV1 defines the component able to manage transaction nonces
type TransactionNonceHandlerV1 interface {
	GetNonce(ctx context.Context, address core.AddressHandler) (uint64, error)
	SendTransaction(ctx context.Context, tx *transaction.FrontendTransaction) (string, error)
	ForceNonceReFetch(address core.AddressHandler) error
	Close() error
	IsInterfaceNil() bool
}

// TransactionNonceHandlerV2 defines the component able to apply nonce for a given frontend transaction
type TransactionNonceHandlerV2 interface {
	ApplyNonceAndGasPrice(ctx context.Context, address core.AddressHandler, tx *transaction.FrontendTransaction) error
	SendTransaction(ctx context.Context, tx *transaction.FrontendTransaction) (string, error)
	Close() error
	IsInterfaceNil() bool
}
