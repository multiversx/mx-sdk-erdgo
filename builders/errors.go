package builders

import "errors"

// ErrInvalidValue signals that an invalid value was provided
var ErrInvalidValue = errors.New("invalid value")

// ErrNilValue signals that a nil value was provided
var ErrNilValue = errors.New("nil value")

// ErrNilAddress signals that a nil address was provided
var ErrNilAddress = errors.New("nil address handler")

// ErrInvalidAddress signals that an invalid address was provided
var ErrInvalidAddress = errors.New("invalid address handler")

// ErrNilSigner signals that a nil transaction signer was provided
var ErrNilSigner = errors.New("nil signer")

// ErrNilCryptoComponentsHolder signals that a nil crypto components holder was provided
var ErrNilCryptoComponentsHolder = errors.New("nil crypto components holder")

// ErrMissingSignature signals that a transaction's signature is empty when trying to compute it's hash
var ErrMissingSignature = errors.New("missing signature when computing the transaction's hash")

// ErrNilInnerTransaction signals that a nil inner transaction was provided
var ErrNilInnerTransaction = errors.New("nil inner transaction")

// ErrNilRelayerAccount signals that a nil relayer account was provided
var ErrNilRelayerAccount = errors.New("nil relayer account")

// ErrNilNetworkConfig signals that a nil network config was provided
var ErrNilNetworkConfig = errors.New("nil network config")

// ErrNilInnerTransactionSignature signals that a nil inner transaction signature was provided
var ErrNilInnerTransactionSignature = errors.New("nil inner transaction signature")

// ErrInvalidGasLimitNeededForInnerTransaction signals that an invalid gas limit needed for the inner transaction was provided
var ErrInvalidGasLimitNeededForInnerTransaction = errors.New("invalid gas limit needed for inner transaction")

// ErrGasLimitForInnerTransactionV2ShouldBeZero signals that the gas limit for the inner transaction should be zero
var ErrGasLimitForInnerTransactionV2ShouldBeZero = errors.New("gas limit of the inner transaction should be 0")

// ErrInvalidValueForInnerTransaction signals that the inner transaction value for relayed tx v2 should be 0
var ErrInvalidValueForInnerTransaction = errors.New("value of the inner transaction should be 0")

// ErrMissingGuardianOption signals that the guardian flag is missing in the transaction option field
var ErrMissingGuardianOption = errors.New("guardian flag is missing in the option field")

// ErrGuardianDoesNotMatch signals a mismatch between the configured guardian in tx and the signing guardian address
var ErrGuardianDoesNotMatch = errors.New("configured guardian does not match signing guardian")
