package blockchain

import (
	"bytes"

	mxChainCore "github.com/multiversx/mx-chain-core-go/core"
	"github.com/multiversx/mx-chain-core-go/core/check"
	"github.com/multiversx/mx-chain-core-go/data/typeConverters/uint64ByteSlice"
	"github.com/multiversx/mx-chain-core-go/hashing"
	"github.com/multiversx/mx-chain-core-go/hashing/keccak"
	"github.com/multiversx/mx-chain-core-go/marshal"
	"github.com/multiversx/mx-chain-go/process"
	"github.com/multiversx/mx-chain-go/process/factory"
	"github.com/multiversx/mx-chain-go/process/smartContract/hooks"
	"github.com/multiversx/mx-sdk-go/core"
	"github.com/multiversx/mx-sdk-go/data"
	"github.com/multiversx/mx-sdk-go/disabled"
	"github.com/multiversx/mx-sdk-go/storage"
)

const accountStartNonce = uint64(0)

var initialDNSAddress = bytes.Repeat([]byte{1}, 32)

// addressGenerator is used to generate some addresses based on mx-chain-go logic
type addressGenerator struct {
	coordinator    *shardCoordinator
	blockChainHook process.BlockChainHookHandler
	hasher         hashing.Hasher
}

// NewAddressGenerator will create an address generator instance
func NewAddressGenerator(coordinator *shardCoordinator) (*addressGenerator, error) {
	if check.IfNil(coordinator) {
		return nil, ErrNilShardCoordinator
	}

	builtInFuncs := &disabled.BuiltInFunctionContainer{}

	var argsHook = hooks.ArgBlockChainHook{
		Accounts:              &disabled.Accounts{},
		PubkeyConv:            core.AddressPublicKeyConverter,
		StorageService:        &disabled.StorageService{},
		BlockChain:            &disabled.Blockchain{},
		ShardCoordinator:      &disabled.ShardCoordinator{},
		Marshalizer:           &marshal.JsonMarshalizer{},
		Uint64Converter:       uint64ByteSlice.NewBigEndianConverter(),
		BuiltInFunctions:      builtInFuncs,
		DataPool:              &disabled.DataPool{},
		CompiledSCPool:        storage.NewMapCacher(),
		NilCompiledSCStore:    true,
		NFTStorageHandler:     &disabled.SimpleESDTNFTStorageHandler{},
		EpochNotifier:         &disabled.EpochNotifier{},
		GlobalSettingsHandler: &disabled.GlobalSettingsHandler{},
		EnableEpochsHandler:   &disabled.EnableEpochsHandler{},
		GasSchedule:           &disabled.GasScheduleNotifier{},
		Counter:               &disabled.BlockChainHookCounter{},
	}
	blockchainHook, err := hooks.NewBlockChainHookImpl(argsHook)
	if err != nil {
		return nil, err
	}

	return &addressGenerator{
		coordinator:    coordinator,
		blockChainHook: blockchainHook,
		hasher:         keccak.NewKeccak(),
	}, nil
}

// CompatibleDNSAddress will return the compatible DNS address providing the shard ID
func (ag *addressGenerator) CompatibleDNSAddress(shardId byte) (core.AddressHandler, error) {
	addressLen := len(initialDNSAddress)
	shardInBytes := []byte{0, shardId}

	newDNSPk := string(initialDNSAddress[:(addressLen-mxChainCore.ShardIdentiferLen)]) + string(shardInBytes)
	newDNSAddress, err := ag.blockChainHook.NewAddress([]byte(newDNSPk), accountStartNonce, factory.WasmVirtualMachine)
	if err != nil {
		return nil, err
	}

	return data.NewAddressFromBytes(newDNSAddress), err
}

// CompatibleDNSAddressFromUsername will return the compatible DNS address providing the username
func (ag *addressGenerator) CompatibleDNSAddressFromUsername(username string) (core.AddressHandler, error) {
	hash := ag.hasher.Compute(username)
	lastByte := hash[len(hash)-1]
	return ag.CompatibleDNSAddress(lastByte)
}

// ComputeArwenScAddress will return the smart contract address that will be generated by the Arwen VM providing
// the owner's address & nonce
func (ag *addressGenerator) ComputeArwenScAddress(address core.AddressHandler, nonce uint64) (core.AddressHandler, error) {
	if check.IfNil(address) {
		return nil, ErrNilAddress
	}

	scAddressBytes, err := ag.blockChainHook.NewAddress(address.AddressBytes(), nonce, factory.WasmVirtualMachine)
	if err != nil {
		return nil, err
	}

	return data.NewAddressFromBytes(scAddressBytes), nil
}
