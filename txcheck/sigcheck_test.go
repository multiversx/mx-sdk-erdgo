package txcheck_test

import (
	"encoding/hex"
	"math/big"
	"testing"

	"github.com/multiversx/mx-chain-core-go/data/transaction"
	"github.com/multiversx/mx-chain-core-go/hashing/keccak"
	marshallerFactory "github.com/multiversx/mx-chain-core-go/marshal/factory"
	"github.com/multiversx/mx-chain-crypto-go/signing"
	"github.com/multiversx/mx-chain-crypto-go/signing/ed25519"
	"github.com/multiversx/mx-sdk-go/blockchain/cryptoProvider"
	"github.com/multiversx/mx-sdk-go/builders"
	"github.com/multiversx/mx-sdk-go/core"
	"github.com/multiversx/mx-sdk-go/interactors"
	"github.com/multiversx/mx-sdk-go/txcheck"
	"github.com/stretchr/testify/require"
)

func Test_VerifyTransactionSignature(t *testing.T) {
	signer := cryptoProvider.NewSigner()

	userCryptoHolder, guardianCryptoHolder := createUserAndGuardianKeys(t)

	builder, err := builders.NewTxBuilder(signer)
	require.Nil(t, err)

	tx := createFrontendTransaction()
	signature, signatureGuardian, err := signTransaction(userCryptoHolder, guardianCryptoHolder, &tx, builder)
	require.Nil(t, err)

	txArgHashSigning := tx
	txArgHashSigning.Options |= transaction.MaskSignedWithHash
	txArgHashSigning.Version = 2

	txHashSign := tx // copy
	signatureOnHash, signatureGuardianOnHash, err := signTransaction(userCryptoHolder, guardianCryptoHolder, &txHashSign, builder)
	require.Nil(t, err)

	marshaller, err := marshallerFactory.NewMarshalizer(marshallerFactory.JsonMarshalizer)
	require.Nil(t, err)

	hasher := keccak.NewKeccak()
	require.Nil(t, err)

	t.Run("nil transaction should err", func(t *testing.T) {
		err = txcheck.VerifyTransactionSignature(nil, userCryptoHolder.GetPublicKey(), signature, signer, marshaller, hasher)
		require.Equal(t, txcheck.ErrNilTransaction, err)
	})
	t.Run("nil public key should err", func(t *testing.T) {
		err = txcheck.VerifyTransactionSignature(&tx, nil, signature, signer, marshaller, hasher)
		require.Equal(t, txcheck.ErrNilPubKey, err)
	})
	t.Run("nil signature should err", func(t *testing.T) {
		err = txcheck.VerifyTransactionSignature(&tx, userCryptoHolder.GetPublicKey(), nil, signer, marshaller, hasher)
		require.Equal(t, txcheck.ErrNilSignature, err)
	})
	t.Run("nil verifier should err", func(t *testing.T) {
		err = txcheck.VerifyTransactionSignature(&tx, userCryptoHolder.GetPublicKey(), signature, nil, marshaller, hasher)
		require.Equal(t, txcheck.ErrNilSignatureVerifier, err)
	})
	t.Run("nil marshaller should err", func(t *testing.T) {
		err = txcheck.VerifyTransactionSignature(&tx, userCryptoHolder.GetPublicKey(), signature, signer, nil, hasher)
		require.Equal(t, txcheck.ErrNilMarshaller, err)
	})
	t.Run("nil hasher should err", func(t *testing.T) {
		err = txcheck.VerifyTransactionSignature(&tx, userCryptoHolder.GetPublicKey(), signature, signer, marshaller, nil)
		require.Equal(t, txcheck.ErrNilHasher, err)
	})
	t.Run("verify user signature OK", func(t *testing.T) {
		err = txcheck.VerifyTransactionSignature(&tx, userCryptoHolder.GetPublicKey(), signature, signer, marshaller, hasher)
		require.Nil(t, err)
	})
	t.Run("verify user signature OK with hashSigning", func(t *testing.T) {
		err = txcheck.VerifyTransactionSignature(&txHashSign, userCryptoHolder.GetPublicKey(), signatureOnHash, signer, marshaller, hasher)
		require.Nil(t, err)
	})
	t.Run("verify guardian signature OK", func(t *testing.T) {
		err = txcheck.VerifyTransactionSignature(&tx, guardianCryptoHolder.GetPublicKey(), signatureGuardian, signer, marshaller, hasher)
		require.Nil(t, err)
	})
	t.Run("verify guardian signature OK with hashSigning", func(t *testing.T) {
		err = txcheck.VerifyTransactionSignature(&txHashSign, guardianCryptoHolder.GetPublicKey(), signatureGuardianOnHash, signer, marshaller, hasher)
		require.Nil(t, err)
	})
}

func createUserAndGuardianKeys(t *testing.T) (cryptoHolderUser core.CryptoComponentsHolder, cryptoHolderGuardian core.CryptoComponentsHolder) {
	suite := ed25519.NewEd25519()
	keyGen := signing.NewKeyGenerator(suite)

	skUser, err := hex.DecodeString("6ae10fed53a84029e53e35afdbe083688eea0917a09a9431951dd42fd4da14c4")
	require.Nil(t, err)

	skGuardian, err := hex.DecodeString("28654d9264f55f18d810bb88617e22c117df94fa684dfe341a511a72dfbf2b68")
	require.Nil(t, err)

	cryptoHolderUser, err = cryptoProvider.NewCryptoComponentsHolder(keyGen, skUser)
	require.Nil(t, err)

	cryptoHolderGuardian, err = cryptoProvider.NewCryptoComponentsHolder(keyGen, skGuardian)
	require.Nil(t, err)

	return
}

func createFrontendTransaction() transaction.FrontendTransaction {
	value := big.NewInt(999)
	txArg := transaction.FrontendTransaction{
		Value:        value.String(),
		Receiver:     "erd1l20m7kzfht5rhdnd4zvqr82egk7m4nvv3zk06yw82zqmrt9kf0zsf9esqq",
		GasPrice:     10,
		GasLimit:     100000,
		Data:         []byte(""),
		ChainID:      "chain id",
		Version:      uint32(1),
		GuardianAddr: "erd1lta2vgd0tkeqqadkvgef73y0efs6n3xe5ss589ufhvmt6tcur8kq34qkwr",
		Options:      transaction.MaskGuardedTransaction,
	}

	return txArg
}

func signTransaction(
	cryptoHolderUser core.CryptoComponentsHolder,
	cryptoHolderGuardian core.CryptoComponentsHolder,
	tx *transaction.FrontendTransaction,
	builder interactors.TxBuilder,
) (sigUser []byte, sigGuardian []byte, err error) {
	err = builder.ApplyUserSignature(cryptoHolderUser, tx)
	if err != nil {
		return nil, nil, err
	}

	err = builder.ApplyGuardianSignature(cryptoHolderGuardian, tx)
	if err != nil {
		return nil, nil, err
	}

	signatureGuardian, err := hex.DecodeString(tx.GuardianSignature)
	if err != nil {
		return nil, nil, err
	}

	signature, err := hex.DecodeString(tx.Signature)
	if err != nil {
		return nil, nil, err
	}

	return signature, signatureGuardian, nil
}
