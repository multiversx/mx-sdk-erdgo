package builders

import (
	"encoding/hex"
	"errors"
	"math/big"
	"testing"

	"github.com/multiversx/mx-chain-core-go/core/check"
	"github.com/multiversx/mx-chain-core-go/data/transaction"
	crypto "github.com/multiversx/mx-chain-crypto-go"
	"github.com/multiversx/mx-chain-crypto-go/signing"
	"github.com/multiversx/mx-chain-crypto-go/signing/ed25519"
	"github.com/multiversx/mx-sdk-go/blockchain/cryptoProvider"
	"github.com/multiversx/mx-sdk-go/testsCommon"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

var (
	suite  = ed25519.NewEd25519()
	keyGen = signing.NewKeyGenerator(suite)
)

func TestNewTxBuilder(t *testing.T) {
	t.Parallel()

	t.Run("nil signer should error", func(t *testing.T) {
		t.Parallel()

		tb, err := NewTxBuilder(nil)
		assert.True(t, check.IfNil(tb))
		assert.Equal(t, ErrNilSigner, err)
	})
	t.Run("should work", func(t *testing.T) {
		t.Parallel()

		tb, err := NewTxBuilder(&testsCommon.SignerStub{})
		assert.False(t, check.IfNil(tb))
		assert.Nil(t, err)
	})
}

func TestTxBuilder_ApplySignature(t *testing.T) {
	t.Parallel()

	sk, err := hex.DecodeString("6ae10fed53a84029e53e35afdbe083688eea0917a09a9431951dd42fd4da14c40d248169f4dd7c90537f05be1c49772ddbf8f7948b507ed17fb23284cf218b7d")
	require.Nil(t, err)
	cryptoHolder, err := cryptoProvider.NewCryptoComponentsHolder(keyGen, sk)
	require.Nil(t, err)
	value := big.NewInt(999)
	tx := transaction.FrontendTransaction{
		Value:    value.String(),
		Receiver: "erd1l20m7kzfht5rhdnd4zvqr82egk7m4nvv3zk06yw82zqmrt9kf0zsf9esqq",
		GasPrice: 10,
		GasLimit: 100000,
		Data:     []byte(""),
		ChainID:  "integration test chain id",
		Version:  uint32(1),
	}

	t.Run("tx signer errors when signing should error", func(t *testing.T) {
		t.Parallel()

		txCopy := tx
		expectedErr := errors.New("expected error")
		tb, _ := NewTxBuilder(&testsCommon.SignerStub{
			SignByteSliceCalled: func(_ []byte, _ crypto.PrivateKey) ([]byte, error) {
				return nil, expectedErr
			},
		})

		errGenerate := tb.ApplyUserSignature(cryptoHolder, &txCopy)
		assert.Empty(t, txCopy.Signature)
		assert.Equal(t, expectedErr, errGenerate)
	})

	signer := cryptoProvider.NewSigner()
	tb, err := NewTxBuilder(signer)
	require.Nil(t, err)

	t.Run("sign on all tx bytes should work", func(t *testing.T) {
		t.Parallel()

		txCopy := tx
		errGenerate := tb.ApplyUserSignature(cryptoHolder, &txCopy)
		require.Nil(t, errGenerate)

		assert.Equal(t, "erd1p5jgz605m47fq5mlqklpcjth9hdl3au53dg8a5tlkgegfnep3d7stdk09x", txCopy.Sender)
		assert.Equal(t, "80e1b5476c5ea9567614d9c364e1a7380b7990b53e7b6fd8431bf8536d174c8b3e73cc354b783a03e5ae0a53b128504a6bcf32c3b9bbc06f284afe1fac179e0d",
			txCopy.Signature)
	})
	t.Run("sign on tx hash should work", func(t *testing.T) {
		t.Parallel()

		txCopy := tx
		txCopy.Version = 2
		txCopy.Options = 1

		errGenerate := tb.ApplyUserSignature(cryptoHolder, &txCopy)
		require.Nil(t, errGenerate)

		assert.Equal(t, "erd1p5jgz605m47fq5mlqklpcjth9hdl3au53dg8a5tlkgegfnep3d7stdk09x", txCopy.Sender)
		assert.Equal(t, "1761bcac651a65839b53e89f6b0738e0956cb12e8624826b98bfc577c9f8d5e36a2544a9c5445ce7d5059972b2c5f42e25f3ad9f59255465a2ba128f0764b90e",
			txCopy.Signature)
	})
}

func TestTxBuilder_ApplySignatureAndGenerateTxHash(t *testing.T) {
	t.Parallel()

	sk, err := hex.DecodeString("28654d9264f55f18d810bb88617e22c117df94fa684dfe341a511a72dfbf2b68")
	require.Nil(t, err)
	cryptoHolder, err := cryptoProvider.NewCryptoComponentsHolder(keyGen, sk)
	require.Nil(t, err)

	t.Run("fails if the signature is missing", func(t *testing.T) {
		t.Parallel()

		tb, _ := NewTxBuilder(cryptoProvider.NewSigner())
		txHash, errGenerate := tb.ComputeTxHash(&transaction.FrontendTransaction{})
		assert.Nil(t, txHash)
		assert.Equal(t, ErrMissingSignature, errGenerate)
	})

	t.Run("should generate tx hash", func(t *testing.T) {
		t.Parallel()

		tx := &transaction.FrontendTransaction{
			Nonce:    1,
			Value:    "11500313000000000000",
			Receiver: "erd1p72ru5zcdsvgkkcm9swtvw2zy5epylwgv8vwquptkw7ga7pfvk7qz7snzw",
			GasPrice: 1000000000,
			GasLimit: 60000,
			Data:     []byte(""),
			ChainID:  "T",
			Version:  uint32(1),
		}
		tb, _ := NewTxBuilder(cryptoProvider.NewSigner())

		_ = tb.ApplyUserSignature(cryptoHolder, tx)
		assert.Equal(t, "725c6aa7def724c60f02ee481734807038fef125e453242bf4dc570fc4a4f2ff1b78e996a2ec67ef8be03f9b98b0251d419cfc72c6e6c5c9e33f879af938f008", tx.Signature)

		txHash, errGenerate := tb.ComputeTxHash(tx)
		assert.Nil(t, errGenerate)
		assert.Equal(t, "8bbb2b7474deb2e67fa8f9db1eccef57ec14aa93710452a5de5ff52e5a369144", hex.EncodeToString(txHash))
	})
}

func TestTxBuilder_ApplyUserSignatureAndGenerateWithTxGuardian(t *testing.T) {
	t.Parallel()

	guardianAddress := "erd1p5jgz605m47fq5mlqklpcjth9hdl3au53dg8a5tlkgegfnep3d7stdk09x"
	skGuardian, err := hex.DecodeString("6ae10fed53a84029e53e35afdbe083688eea0917a09a9431951dd42fd4da14c40d248169f4dd7c90537f05be1c49772ddbf8f7948b507ed17fb23284cf218b7d")
	require.Nil(t, err)
	cryptoHolderGuardian, err := cryptoProvider.NewCryptoComponentsHolder(keyGen, skGuardian)
	require.Nil(t, err)

	senderAddress := "erd1lta2vgd0tkeqqadkvgef73y0efs6n3xe5ss589ufhvmt6tcur8kq34qkwr"
	sk, err := hex.DecodeString("28654d9264f55f18d810bb88617e22c117df94fa684dfe341a511a72dfbf2b68")
	require.Nil(t, err)
	cryptoHolder, err := cryptoProvider.NewCryptoComponentsHolder(keyGen, sk)
	require.Nil(t, err)

	tx := transaction.FrontendTransaction{
		Nonce:        1,
		Value:        "11500313000000000000",
		Receiver:     "erd1p72ru5zcdsvgkkcm9swtvw2zy5epylwgv8vwquptkw7ga7pfvk7qz7snzw",
		GasPrice:     1000000000,
		GasLimit:     60000,
		Data:         []byte(""),
		ChainID:      "T",
		Version:      uint32(2),
		Options:      transaction.MaskGuardedTransaction,
		GuardianAddr: guardianAddress,
	}

	t.Run("no guardian option should fail", func(t *testing.T) {
		txLocal := tx
		txLocal.Options = 0
		tb, _ := NewTxBuilder(cryptoProvider.NewSigner())
		_ = tb.ApplyUserSignature(cryptoHolder, &txLocal)
		err = tb.ApplyGuardianSignature(cryptoHolderGuardian, &txLocal)

		require.Equal(t, ErrMissingGuardianOption, err)
	})

	t.Run("no guardian address should fail", func(t *testing.T) {
		txLocal := tx
		txLocal.GuardianAddr = ""
		tb, _ := NewTxBuilder(cryptoProvider.NewSigner())
		_ = tb.ApplyUserSignature(cryptoHolder, &txLocal)

		err = tb.ApplyGuardianSignature(cryptoHolderGuardian, &txLocal)
		require.NotNil(t, err)
	})

	t.Run("different guardian address should fail", func(t *testing.T) {
		txLocal := tx
		txLocal.GuardianAddr = senderAddress
		tb, _ := NewTxBuilder(cryptoProvider.NewSigner())
		_ = tb.ApplyUserSignature(cryptoHolder, &txLocal)

		err = tb.ApplyGuardianSignature(cryptoHolderGuardian, &txLocal)
		require.Equal(t, ErrGuardianDoesNotMatch, err)
	})
	t.Run("correct guardian ok", func(t *testing.T) {
		txLocal := tx
		tb, _ := NewTxBuilder(cryptoProvider.NewSigner())
		_ = tb.ApplyUserSignature(cryptoHolder, &txLocal)

		err = tb.ApplyGuardianSignature(cryptoHolderGuardian, &txLocal)
		require.Nil(t, err)
	})
	t.Run("correct guardian and sign with hash ok", func(t *testing.T) {
		txLocal := tx
		txLocal.Options |= transaction.MaskSignedWithHash
		tb, _ := NewTxBuilder(cryptoProvider.NewSigner())
		_ = tb.ApplyUserSignature(cryptoHolder, &txLocal)

		err = tb.ApplyGuardianSignature(cryptoHolderGuardian, &txLocal)
		require.Nil(t, err)
	})
}

func TestTxBuilder_ApplyRelayerSignature(t *testing.T) {
	t.Parallel()

	relayerAddress := "erd1p5jgz605m47fq5mlqklpcjth9hdl3au53dg8a5tlkgegfnep3d7stdk09x"
	skRelayer, err := hex.DecodeString("6ae10fed53a84029e53e35afdbe083688eea0917a09a9431951dd42fd4da14c40d248169f4dd7c90537f05be1c49772ddbf8f7948b507ed17fb23284cf218b7d")
	require.Nil(t, err)
	cryptoHolderRelayer, err := cryptoProvider.NewCryptoComponentsHolder(keyGen, skRelayer)
	require.Nil(t, err)

	senderAddress := "erd1lta2vgd0tkeqqadkvgef73y0efs6n3xe5ss589ufhvmt6tcur8kq34qkwr"
	sk, err := hex.DecodeString("28654d9264f55f18d810bb88617e22c117df94fa684dfe341a511a72dfbf2b68")
	require.Nil(t, err)
	cryptoHolder, err := cryptoProvider.NewCryptoComponentsHolder(keyGen, sk)
	require.Nil(t, err)

	tx := transaction.FrontendTransaction{
		Nonce:       1,
		Value:       "1000000000000000000",
		Receiver:    "erd1p72ru5zcdsvgkkcm9swtvw2zy5epylwgv8vwquptkw7ga7pfvk7qz7snzw",
		GasPrice:    1000000000,
		GasLimit:    100000,
		Data:        []byte("gift"),
		ChainID:     "T",
		Version:     uint32(2),
		RelayerAddr: relayerAddress,
	}

	t.Run("no relayer address should fail", func(t *testing.T) {
		txLocal := tx
		txLocal.RelayerAddr = ""
		tb, _ := NewTxBuilder(cryptoProvider.NewSigner())
		_ = tb.ApplyUserSignature(cryptoHolder, &txLocal)

		err = tb.ApplyRelayerSignature(cryptoHolderRelayer, &txLocal)
		require.NotNil(t, err)
	})
	t.Run("different relayer address should fail", func(t *testing.T) {
		txLocal := tx
		txLocal.RelayerAddr = senderAddress
		tb, _ := NewTxBuilder(cryptoProvider.NewSigner())
		_ = tb.ApplyUserSignature(cryptoHolder, &txLocal)

		err = tb.ApplyRelayerSignature(cryptoHolderRelayer, &txLocal)
		require.Equal(t, ErrRelayerDoesNotMatch, err)
	})
	t.Run("correct relayer should work", func(t *testing.T) {
		txLocal := tx
		tb, _ := NewTxBuilder(cryptoProvider.NewSigner())
		_ = tb.ApplyUserSignature(cryptoHolder, &txLocal)

		err = tb.ApplyRelayerSignature(cryptoHolderRelayer, &txLocal)
		require.Nil(t, err)
	})
	t.Run("correct relayer and sign with hash ok", func(t *testing.T) {
		txLocal := tx
		txLocal.Options |= transaction.MaskSignedWithHash
		tb, _ := NewTxBuilder(cryptoProvider.NewSigner())
		_ = tb.ApplyUserSignature(cryptoHolder, &txLocal)

		err = tb.ApplyRelayerSignature(cryptoHolderRelayer, &txLocal)
		require.Nil(t, err)
	})
}
