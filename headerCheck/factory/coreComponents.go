package factory

import (
	"github.com/multiversx/mx-chain-core-go/core"
	"github.com/multiversx/mx-chain-core-go/core/pubkeyConverter"
	"github.com/multiversx/mx-chain-core-go/hashing"
	hasherFactory "github.com/multiversx/mx-chain-core-go/hashing/factory"
	"github.com/multiversx/mx-chain-core-go/marshal"
	marshalizerFactory "github.com/multiversx/mx-chain-core-go/marshal/factory"
	"github.com/multiversx/mx-chain-go/common"
	"github.com/multiversx/mx-chain-go/common/enablers"
	"github.com/multiversx/mx-chain-go/config"
	"github.com/multiversx/mx-chain-go/process/rating"
	"github.com/multiversx/mx-chain-go/sharding/nodesCoordinator"
	"github.com/multiversx/mx-sdk-go/data"
	"github.com/multiversx/mx-sdk-go/disabled"
)

const (
	marshalizerType          = "gogo protobuf"
	hasherType               = "blake2b"
	validatorHexPubKeyLength = 96
)

type coreComponents struct {
	Marshaller          marshal.Marshalizer
	Hasher              hashing.Hasher
	Rater               nodesCoordinator.ChanceComputer
	PubKeyConverter     core.PubkeyConverter
	EnableEpochsHandler common.EnableEpochsHandler
}

// CreateCoreComponents creates core components needed for header verification
func CreateCoreComponents(
	ratingsConfig *data.RatingsConfig,
	networkConfig *data.NetworkConfig,
	enableEpochsConfig *data.EnableEpochsConfig,
) (*coreComponents, error) {
	marshalizer, err := marshalizerFactory.NewMarshalizer(marshalizerType)
	if err != nil {
		return nil, err
	}

	hasher, err := hasherFactory.NewHasher(hasherType)
	if err != nil {
		return nil, err
	}

	rater, err := createRater(ratingsConfig, networkConfig)
	if err != nil {
		return nil, err
	}

	converter, err := pubkeyConverter.NewHexPubkeyConverter(validatorHexPubKeyLength)
	if err != nil {
		return nil, err
	}

	enableEpochsHandler, err := enablers.NewEnableEpochsHandler(enableEpochsConfig.EnableEpochs, &disabled.EpochNotifier{})
	if err != nil {
		return nil, err
	}

	return &coreComponents{
		Marshaller:          marshalizer,
		Hasher:              hasher,
		Rater:               rater,
		PubKeyConverter:     converter,
		EnableEpochsHandler: enableEpochsHandler,
	}, nil
}

func createRater(rc *data.RatingsConfig, nc *data.NetworkConfig) (nodesCoordinator.ChanceComputer, error) {
	ratingsConfig := createRatingsConfig(rc)

	ratingDataArgs := rating.RatingsDataArg{
		Config:                   ratingsConfig,
		ShardConsensusSize:       uint32(nc.ShardConsensusGroupSize),
		MetaConsensusSize:        nc.MetaConsensusGroup,
		ShardMinNodes:            nc.NumNodesInShard,
		MetaMinNodes:             nc.NumMetachainNodes,
		RoundDurationMiliseconds: uint64(nc.RoundDuration),
	}

	ratingsData, err := rating.NewRatingsData(ratingDataArgs)
	if err != nil {
		return nil, err
	}

	rater, err := rating.NewBlockSigningRater(ratingsData)
	if err != nil {
		return nil, err
	}

	return rater, nil
}

func createRatingsConfig(rd *data.RatingsConfig) config.RatingsConfig {
	selectionChances := make([]*config.SelectionChance, len(rd.GeneralSelectionChances))
	for i, v := range rd.GeneralSelectionChances {
		selectionChance := &config.SelectionChance{
			MaxThreshold:  v.MaxThreshold,
			ChancePercent: v.ChancePercent,
		}
		selectionChances[i] = selectionChance
	}

	general := config.General{
		StartRating:           rd.GeneralStartRating,
		MaxRating:             rd.GeneralMaxRating,
		MinRating:             rd.GeneralMinRating,
		SignedBlocksThreshold: rd.GeneralSignedBlocksThreshold,
		SelectionChances:      selectionChances,
	}

	shardChain := config.ShardChain{
		RatingSteps: config.RatingSteps{
			HoursToMaxRatingFromStartRating: rd.ShardchainHoursToMaxRatingFromStartRating,
			ProposerValidatorImportance:     rd.ShardchainProposerValidatorImportance,
			ProposerDecreaseFactor:          rd.ShardchainProposerDecreaseFactor,
			ValidatorDecreaseFactor:         rd.ShardchainValidatorDecreaseFactor,
			ConsecutiveMissedBlocksPenalty:  rd.ShardchainConsecutiveMissedBlocksPenalty,
		},
	}

	metaChain := config.MetaChain{
		RatingSteps: config.RatingSteps{
			HoursToMaxRatingFromStartRating: rd.MetachainHoursToMaxRatingFromStartRating,
			ProposerValidatorImportance:     rd.MetachainProposerValidatorImportance,
			ProposerDecreaseFactor:          rd.MetachainProposerDecreaseFactor,
			ValidatorDecreaseFactor:         rd.MetachainValidatorDecreaseFactor,
			ConsecutiveMissedBlocksPenalty:  rd.MetachainConsecutiveMissedBlocksPenalty,
		},
	}

	ratingsConfig := config.RatingsConfig{
		General:     general,
		ShardChain:  shardChain,
		MetaChain:   metaChain,
		PeerHonesty: config.PeerHonestyConfig{},
	}

	return ratingsConfig
}
