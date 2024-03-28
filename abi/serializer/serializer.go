package serializer

import (
	"encoding/hex"
	"errors"
	"strings"

	"github.com/multiversx/mx-sdk-go/abi/values"
)

type serializer struct {
	codec valuesCodec
}

func NewSerializer(codec valuesCodec) *serializer {
	return &serializer{
		codec: codec,
	}
}

func (s *serializer) Serialize(inputValues []any) (string, error) {
	parts, err := s.SerializeToParts(inputValues)
	if err != nil {
		return "", err
	}

	return s.encodeParts(parts), nil
}

func (s *serializer) SerializeToParts(inputValues []any) ([][]byte, error) {
	partsHolder := newEmptyPartsHolder()

	err := s.doSerialize(partsHolder, inputValues)
	if err != nil {
		return nil, err
	}

	return partsHolder.getParts(), nil
}

func (s *serializer) doSerialize(partsHolder *partsHolder, inputValues []any) error {
	var err error

	for i, value := range inputValues {
		if value == nil {
			return errors.New("cannot serialize nil value")
		}

		switch value.(type) {
		case values.InputMultiValue:
			err = s.serializeInputMultiValue(partsHolder, value.(values.InputMultiValue))
		case values.InputVariadicValues:
			if i != len(inputValues)-1 {
				return errors.New("variadic values must be last among input values")
			}

			err = s.serializeInputVariadicValues(partsHolder, value.(values.InputVariadicValues))
		default:
			partsHolder.appendEmptyPart()
			err = s.serializeDirectlyEncodableValue(partsHolder, value)
		}

		if err != nil {
			return err
		}
	}

	return nil
}

func (s *serializer) Deserialize(data string, outputValues []any) error {
	parts, err := s.decodeIntoParts(data)
	if err != nil {
		return err
	}

	return s.DeserializeParts(parts, outputValues)
}

func (s *serializer) DeserializeParts(parts [][]byte, outputValues []any) error {
	partsHolder := newPartsHolder(parts)

	err := s.doDeserialize(partsHolder, outputValues)
	if err != nil {
		return err
	}

	return nil
}

func (s *serializer) doDeserialize(partsHolder *partsHolder, outputValues []any) error {
	var err error

	for i, value := range outputValues {
		if value == nil {
			return errors.New("cannot deserialize into nil value")
		}

		switch value.(type) {
		case *values.OutputMultiValue:
			err = s.deserializeOutputMultiValue(partsHolder, value.(*values.OutputMultiValue))
		case *values.OutputVariadicValues:
			if i != len(outputValues)-1 {
				return errors.New("variadic values must be last among output values")
			}

			err = s.deserializeOutputVariadicValues(partsHolder, value.(*values.OutputVariadicValues))
		default:
			err = s.deserializeDirectlyEncodableValue(partsHolder, value)
		}

		if err != nil {
			return err
		}
	}

	return nil
}

func (s *serializer) serializeInputMultiValue(partsHolder *partsHolder, value values.InputMultiValue) error {
	for _, item := range value.Items {
		err := s.doSerialize(partsHolder, []any{item})
		if err != nil {
			return err
		}
	}

	return nil
}

func (s *serializer) serializeInputVariadicValues(partsHolder *partsHolder, value values.InputVariadicValues) error {
	for _, item := range value.Items {
		err := s.doSerialize(partsHolder, []any{item})
		if err != nil {
			return err
		}
	}

	return nil
}

func (s *serializer) serializeDirectlyEncodableValue(partsHolder *partsHolder, value any) error {
	data, err := s.codec.EncodeTopLevel(value)
	if err != nil {
		return err
	}

	return partsHolder.appendToLastPart(data)
}

func (s *serializer) deserializeOutputMultiValue(partsHolder *partsHolder, value *values.OutputMultiValue) error {
	for _, item := range value.Items {
		err := s.doDeserialize(partsHolder, []any{item})
		if err != nil {
			return err
		}
	}

	return nil
}

func (s *serializer) deserializeOutputVariadicValues(partsHolder *partsHolder, value *values.OutputVariadicValues) error {
	if value.ItemCreator == nil {
		return errors.New("cannot deserialize variadic values: item creator is nil")
	}

	for !partsHolder.isFocusedBeyondLastPart() {
		newItem := value.ItemCreator()

		err := s.doDeserialize(partsHolder, []any{newItem})
		if err != nil {
			return err
		}

		value.Items = append(value.Items, newItem)
	}

	return nil
}

func (s *serializer) deserializeDirectlyEncodableValue(partsHolder *partsHolder, value any) error {
	part, err := partsHolder.readWholeFocusedPart()
	if err != nil {
		return err
	}

	err = s.codec.DecodeTopLevel(part, value)
	if err != nil {
		return err
	}

	err = partsHolder.focusOnNextPart()
	if err != nil {
		return err
	}

	return nil
}

func (s *serializer) encodeParts(parts [][]byte) string {
	partsHex := make([]string, len(parts))

	for i, part := range parts {
		partsHex[i] = hex.EncodeToString(part)
	}

	return strings.Join(partsHex, partsSeparator)
}

func (s *serializer) decodeIntoParts(encoded string) ([][]byte, error) {
	partsHex := strings.Split(encoded, partsSeparator)
	parts := make([][]byte, len(partsHex))

	for i, partHex := range partsHex {
		part, err := hex.DecodeString(partHex)
		if err != nil {
			return nil, err
		}

		parts[i] = part
	}

	return parts, nil
}
