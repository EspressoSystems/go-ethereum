package rawdb

import (
	"encoding/binary"
	"fmt"
	"os"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/ethereum/go-ethereum/ethdb"
	"github.com/ethereum/go-ethereum/rlp"
)

var BlockSignaturePrefix = []byte("blockSignature")

func uint64ToKey(x uint64) []byte {
	data := make([]byte, 8)
	binary.BigEndian.PutUint64(data, x)
	return data
}

func dbKey(prefix []byte, pos uint64) []byte {
	var key []byte
	key = append(key, prefix...)
	key = append(key, uint64ToKey(pos)...)
	return key
}

func GetBlockSignature(db ethdb.KeyValueReader, blockHash common.Hash) ([]byte, error) {
	blockNumber := binary.BigEndian.Uint64(blockHash.Bytes())
	key := dbKey(BlockSignaturePrefix, (blockNumber))
	return db.Get(key)
}

func GetHashOverInterface(data interface{}) ([]byte, error) {

	dataBytes, err := rlp.EncodeToBytes(data)
	if err != nil {
		return nil, err
	}
	hash := crypto.Keccak256Hash(dataBytes)
	return hash.Bytes(), nil
}

func VerifyBlockSignature(db ethdb.KeyValueReader, blockHash common.Hash) error {

	blockSignature, err := GetBlockSignature(db, blockHash)
	if err != nil {
		return fmt.Errorf("unable to get block signature")
	}

	publicKeyBytes, err := crypto.Ecrecover(blockHash.Bytes(), blockSignature)
	if err != nil {
		return fmt.Errorf("unable to recover public key")
	}
	pubKey, err := crypto.UnmarshalPubkey(publicKeyBytes)
	if err != nil || pubKey == nil {
		return fmt.Errorf("invalid public key")
	}
	// Public Key to address
	publicKeyAddress := crypto.PubkeyToAddress(*pubKey)
	// TODO: In follow up PRs, we should allows any valid PCR0 address registered in the contract
	// to be able to decrypt the snapshot
	snapshotAddressString := os.Getenv("SNAPSHOT_ADDRESS")
	snapshotAddress := common.HexToAddress(snapshotAddressString)

	if publicKeyAddress != snapshotAddress {
		return fmt.Errorf("invalid snapshot address")
	}
	return nil
}

// VerifyBodyMatchesBlockHashProof verifies that the given body matches the block hash which
// the enclave has signed over.
func VerifyBodyMatchesBlockHashProof(db ethdb.Reader, number uint64, hash common.Hash, body *types.Body) error {
	header := ReadHeader(db, hash, number)
	if header == nil {
		return fmt.Errorf("header #%d not found", number)
	}

	if header.Hash() != hash {
		return fmt.Errorf("header #%d hash mismatch: have %v, want %v", number, header.Hash(), hash)
	}

	// We generate the transaction root and uncle hash and the withdrawal root from the body
	txRoot := types.DeriveSha(types.Transactions(body.Transactions), nil)
	uncleHash := types.CalcUncleHash(body.Uncles)
	withdrawalRoot := types.DeriveSha(types.Withdrawals(body.Withdrawals), nil)

	if txRoot != header.TxHash {
		return fmt.Errorf("transaction root mismatch: have %v, want %v", txRoot, header.TxHash)
	}
	if uncleHash != header.UncleHash {
		return fmt.Errorf("uncle hash mismatch: have %v, want %v", uncleHash, header.UncleHash)
	}

	if header.WithdrawalsHash != nil && withdrawalRoot != *header.WithdrawalsHash {
		return fmt.Errorf("withdrawal root mismatch: have %v, want %v", withdrawalRoot, header.WithdrawalsHash)
	}

	return nil
}

func VerifyReceiptsInBlock(db ethdb.Reader, number uint64, hash common.Hash, receipts types.Receipts) error {

	header := ReadHeader(db, hash, number)
	if header == nil {
		return fmt.Errorf("header #%d not found", number)
	}

	root := types.DeriveSha(types.Receipts(receipts), nil)
	if root != header.ReceiptHash {
		return fmt.Errorf("receipt root mismatch: have %v, want %v", root, header.ReceiptHash)
	}

	return nil
}

func VerifyLogsInBlock(db ethdb.Reader, number uint64, hash common.Hash, receipts types.Receipts) ([][]*types.Log, error) {
	err := VerifyReceiptsInBlock(db, number, hash, receipts)
	if err != nil {
		return nil, err
	}

	logs := make([][]*types.Log, len(receipts))
	for i, r := range receipts {
		logs[i] = r.Logs
	}
	return logs, nil
}
