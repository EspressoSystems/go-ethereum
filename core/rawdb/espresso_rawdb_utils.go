package rawdb

import (
	"crypto/ecdsa"
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

var DefaultHasher types.TrieHasher

func SetDefaultTrieHasher(hasher types.TrieHasher) { DefaultHasher = hasher }

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

func StoreHeaderSignatureForTests(db ethdb.KeyValueWriter, hash []common.Hash, snapshotSignerPrivateKey *ecdsa.PrivateKey) error {
	// Generate a new public and private key pair which will be used to sign the block
	for _, h := range hash {
		// Sign the hash of the header using the private key
		signature, err := crypto.Sign(h.Bytes(), snapshotSignerPrivateKey)
		if err != nil {
			return fmt.Errorf("failed to sign header: %v", err)
		}

		err = StoreBlockSignatureForTests(db, h, signature)
		if err != nil {
			return fmt.Errorf("failed to store signature: %v", err)
		}
	}
	return nil
}

func StoreBlockSignatureForTests(db ethdb.KeyValueWriter, blockHash common.Hash, blockSignature []byte) error {
	blockNumber := binary.BigEndian.Uint64(blockHash.Bytes())
	key := dbKey(BlockSignaturePrefix, (blockNumber))
	return db.Put(key, blockSignature)
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
	snapshotAddressString := os.Getenv("SNAPSHOT_ADDRESS")

	if snapshotAddressString == "" {
		return nil
	}
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
	snapshotAddress := common.HexToAddress(snapshotAddressString)

	if publicKeyAddress != snapshotAddress {
		return fmt.Errorf("invalid snapshot address")
	}
	return nil
}

// VerifyBodyMatchesBlockHashProof verifies that the given body matches the block hash which
// the enclave has signed over.
func VerifyBodyMatchesBlockHashProof(db ethdb.Reader, number uint64, hash common.Hash, body *types.Body) error {
	if os.Getenv("SNAPSHOT_ADDRESS") == "" {
		return nil
	}
	header := ReadHeader(db, hash, number)
	if header == nil {
		return fmt.Errorf("header #%d not found", number)
	}
	if header.Hash() != hash {
		return fmt.Errorf("header #%d hash mismatch: have %v, want %v", number, header.Hash(), hash)
	}
	if header.Number.Uint64() != number {
		return fmt.Errorf("header #%d number mismatch: have %v, want %v", number, header.Number, number)
	}

	txRoot := types.EmptyTxsHash
	uncleHash := types.EmptyUncleHash
	withdrawalRoot := types.EmptyWithdrawalsHash

	hasher := DefaultHasher
	// We generate the transaction root and uncle hash and the withdrawal root from the body
	if len(body.Transactions) > 0 {
		txRoot = types.DeriveSha(types.Transactions(body.Transactions), hasher)
	}
	if len(body.Uncles) > 0 {
		uncleHash = types.CalcUncleHash(body.Uncles)
	}
	if len(body.Withdrawals) > 0 {
		withdrawalRoot = types.DeriveSha(types.Withdrawals(body.Withdrawals), hasher)
	}

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

func VerifyBlockNumber(db ethdb.Reader, number uint64, hash common.Hash) error {
	if os.Getenv("SNAPSHOT_ADDRESS") == "" {
		return nil
	}
	header := ReadHeader(db, hash, number)
	if header == nil {
		return fmt.Errorf("header #%d not found", number)
	}
	if header.Number.Uint64() != number {
		return fmt.Errorf("header #%d number mismatch: have %v, want %v", number, header.Number, number)
	}
	if header.Hash() != hash {
		return fmt.Errorf("header #%d hash mismatch: have %v, want %v", number, header.Hash(), hash)
	}
	return nil
}

/*
This method is used to verify block number which is supposed to not be present in ancient store
*/
func VerifyBlockNumberWithoutAncients(db ethdb.KeyValueReader, number uint64, hash common.Hash) (*types.Header, error) {
	if os.Getenv("SNAPSHOT_ADDRESS") == "" {
		return nil, nil
	}
	data, _ := db.Get(headerKey(number, hash))
	if len(data) == 0 {
		return nil, fmt.Errorf("header #%d not found", number)
	}
	header := new(types.Header)
	if err := rlp.DecodeBytes(data, header); err != nil {
		return nil, fmt.Errorf("invalid block header RLP in VerifyBlockNumberWithoutAncients: %v", err)
	}

	if header.Number.Uint64() != number {
		return nil, fmt.Errorf("header #%d number mismatch: have %v, want %v", number, header.Number, number)
	}
	if header.Hash() != hash {
		return nil, fmt.Errorf("header #%d hash mismatch: have %v, want %v", number, header.Hash(), hash)
	}
	return header, nil
}

func VerifyReceiptsInBlock(db ethdb.Reader, number uint64, hash common.Hash, receipts types.Receipts) error {
	if os.Getenv("SNAPSHOT_ADDRESS") == "" {
		return nil
	}
	header := ReadHeader(db, hash, number)
	if header == nil {
		return fmt.Errorf("header #%d not found", number)
	}
	hasher := DefaultHasher

	root := types.DeriveSha(receipts, hasher)
	if root != header.ReceiptHash {
		return fmt.Errorf("receipt root mismatch: have %v, want %v", root, header.ReceiptHash)
	}

	// Also verify bloom bits
	blockBloom := types.MergeBloom(receipts)
	if blockBloom != header.Bloom {
		return fmt.Errorf("receipt bloom mismatch: have %v, want %v", blockBloom, header.Bloom)
	}

	return nil
}

func VerifyLogsInBlock(db ethdb.Reader, number uint64, hash common.Hash, receipts types.Receipts) ([][]*types.Log, error) {
	if os.Getenv("SNAPSHOT_ADDRESS") == "" {
		// Return the logs
		logs := make([][]*types.Log, len(receipts))
		for i, r := range receipts {
			logs[i] = r.Logs
		}
		return logs, nil
	}
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
