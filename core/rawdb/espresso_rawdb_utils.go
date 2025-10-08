package rawdb

import (
	"crypto/ecdsa"
	"encoding/binary"
	"errors"
	"fmt"
	"os"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/ethereum/go-ethereum/ethdb"
	"github.com/ethereum/go-ethereum/rlp"
)

var defaultHasher types.TrieHasher

func SetDefaultTrieHasher(hasher types.TrieHasher) { defaultHasher = hasher }
func GetDefaultTrieHasher() (types.TrieHasher, error) {
	if defaultHasher == nil {
		return nil, fmt.Errorf("default hasher not set for rawdb")
	}
	return defaultHasher, nil
}

func storeHeaderSignatureForTests(db ethdb.KeyValueWriter, hash []common.Hash, snapshotSignerPrivateKey *ecdsa.PrivateKey) error {
	for _, h := range hash {
		// Sign the hash of the header using the private key
		signature, err := crypto.Sign(h.Bytes(), snapshotSignerPrivateKey)
		if err != nil {
			return fmt.Errorf("failed to sign header: %v", err)
		}

		err = storeBlockSignatureForTests(db, h, signature)
		if err != nil {
			return fmt.Errorf("failed to store signature: %v", err)
		}
	}
	return nil
}

func storeBlockSignatureForTests(db ethdb.KeyValueWriter, blockHash common.Hash, blockSignature []byte) error {
	blockNumber := binary.BigEndian.Uint64(blockHash.Bytes())
	key := blockSignatureKey(blockNumber)
	return db.Put(key, blockSignature)
}

func GetBlockSignature(db ethdb.KeyValueReader, blockHash common.Hash) ([]byte, error) {
	blockNumber := binary.BigEndian.Uint64(blockHash.Bytes())
	key := blockSignatureKey(blockNumber)
	return db.Get(key)
}

func VerifyBlockHashSignature(db ethdb.KeyValueReader, blockHash common.Hash) error {
	var snapshotAddressString string
	var ok bool
	if snapshotAddressString, ok = IsTEEEnabled(); !ok {
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
		return fmt.Errorf("signature verification failed")
	}
	return nil
}

// VerifyBodyMatchesBlockHashProof verifies that the given body matches the block hash which
// the enclave has signed over.
func VerifyBodyMatchesBlockHashProof(db ethdb.Reader, number uint64, hash common.Hash, body *types.Body) error {
	if _, ok := IsTEEEnabled(); !ok {
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

	hasher, err := GetDefaultTrieHasher()
	if err != nil {
		return err
	}
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
	if _, ok := IsTEEEnabled(); !ok {
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
func VerifyBlockNumberWithoutAncients(db ethdb.KeyValueReader, number uint64) (*types.Header, error) {
	if _, ok := IsTEEEnabled(); !ok {
		return nil, nil
	}
	data, _ := db.Get(headerHashKey(number))
	if len(data) == 0 {
		return nil, fmt.Errorf("header #%d not found", number)
	}
	hash := common.BytesToHash(data)

	headerData, _ := db.Get(headerKey(number, hash))
	header := new(types.Header)
	if err := rlp.DecodeBytes(headerData, &header); err != nil {
		return nil, fmt.Errorf("invalid block header RLP in VerifyBlockNumberWithoutAncients: %v", err)
	}

	if header.Number.Uint64() != number {
		return nil, fmt.Errorf("header #%d number mismatch: have %v, want %v", number, header.Number, number)
	}

	return header, nil
}

func VerifyReceiptsInBlock(db ethdb.Reader, number uint64, hash common.Hash, receipts types.Receipts) error {
	if _, ok := IsTEEEnabled(); !ok {
		return nil
	}
	header := ReadHeader(db, hash, number)
	if header == nil {
		return fmt.Errorf("header #%d not found", number)
	}

	hasher, err := GetDefaultTrieHasher()
	if err != nil {
		return err
	}
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
	if _, ok := IsTEEEnabled(); !ok {
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

func HashCode(code []byte) common.Hash {
	hasher := newHasher()
	defer hasher.release()
	hasher.sha.Write(code)
	var out common.Hash
	hasher.sha.Read(out[:])
	return out
}

// Example verification
func VerifyBytes(code []byte, codeHash common.Hash) bool {
	return HashCode(code) == codeHash
}

func VerifyBloomBits(db ethdb.Database, section uint64, bit uint, sectionSize uint64, expectedHead common.Hash) ([]byte, error) {
	startBlock := section * sectionSize
	// This calculation is borrowed from `compress.go`
	bitset := make([]byte, (sectionSize+7)/8)

	for i := uint64(0); i < sectionSize; i++ {
		blockNumber := startBlock + i
		blockHash := ReadCanonicalHash(db, blockNumber)

		// Verify we're on the expected canonical chain
		if blockNumber == (section+1)*sectionSize-1 && blockHash != expectedHead {
			return nil, errors.New("canonical chain mismatch")
		}

		// Get the block's bloom filter (from receipts)
		receipts := ReadRawReceipts(db, blockHash, blockNumber)
		var bloom types.Bloom
		if len(receipts) > 0 {
			bloom = types.MergeBloom(receipts)
		}

		if isBitSet(bloom, bit) {
			// This calculation is borrowed from `compress.go`
			bitset[i/8] |= 1 << byte(7-i%8)
		}
	}

	return bitset, nil
}

// Simple bit check - no complex transformations needed
func isBitSet(bloom types.Bloom, bit uint) bool {
	byteIndex := bit / 8
	bitIndex := bit % 8
	// This calculation is borrowed from `compress.go`
	return bloom[byteIndex]&(1<<byte(7-bitIndex)) != 0
}

func IsTEEEnabled() (string, bool) {
	return os.LookupEnv("SNAPSHOT_ADDRESS")
}
