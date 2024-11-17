package bridge

import (
	"bytes"
	"context"
	"encoding/hex"
	"fmt"
	"io"
	"sync"

	pb "go-backend/pkg/proto/crypto" // Protocol buffers for Python communication

	"github.com/zeebo/blake3"
)

// HashResult represents a hash result that's compatible with Python
type HashResult struct {
	Hash   []byte `json:"hash"`
	Hex    string `json:"hex"`
	Length int    `json:"length"`
}

// Blake3Bridge provides compatibility with Python's Blake3 implementation
type Blake3Bridge struct {
	contexts sync.Map // Thread-safe context storage
}

// NewBlake3Bridge creates a new bridge instance
func NewBlake3Bridge() *Blake3Bridge {
	return &Blake3Bridge{}
}

// Hash implements the same hashing logic as Python
func (b *Blake3Bridge) Hash(data []byte, context string) (*HashResult, error) {
	if len(data) == 0 {
		return nil, fmt.Errorf("empty data")
	}

	hasher := blake3.New()
	hasher.Write([]byte(context))
	hasher.Write(data)

	hash := hasher.Sum(nil)
	return &HashResult{
		Hash:   hash,
		Hex:    hex.EncodeToString(hash),
		Length: len(hash),
	}, nil
}

// VerifyPythonHash verifies a hash from Python
func (b *Blake3Bridge) VerifyPythonHash(data []byte, context string, pythonHash []byte) bool {
	result, err := b.Hash(data, context)
	if err != nil {
		return false
	}
	return bytes.Equal(result.Hash, pythonHash)
}

// StreamingHasher provides streaming hash functionality
type StreamingHasher struct {
	context string
	hasher  *blake3.Hasher
	result  chan *HashResult
	done    chan struct{}
}

// NewStreamingHasher creates a new streaming hasher
func (b *Blake3Bridge) NewStreamingHasher(context string) *StreamingHasher {
	hasher := blake3.New()
	hasher.Write([]byte(context))

	return &StreamingHasher{
		context: context,
		hasher:  hasher,
		result:  make(chan *HashResult, 1),
		done:    make(chan struct{}),
	}
}

// Write implements io.Writer for streaming
func (sh *StreamingHasher) Write(p []byte) (n int, err error) {
	n, err = sh.hasher.Write(p)
	if err != nil {
		return n, err
	}

	// Send intermediate result
	hash := sh.hasher.Sum(nil)
	select {
	case sh.result <- &HashResult{
		Hash:   hash,
		Hex:    hex.EncodeToString(hash),
		Length: len(hash),
	}:
	default:
		// Channel full, skip intermediate result
	}

	return n, nil
}

// Results returns a channel for receiving hash results
func (sh *StreamingHasher) Results() <-chan *HashResult {
	return sh.result
}

// Close closes the streaming hasher
func (sh *StreamingHasher) Close() error {
	close(sh.done)
	close(sh.result)
	return nil
}

// HashFile implements file hashing with progress reporting
func (b *Blake3Bridge) HashFile(reader io.Reader, context string) (*HashResult, error) {
	hasher := blake3.New()
	hasher.Write([]byte(context))

	_, err := io.Copy(hasher, reader)
	if err != nil {
		return nil, fmt.Errorf("hashing failed: %w", err)
	}

	hash := hasher.Sum(nil)
	return &HashResult{
		Hash:   hash,
		Hex:    hex.EncodeToString(hash),
		Length: len(hash),
	}, nil
}

// VerifyFile verifies a file against a Python hash
func (b *Blake3Bridge) VerifyFile(reader io.Reader, context string, pythonHash []byte) (bool, error) {
	result, err := b.HashFile(reader, context)
	if err != nil {
		return false, err
	}
	return bytes.Equal(result.Hash, pythonHash), nil
}

// gRPC service implementation
type Blake3Service struct {
	pb.UnimplementedBlake3ServiceServer
	bridge *Blake3Bridge
}

func NewBlake3Service() *Blake3Service {
	return &Blake3Service{
		bridge: NewBlake3Bridge(),
	}
}

func (s *Blake3Service) Hash(ctx context.Context, req *pb.HashRequest) (*pb.HashResponse, error) {
	result, err := s.bridge.Hash(req.Data, req.Context)
	if err != nil {
		return nil, err
	}

	return &pb.HashResponse{
		Hash: result.Hash,
		Hex:  result.Hex,
	}, nil
}

func (s *Blake3Service) Verify(ctx context.Context, req *pb.VerifyRequest) (*pb.VerifyResponse, error) {
	isValid := s.bridge.VerifyPythonHash(req.Data, req.Context, req.ExpectedHash)
	return &pb.VerifyResponse{
		Valid: isValid,
	}, nil
}

func (s *Blake3Service) StreamHash(req *pb.StreamHashRequest, stream pb.Blake3Service_StreamHashServer) error {
	sh := s.bridge.NewStreamingHasher(req.Context)
	defer sh.Close()

	// Process incoming data
	go func() {
		chunk := make([]byte, 64*1024)
		for {
			n, err := req.Data.Read(chunk)
			if err == io.EOF {
				break
			}
			if err != nil {
				return
			}
			sh.Write(chunk[:n])
		}
	}()

	// Send results
	for result := range sh.Results() {
		if err := stream.Send(&pb.HashResponse{
			Hash: result.Hash,
			Hex:  result.Hex,
		}); err != nil {
			return err
		}
	}

	return nil
}
