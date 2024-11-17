// go-backend/pkg/server/grpc_server.go
package server

import (
	"context"
	"fmt"
	"io"
	"net"
	"sync"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/keepalive"

	"github.com/theaxiomverse/go-backend/pkg/crypto/bridge"
	pb "github.com/theaxiomverse/go-backend/pkg/proto/crypto"
)

type CryptoServer struct {
	pb.UnimplementedBlake3ServiceServer
	bridge *bridge.Blake3Bridge
	mu     sync.RWMutex
	// Track active streams
	streams map[string]*streamState
}

type streamState struct {
	bytesProcessed int64
	totalBytes     int64
	startTime      time.Time
}

func NewCryptoServer() *CryptoServer {
	return &CryptoServer{
		bridge:  bridge.NewBlake3Bridge(),
		streams: make(map[string]*streamState),
	}
}

// Hash implements the Hash RPC method
func (s *CryptoServer) Hash(ctx context.Context, req *pb.HashRequest) (*pb.HashResponse, error) {
	result, err := s.bridge.Hash(req.Data, req.Context)
	if err != nil {
		return nil, fmt.Errorf("hashing failed: %v", err)
	}

	return &pb.HashResponse{
		Hash: result.Hash,
		Hex:  result.Hex,
	}, nil
}

// Verify implements the Verify RPC method
func (s *CryptoServer) Verify(ctx context.Context, req *pb.VerifyRequest) (*pb.VerifyResponse, error) {
	isValid := s.bridge.VerifyPythonHash(req.Data, req.Context, req.ExpectedHash)
	return &pb.VerifyResponse{
		Valid: isValid,
	}, nil
}

// StreamHash implements the streaming hash RPC method
func (s *CryptoServer) StreamHash(stream pb.Blake3Service_StreamHashServer) error {
	streamID := fmt.Sprintf("stream-%d", time.Now().UnixNano())

	// Initialize stream state
	s.mu.Lock()
	s.streams[streamID] = &streamState{
		startTime: time.Now(),
	}
	s.mu.Unlock()

	defer func() {
		s.mu.Lock()
		delete(s.streams, streamID)
		s.mu.Unlock()
	}()

	hasher := s.bridge.NewStreamingHasher("")
	defer hasher.Close()

	// Process incoming chunks
	for {
		req, err := stream.Recv()
		if err == io.EOF {
			break
		}
		if err != nil {
			return fmt.Errorf("receive error: %v", err)
		}

		// Initialize hasher context if not already done
		if hasher.Context() == "" {
			hasher.SetContext(req.Context)
		}

		// Update stream state
		s.mu.Lock()
		state := s.streams[streamID]
		state.bytesProcessed += int64(len(req.Data))
		if req.ChunkSize > 0 {
			state.totalBytes = req.ChunkSize
		}
		s.mu.Unlock()

		// Process chunk
		if _, err := hasher.Write(req.Data); err != nil {
			return fmt.Errorf("hash update failed: %v", err)
		}

		// Send intermediate result
		result := hasher.CurrentResult()
		response := &pb.HashResponse{
			Hash:           result.Hash,
			Hex:            result.Hex,
			BytesProcessed: state.bytesProcessed,
			TotalBytes:     state.totalBytes,
		}

		if err := stream.Send(response); err != nil {
			return fmt.Errorf("send error: %v", err)
		}
	}

	return nil
}

// CreateCertificate implements the certificate creation RPC method
func (s *CryptoServer) CreateCertificate(ctx context.Context, req *pb.CertificateRequest) (*pb.CertificateResponse, error) {
	cert, err := s.bridge.CreateCertificate(req.PublicKey, req.Libp2pKey, req.Roles, int(req.ValidityDays))
	if err != nil {
		return nil, fmt.Errorf("certificate creation failed: %v", err)
	}

	return &pb.CertificateResponse{
		Certificate: cert.Certificate,
		Signature:   cert.Signature,
		Hash:        cert.Hash,
	}, nil
}

// VerifyCertificate implements the certificate verification RPC method
func (s *CryptoServer) VerifyCertificate(ctx context.Context, req *pb.CertificateVerifyRequest) (*pb.CertificateVerifyResponse, error) {
	isValid, err := s.bridge.VerifyCertificate(req.Certificate, req.Signature)
	if err != nil {
		return &pb.CertificateVerifyResponse{
			Valid: false,
			Error: err.Error(),
		}, nil
	}

	return &pb.CertificateVerifyResponse{
		Valid: isValid,
	}, nil
}

// Serve starts the gRPC server
func Serve(address string) error {
	listener, err := net.Listen("tcp", address)
	if err != nil {
		return fmt.Errorf("failed to listen: %v", err)
	}

	// Configure keepalive policies
	serverParams := keepalive.ServerParameters{
		MaxConnectionIdle:     15 * time.Minute,
		MaxConnectionAge:      30 * time.Minute,
		MaxConnectionAgeGrace: 5 * time.Second,
		Time:                  5 * time.Second,
		Timeout:               1 * time.Second,
	}

	serverOpts := []grpc.ServerOption{
		grpc.KeepaliveParams(serverParams),
	}

	grpcServer := grpc.NewServer(serverOpts...)
	pb.RegisterBlake3ServiceServer(grpcServer, NewCryptoServer())

	fmt.Printf("Starting gRPC server on %s\n", address)
	return grpcServer.Serve(listener)
}
