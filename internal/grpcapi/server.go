package grpcapi

import (
	"context"
	"strings"
	"time"

	"Securego/internal/middleware"
	"Securego/internal/telemetry"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/health"
	healthpb "google.golang.org/grpc/health/grpc_health_v1"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"
)

// Config holds gRPC security knobs.
type Config struct {
	Timeout             time.Duration
	MaxRecvBytes        int
	MaxSendBytes        int
	AllowJSON           bool
	AllowedContentTypes []string
}

// DefaultConfig returns hardened defaults with JSON disallowed unless explicitly enabled.
func DefaultConfig() Config {
	return Config{
		Timeout:      5 * time.Second,
		MaxRecvBytes: 4 << 20,
		MaxSendBytes: 4 << 20,
		AllowJSON:    false,
	}
}

// NewServer returns a gRPC server with hardened defaults and unary interceptors.
func NewServer(logger telemetry.Logger, cfg Config) *grpc.Server {
	if cfg.MaxRecvBytes <= 0 {
		cfg.MaxRecvBytes = 4 << 20
	}
	if cfg.MaxSendBytes <= 0 {
		cfg.MaxSendBytes = 4 << 20
	}
	allowedCT := []string{"application/grpc", "application/grpc+proto"}
	if cfg.AllowJSON {
		allowedCT = append(allowedCT, "application/grpc+json", "application/json")
	}
	if len(cfg.AllowedContentTypes) > 0 {
		allowedCT = cfg.AllowedContentTypes
	}
	unaryInterceptors := []grpc.UnaryServerInterceptor{
		recoverUnary(logger),
		timeoutUnary(cfg.Timeout),
		contentTypeUnary(allowedCT),
		logUnary(logger),
	}
	opts := []grpc.ServerOption{
		grpc.ChainUnaryInterceptor(unaryInterceptors...),
		grpc.MaxRecvMsgSize(cfg.MaxRecvBytes),
		grpc.MaxSendMsgSize(cfg.MaxSendBytes),
	}
	s := grpc.NewServer(opts...)
	healthServer := health.NewServer()
	healthpb.RegisterHealthServer(s, healthServer)
	healthServer.SetServingStatus("", healthpb.HealthCheckResponse_SERVING)
	return s
}

func logUnary(logger telemetry.Logger) grpc.UnaryServerInterceptor {
	return func(ctx context.Context, req any, info *grpc.UnaryServerInfo, handler grpc.UnaryHandler) (any, error) {
		start := time.Now()
		resp, err := handler(ctx, req)
		code := status.Code(err)
		logger.Info("grpc request",
			"method", info.FullMethod,
			"code", code,
			"duration_ms", time.Since(start).Milliseconds(),
			"request_id", middleware.GetRequestID(ctx),
		)
		return resp, err
	}
}

func timeoutUnary(d time.Duration) grpc.UnaryServerInterceptor {
	return func(ctx context.Context, req any, info *grpc.UnaryServerInfo, handler grpc.UnaryHandler) (any, error) {
		if d <= 0 {
			return handler(ctx, req)
		}
		ctx, cancel := context.WithTimeout(ctx, d)
		defer cancel()
		resp, err := handler(ctx, req)
		if err != nil {
			if ctx.Err() == context.DeadlineExceeded {
				return nil, status.Errorf(codes.DeadlineExceeded, "deadline exceeded")
			}
		}
		return resp, err
	}
}

func recoverUnary(logger telemetry.Logger) grpc.UnaryServerInterceptor {
	return func(ctx context.Context, req any, info *grpc.UnaryServerInfo, handler grpc.UnaryHandler) (resp any, err error) {
		defer func() {
			if r := recover(); r != nil {
				logger.Error("panic recovered", "method", info.FullMethod, "err", r)
				err = status.Errorf(codes.Internal, "internal")
			}
		}()
		return handler(ctx, req)
	}
}

func contentTypeUnary(allowed []string) grpc.UnaryServerInterceptor {
	return func(ctx context.Context, req any, info *grpc.UnaryServerInfo, handler grpc.UnaryHandler) (any, error) {
		md, ok := metadata.FromIncomingContext(ctx)
		if ok {
			if cts := md.Get("content-type"); len(cts) > 0 {
				ct := strings.ToLower(cts[0])
				for _, allow := range allowed {
					if ct == strings.ToLower(allow) {
						return handler(ctx, req)
					}
				}
				return nil, status.Errorf(codes.InvalidArgument, "unsupported content-type")
			}
		}
		return handler(ctx, req)
	}
}
