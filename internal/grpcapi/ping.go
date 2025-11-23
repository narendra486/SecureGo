package grpcapi

import (
	"context"

	"google.golang.org/grpc"
)

// PingRequest/PingResponse are minimal structs to demonstrate an application RPC.
type PingRequest struct {
	Message string
}

type PingResponse struct {
	Message string
}

// PingServiceServer describes the Ping RPC.
type PingServiceServer interface {
	Ping(context.Context, *PingRequest) (*PingResponse, error)
}

// pingService is a default implementation.
type pingService struct{}

func (p pingService) Ping(ctx context.Context, req *PingRequest) (*PingResponse, error) {
	return &PingResponse{Message: "pong: " + req.Message}, nil
}

// RegisterPing registers the Ping service on a gRPC server.
// If srv is nil, a default implementation is used.
func RegisterPing(s *grpc.Server, srv PingServiceServer) {
	if srv == nil {
		srv = pingService{}
	}
	s.RegisterService(&grpc.ServiceDesc{
		ServiceName: "securego.PingService",
		HandlerType: (*PingServiceServer)(nil),
		Methods: []grpc.MethodDesc{
			{
				MethodName: "Ping",
				Handler: func(srv interface{}, ctx context.Context, dec func(interface{}) error, _ grpc.UnaryServerInterceptor) (interface{}, error) {
					in := new(PingRequest)
					if err := dec(in); err != nil {
						return nil, err
					}
					return srv.(PingServiceServer).Ping(ctx, in)
				},
			},
		},
	}, srv)
}
