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

// PingService implements a simple unary Ping method.
type PingService struct{}

func (p PingService) Ping(ctx context.Context, req *PingRequest) (*PingResponse, error) {
	return &PingResponse{Message: "pong: " + req.Message}, nil
}

// RegisterPing registers the Ping service on a gRPC server.
func RegisterPing(s *grpc.Server) {
	s.RegisterService(&grpc.ServiceDesc{
		ServiceName: "securego.PingService",
		HandlerType: (*PingService)(nil),
		Methods: []grpc.MethodDesc{
			{
				MethodName: "Ping",
				Handler: func(srv interface{}, ctx context.Context, dec func(interface{}) error, _ grpc.UnaryServerInterceptor) (interface{}, error) {
					in := new(PingRequest)
					if err := dec(in); err != nil {
						return nil, err
					}
					return srv.(PingService).Ping(ctx, in)
				},
			},
		},
	}, PingService{})
}
