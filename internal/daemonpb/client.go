package daemonpb

// 手写的 StartedService 客户端存根（只含 cx-box 用到的两个 RPC）。
// 服务名与方法路径与 sing-box 上游 daemon.StartedService 完全一致，
// 线路格式由 started_service.pb.go 的消息定义保证兼容。

import (
	"context"

	"google.golang.org/grpc"
	"google.golang.org/protobuf/types/known/emptypb"
)

// StartedServiceClient 是 sing-box API service 的最小客户端。
type StartedServiceClient struct {
	cc grpc.ClientConnInterface
}

// NewStartedServiceClient 用已建立的连接构造客户端。
func NewStartedServiceClient(cc grpc.ClientConnInterface) *StartedServiceClient {
	return &StartedServiceClient{cc: cc}
}

// GetVersion 返回内核版本信息（同时用作连通性探测）。
func (c *StartedServiceClient) GetVersion(ctx context.Context) (*Version, error) {
	out := new(Version)
	if err := c.cc.Invoke(ctx, "/daemon.StartedService/GetVersion", new(emptypb.Empty), out); err != nil {
		return nil, err
	}
	return out, nil
}

// SubscribeConnections 订阅连接事件流（服务端按 interval 周期推送流量增量）。
// 调用方循环对返回的 stream 调用 RecvMsg(&ConnectionEvents{}) 直到出错。
// 注意：必须先把请求消息发出去并关闭发送方向，服务端处理函数才会开始
// 工作——手写存根最容易漏掉这一步（表现为流永远收不到任何消息）。
func (c *StartedServiceClient) SubscribeConnections(ctx context.Context, req *SubscribeConnectionsRequest) (grpc.ClientStream, error) {
	stream, err := c.cc.NewStream(ctx, &grpc.StreamDesc{
		StreamName:    "SubscribeConnections",
		ServerStreams: true,
	}, "/daemon.StartedService/SubscribeConnections")
	if err != nil {
		return nil, err
	}
	if err := stream.SendMsg(req); err != nil {
		return nil, err
	}
	if err := stream.CloseSend(); err != nil {
		return nil, err
	}
	return stream, nil
}
