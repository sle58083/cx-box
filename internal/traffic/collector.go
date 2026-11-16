// Package traffic 实现 cx-box 的流量采集器：订阅 sing-box 1.14 官方
// api service 的连接事件流（daemon.StartedService/SubscribeConnections），
// 按连接事件里的 user 字段（cx-box 注入的用户 name 即客户端 ID）把字节
// 增量精确归因到客户端，聚合后批量落库（见 service.TrafficService）。
//
// 为什么不用 Clash API：其 /connections 元数据不含 user，只能按入站统计；
// v2ray_api 又不在官方构建里。api service 是官方构建自带的 gRPC 接口，
// 连接对象带 user + 累计字节，是唯一能做 per-user 统计的官方通道。
package traffic

import (
	"context"
	"log"
	"sync/atomic"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/metadata"

	"github.com/sle58083/cx-box/internal/daemonpb"
	"github.com/sle58083/cx-box/internal/service"
)

// Config 是采集器配置（函数字段由 run 层接线，便于测试替换）。
type Config struct {
	Addr   string // api service 地址，如 127.0.0.1:19090
	Secret string // api service 密钥（Bearer）
	Sink   interface {
		RecordUsage(ctx context.Context, deltas []service.UsageDelta) error
	}
	// ClientIDs 返回当前全部客户端 ID 集合，用于把连接 user 归因到客户端；
	// 不在集合里的 user（或空 user）记为入站级流量（ClientID 为空）。
	ClientIDs func(ctx context.Context) (map[string]bool, error)
	// OverQuota 返回是否存在已启用但超额的客户端；Apply 重新应用配置。
	OverQuota func(ctx context.Context) (bool, error)
	Apply     func(ctx context.Context) error
	// IPLimits 返回设置了 IP 数限制的客户端（ID -> 上限）；
	// ApplyIPBlocks 在封锁集合变化时把集合交给 configsvc 并重新应用。
	IPLimits      func(ctx context.Context) (map[string]int, error)
	ApplyIPBlocks func(ctx context.Context, blocks map[string][]string) error
	Logf          func(format string, args ...any)

	FlushInterval time.Duration // 落库周期，默认 10s
	EventInterval time.Duration // 向内核订阅的推送周期，默认 5s
}

// Collector 持续订阅连接事件并落库；断线自动重连（账本跨重连保留，
// 配合服务端的 reset 全量同步不会重复计数，见 ledger）。
type Collector struct {
	cfg           Config
	ledger        *ledger
	connected     atomic.Bool
	lastApply     time.Time
	lastKnownSync time.Time

	blocker     *ipBlocker
	lastIPApply time.Time
}

// refreshKnown 同步已知客户端集合（归因依据）。必须在订阅开始前先同步
// 一次，否则会话最初几秒的连接会因集合为空而被误记成入站级流量。
func (c *Collector) refreshKnown(ctx context.Context) {
	if c.cfg.ClientIDs == nil {
		return
	}
	if ids, err := c.cfg.ClientIDs(ctx); err == nil {
		c.ledger.setKnownClients(ids)
		c.lastKnownSync = time.Now()
	}
}

// New 构造采集器（补齐默认参数）。
func New(cfg Config) *Collector {
	if cfg.Logf == nil {
		cfg.Logf = log.Printf
	}
	if cfg.FlushInterval <= 0 {
		cfg.FlushInterval = 10 * time.Second
	}
	if cfg.EventInterval <= 0 {
		cfg.EventInterval = 5 * time.Second
	}
	return &Collector{cfg: cfg, ledger: newLedger(), blocker: newIPBlocker()}
}

// Connected 返回当前是否与内核 api service 保持着订阅。
func (c *Collector) Connected() bool { return c.connected.Load() }

// Run 阻塞运行采集循环，直到 ctx 取消。内核未启动/重启都会走重连。
func (c *Collector) Run(ctx context.Context) {
	backoff := 2 * time.Second
	for {
		if ctx.Err() != nil {
			return
		}
		err := c.session(ctx)
		c.connected.Store(false)
		if ctx.Err() != nil {
			return
		}
		if err != nil {
			c.cfg.Logf("traffic: 与内核 api service 的订阅中断: %v（%s 后重连）", err, backoff)
		}
		select {
		case <-ctx.Done():
			return
		case <-time.After(backoff):
		}
		if backoff < 30*time.Second {
			backoff *= 2
		}
	}
}

// session 是一次订阅的生命周期：建连 → 订阅 → 收事件入账本 → 周期落库。
func (c *Collector) session(ctx context.Context) error {
	conn, err := grpc.NewClient("passthrough:///"+c.cfg.Addr,
		grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		return err
	}
	defer conn.Close()

	c.refreshKnown(ctx)

	client := daemonpb.NewStartedServiceClient(conn)
	sctx := metadata.AppendToOutgoingContext(ctx, "authorization", "Bearer "+c.cfg.Secret)
	if _, err := client.GetVersion(sctx); err != nil {
		return err
	}
	stream, err := client.SubscribeConnections(sctx,
		&daemonpb.SubscribeConnectionsRequest{Interval: int64(c.cfg.EventInterval)})
	if err != nil {
		return err
	}
	c.connected.Store(true)
	c.cfg.Logf("traffic: 已订阅内核连接事件（%s）", c.cfg.Addr)

	batches := make(chan *daemonpb.ConnectionEvents, 32)
	recvErr := make(chan error, 1)
	go func() {
		for {
			evs := new(daemonpb.ConnectionEvents)
			if err := stream.RecvMsg(evs); err != nil {
				recvErr <- err
				return
			}
			select {
			case batches <- evs:
			case <-ctx.Done():
				return
			}
		}
	}()

	ticker := time.NewTicker(c.cfg.FlushInterval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			c.flush(context.Background())
			return nil
		case err := <-recvErr:
			c.flush(context.Background())
			return err
		case b := <-batches:
			if time.Since(c.lastKnownSync) > 5*time.Second {
				c.refreshKnown(ctx)
			}
			c.ledger.applyBatch(b)
		case <-ticker.C:
			c.flush(ctx)
		}
	}
}

// flush 把账本待落库增量写进 DB，随后做配额检查：有超额客户端且距上次
// 触发超过 30 秒时，重新应用配置把超额者从内核配置里剔除。
func (c *Collector) flush(ctx context.Context) {
	c.refreshKnown(ctx)
	deltas := c.ledger.drain()
	if len(deltas) > 0 {
		if err := c.cfg.Sink.RecordUsage(ctx, deltas); err != nil {
			c.cfg.Logf("traffic: 流量落库失败（增量已保留待重试）: %v", err)
			c.ledger.requeue(deltas)
			return
		}
	}
	c.enforceIPLimit(ctx)

	if c.cfg.OverQuota == nil || c.cfg.Apply == nil {
		return
	}
	over, err := c.cfg.OverQuota(ctx)
	if err != nil || !over {
		return
	}
	if time.Since(c.lastApply) < 30*time.Second {
		return
	}
	c.lastApply = time.Now()
	if err := c.cfg.Apply(ctx); err != nil {
		c.cfg.Logf("traffic: 超额剔除时重新应用配置失败: %v", err)
	} else {
		c.cfg.Logf("traffic: 已重新应用配置（剔除超额客户端）")
	}
}

// enforceIPLimit 是 IP 数限制的执法环节（每个落库周期跑一次）：账本
// 给出各客户端的活跃来源 IP，状态机算出应封锁集合；集合变化且距上次
// 下发超过 30 秒时，把集合交给 configsvc 并重新应用配置（封锁规则以
// source_ip_cidr + auth_user -> block 的形式进内核配置）。
func (c *Collector) enforceIPLimit(ctx context.Context) {
	if c.cfg.IPLimits == nil || c.cfg.ApplyIPBlocks == nil {
		return
	}
	limits, err := c.cfg.IPLimits(ctx)
	if err != nil {
		return
	}
	// limits 为空也要继续 evaluate：上限被全部关掉时旧封锁要随之清空。
	snapshot, changed := c.blocker.evaluate(time.Now(), c.ledger.liveIPs(), limits)
	if !changed {
		return
	}
	if time.Since(c.lastIPApply) < 30*time.Second {
		return
	}
	c.lastIPApply = time.Now()
	if err := c.cfg.ApplyIPBlocks(ctx, snapshot); err != nil {
		c.cfg.Logf("traffic: IP 数限制下发失败: %v", err)
		return
	}
	c.blocker.markSent(snapshot)
	c.cfg.Logf("traffic: IP 数限制封锁集合已更新: %v", snapshot)
}
