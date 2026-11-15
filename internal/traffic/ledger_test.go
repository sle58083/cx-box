package traffic

import (
	"testing"

	"github.com/sle58083/cx-box/internal/daemonpb"
)

func conn(id, user, inbound string, up, down, closedAt int64) *daemonpb.Connection {
	return &daemonpb.Connection{
		Id: id, User: user, Inbound: inbound,
		UplinkTotal: up, DownlinkTotal: down, ClosedAt: closedAt,
	}
}

func ev(t daemonpb.ConnectionEventType, c *daemonpb.Connection, upDelta, downDelta int64) *daemonpb.ConnectionEvent {
	e := &daemonpb.ConnectionEvent{Type: t, UplinkDelta: upDelta, DownlinkDelta: downDelta}
	if c != nil {
		e.Id = c.Id
		e.Connection = c
	}
	return e
}

func TestLedgerResetUpdateClosed(t *testing.T) {
	l := newLedger()
	l.setKnownClients(map[string]bool{"client-1": true})

	// Reset：一条活跃连接（历史 100/200 全量入账）+ 一条已关闭（50/60）。
	l.applyBatch(&daemonpb.ConnectionEvents{Reset_: true, Events: []*daemonpb.ConnectionEvent{
		ev(daemonpb.ConnectionEventType_CONNECTION_EVENT_NEW, conn("c1", "client-1", "vless-in", 100, 200, 0), 0, 0),
		ev(daemonpb.ConnectionEventType_CONNECTION_EVENT_NEW, conn("c2", "client-1", "vless-in", 50, 60, 123), 0, 0),
	}})
	// UPDATE 增量入账；CLOSED 按最终总量补齐（300/400 - 已入账 110/215）。
	l.applyBatch(&daemonpb.ConnectionEvents{Events: []*daemonpb.ConnectionEvent{
		ev(daemonpb.ConnectionEventType_CONNECTION_EVENT_UPDATE, &daemonpb.Connection{Id: "c1"}, 10, 15),
	}})
	l.applyBatch(&daemonpb.ConnectionEvents{Events: []*daemonpb.ConnectionEvent{
		ev(daemonpb.ConnectionEventType_CONNECTION_EVENT_CLOSED, conn("c1", "client-1", "vless-in", 300, 400, 999), 0, 0),
	}})

	deltas := l.drain()
	if len(deltas) != 1 {
		t.Fatalf("deltas = %v, want 1 aggregated row", deltas)
	}
	d := deltas[0]
	// 期望：up = 100+50+10+(300-110) = 350；down = 200+60+15+(400-215) = 460
	if d.ClientID != "client-1" || d.InboundTag != "vless-in" || d.Up != 350 || d.Down != 460 {
		t.Fatalf("delta = %+v, want client-1/vless-in 350/460", d)
	}
}

func TestLedgerReconnectDoesNotDoubleCount(t *testing.T) {
	l := newLedger()
	l.setKnownClients(map[string]bool{"client-1": true})
	l.applyBatch(&daemonpb.ConnectionEvents{Reset_: true, Events: []*daemonpb.ConnectionEvent{
		ev(daemonpb.ConnectionEventType_CONNECTION_EVENT_NEW, conn("c1", "client-1", "in", 100, 100, 0), 0, 0),
	}})
	_ = l.drain()
	// 重连后同样的 Reset 全量：base 已对齐，增量应为 0。
	l.applyBatch(&daemonpb.ConnectionEvents{Reset_: true, Events: []*daemonpb.ConnectionEvent{
		ev(daemonpb.ConnectionEventType_CONNECTION_EVENT_NEW, conn("c1", "client-1", "in", 100, 100, 0), 0, 0),
		ev(daemonpb.ConnectionEventType_CONNECTION_EVENT_NEW, conn("c2", "client-1", "in", 40, 40, 555), 0, 0),
	}})
	deltas := l.drain()
	if len(deltas) != 1 || deltas[0].Up != 40 || deltas[0].Down != 40 {
		t.Fatalf("deltas = %v, want only the newly closed c2 40/40", deltas)
	}
}

func TestLedgerUnknownUserFallsToInboundLevel(t *testing.T) {
	l := newLedger()
	l.setKnownClients(map[string]bool{"client-1": true})
	l.applyBatch(&daemonpb.ConnectionEvents{Reset_: true, Events: []*daemonpb.ConnectionEvent{
		ev(daemonpb.ConnectionEventType_CONNECTION_EVENT_NEW, conn("c9", "someone-else", "ss-in", 7, 8, 0), 0, 0),
		ev(daemonpb.ConnectionEventType_CONNECTION_EVENT_NEW, conn("c10", "", "ss-in", 1, 2, 0), 0, 0),
	}})
	deltas := l.drain()
	if len(deltas) != 1 || deltas[0].ClientID != "" || deltas[0].Up != 8 || deltas[0].Down != 10 {
		t.Fatalf("deltas = %v, want inbound-level 8/10", deltas)
	}
	// 未知连接的 UPDATE 被忽略（无归因不入账）。
	l.applyBatch(&daemonpb.ConnectionEvents{Events: []*daemonpb.ConnectionEvent{
		{Type: daemonpb.ConnectionEventType_CONNECTION_EVENT_UPDATE, Id: "ghost", UplinkDelta: 5},
	}})
	if got := l.drain(); len(got) != 0 {
		t.Fatalf("ghost update accounted: %v", got)
	}
}
