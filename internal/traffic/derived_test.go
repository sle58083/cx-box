package traffic

import (
	"testing"

	"github.com/sle58083/cx-box/internal/daemonpb"
	"github.com/sle58083/cx-box/internal/renderer"
)

// TestLedgerDerivedUserAttribution 覆盖派生用户流量归因：多出口订阅
// 节点的连接 user 是派生名（客户端ID#出口ID），流量应记到基础客户端
// 名下，而不是掉进入站级。
func TestLedgerDerivedUserAttribution(t *testing.T) {
	l := newLedger()
	l.setKnownClients(map[string]bool{"client-1": true})
	derived := renderer.DerivedUserName("client-1", "ob-9")
	l.applyBatch(&daemonpb.ConnectionEvents{Reset_: true, Events: []*daemonpb.ConnectionEvent{
		ev(daemonpb.ConnectionEventType_CONNECTION_EVENT_NEW, conn("d1", derived, "vless-in", 100, 200, 0), 0, 0),
	}})
	deltas := l.drain()
	if len(deltas) != 1 || deltas[0].ClientID != "client-1" || deltas[0].Up != 100 || deltas[0].Down != 200 {
		t.Fatalf("deltas = %v, want client-1 100/200", deltas)
	}
}
