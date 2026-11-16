package traffic

import (
	"testing"
	"time"

	"github.com/sle58083/cx-box/internal/daemonpb"
)

func TestSourceIP(t *testing.T) {
	cases := map[string]string{
		"192.168.1.5:12345":  "192.168.1.5",
		"[2001:db8::1]:443": "2001:db8::1",
		"10.0.0.9":          "10.0.0.9",
		"":                  "",
		"garbage":           "",
	}
	for in, want := range cases {
		if got := sourceIP(in); got != want {
			t.Fatalf("sourceIP(%q) = %q, want %q", in, got, want)
		}
	}
}

// TestIPBlockerFlow 覆盖执法状态机：超限 IP 连续 2 个周期才封、封锁
// 保持期内不解除、老 IP 下线后被封 IP 落入名额立即解除、上限关闭时
// 封锁清空。
func TestIPBlockerFlow(t *testing.T) {
	b := newIPBlocker()
	t0 := time.Unix(1700000000, 0)
	limits := map[string]int{"c1": 1}
	liveAB := map[string][]ipLive{"c1": {
		{IP: "1.1.1.1", FirstSeen: t0},
		{IP: "2.2.2.2", FirstSeen: t0.Add(time.Minute)},
	}}

	// 第 1 个周期：只是候选，不封。
	snap, changed := b.evaluate(t0, liveAB, limits)
	if changed || len(snap) != 0 {
		t.Fatalf("cycle1: snap=%v changed=%v, want empty/false", snap, changed)
	}
	// 第 2 个周期：封 2.2.2.2。
	snap, changed = b.evaluate(t0.Add(10*time.Second), liveAB, limits)
	if !changed || len(snap["c1"]) != 1 || snap["c1"][0] != "2.2.2.2" {
		t.Fatalf("cycle2: snap=%v changed=%v, want block 2.2.2.2", snap, changed)
	}
	b.markSent(snap)
	// 已下发后同一状态不再报变化。
	if _, changed = b.evaluate(t0.Add(20*time.Second), liveAB, limits); changed {
		t.Fatal("steady state should not report change")
	}
	// 1.1.1.1 下线，只剩被封的 2.2.2.2：落入放行名额，立即解除。
	liveB := map[string][]ipLive{"c1": {{IP: "2.2.2.2", FirstSeen: t0.Add(time.Minute)}}}
	snap, changed = b.evaluate(t0.Add(30*time.Second), liveB, limits)
	if !changed || len(snap) != 0 {
		t.Fatalf("after A offline: snap=%v changed=%v, want empty/true", snap, changed)
	}
	b.markSent(snap)
	// 上限关闭：任何残留封锁都应清空（此处已为空，验证不 panic 且无变化）。
	snap, changed = b.evaluate(t0.Add(40*time.Second), liveB, map[string]int{})
	if changed || len(snap) != 0 {
		t.Fatalf("limit off: snap=%v changed=%v", snap, changed)
	}
}

// TestIPBlockerHoldExpiry 覆盖保持期：被封 IP 即使连接全断，封锁也
// 保持到 10 分钟到期才解除（防反复封/解导致内核频繁重启）。
func TestIPBlockerHoldExpiry(t *testing.T) {
	b := newIPBlocker()
	t0 := time.Unix(1700000000, 0)
	limits := map[string]int{"c1": 1}
	liveAB := map[string][]ipLive{"c1": {
		{IP: "1.1.1.1", FirstSeen: t0},
		{IP: "2.2.2.2", FirstSeen: t0.Add(time.Minute)},
	}}
	b.evaluate(t0, liveAB, limits)
	snap, _ := b.evaluate(t0.Add(10*time.Second), liveAB, limits)
	b.markSent(snap)

	empty := map[string][]ipLive{}
	snap, changed := b.evaluate(t0.Add(time.Minute), empty, limits)
	if changed || len(snap["c1"]) != 1 {
		t.Fatalf("within hold: snap=%v changed=%v, want still blocked", snap, changed)
	}
	snap, changed = b.evaluate(t0.Add(11*time.Minute), empty, limits)
	if !changed || len(snap) != 0 {
		t.Fatalf("after hold: snap=%v changed=%v, want cleared", snap, changed)
	}
}

// TestLedgerLiveIPs 覆盖账本的来源跟踪：NEW 登记、CLOSED 移除、
// Reset 全量对齐修剪已消失的连接。
func TestLedgerLiveIPs(t *testing.T) {
	l := newLedger()
	l.setKnownClients(map[string]bool{"c1": true})
	mk := func(id, user, source string) *daemonpb.ConnectionEvent {
		return ev(daemonpb.ConnectionEventType_CONNECTION_EVENT_NEW,
			&daemonpb.Connection{Id: id, User: user, Inbound: "ss-in", Source: source}, 0, 0)
	}
	l.applyBatch(&daemonpb.ConnectionEvents{Events: []*daemonpb.ConnectionEvent{
		mk("a1", "c1", "1.1.1.1:1000"),
		mk("a2", "c1", "1.1.1.1:1001"),
		mk("b1", "c1", "2.2.2.2:2000"),
		mk("x1", "someone-else", "9.9.9.9:3000"),
	}})
	live := l.liveIPs()
	if len(live["c1"]) != 2 {
		t.Fatalf("liveIPs c1 = %v, want 2 IPs", live["c1"])
	}
	if len(live) != 1 {
		t.Fatalf("unknown user should not be tracked: %v", live)
	}
	// 关闭 2.2.2.2 的连接后，窗口期内它仍算「在用」（滑动窗口语义）。
	l.applyBatch(&daemonpb.ConnectionEvents{Events: []*daemonpb.ConnectionEvent{
		ev(daemonpb.ConnectionEventType_CONNECTION_EVENT_CLOSED,
			&daemonpb.Connection{Id: "b1", User: "c1", Inbound: "ss-in", Source: "2.2.2.2:2000"}, 0, 0),
	}})
	live = l.liveIPs()
	if len(live["c1"]) != 2 {
		t.Fatalf("after close (grace): %v, want 2 IPs", live["c1"])
	}
	// 把 2.2.2.2 的最近活动拨回窗口外：不再计数。
	l.lastSeen["c1|2.2.2.2"] = time.Now().Add(-ipLiveGrace - time.Minute)
	live = l.liveIPs()
	if len(live["c1"]) != 1 || live["c1"][0].IP != "1.1.1.1" {
		t.Fatalf("after grace expiry: %v", live["c1"])
	}
	// Reset 只带 a1：a2 的来源跟踪应被修剪（连接已消失）。
	l.applyBatch(&daemonpb.ConnectionEvents{Reset_: true, Events: []*daemonpb.ConnectionEvent{
		ev(daemonpb.ConnectionEventType_CONNECTION_EVENT_NEW,
			&daemonpb.Connection{Id: "a1", User: "c1", Inbound: "ss-in", Source: "1.1.1.1:1000"}, 0, 0),
	}})
	live = l.liveIPs()
	if len(live["c1"]) != 1 || live["c1"][0].IP != "1.1.1.1" {
		t.Fatalf("after reset: %v", live["c1"])
	}
}
