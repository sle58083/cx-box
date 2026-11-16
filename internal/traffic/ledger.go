package traffic

// ledger 是采集器的记账核心（纯逻辑，无 IO，便于单测）。
//
// 计数不变量：每条连接维护 base = 已入账的累计字节（上/下行）。服务端在
// 每次订阅开始时发一批 Reset 全量状态（活跃连接 + 近期已关闭连接，带累计
// 总量），账本据此对齐：增量 = 总量 - base，未见过的连接从 0 起算——这样
// 采集器重启/重连都不会重复计数，也不会漏掉订阅空窗期关闭的连接。
// 后续 UPDATE 事件自带服务端算好的增量，直接入账并推进 base；CLOSED
// 事件带最终总量，按 总量 - base 补齐尾巴。

import (
	"sort"
	"time"

	"github.com/sle58083/cx-box/internal/daemonpb"
	"github.com/sle58083/cx-box/internal/renderer"
	"github.com/sle58083/cx-box/internal/service"
)

// aggKey 是聚合维度：客户端 + 入站 tag。
type aggKey struct {
	clientID string
	inbound  string
}

type ledger struct {
	base    map[string][2]int64 // connID -> 已入账累计（up, down）
	closed  map[string]bool     // connID -> 已关闭（reset 修剪用）
	attr    map[string]aggKey   // connID -> 归因（UPDATE 事件不带连接信息，靠它）
	known   map[string]bool     // 已知客户端 ID 集合（user 归因校验）
	pending map[aggKey][2]int64 // 待落库增量

	// IP 数限制：连接来源跟踪（仅归因到客户端的连接）。IP 的计数用
	// 滑动窗口语义：窗口内（ipLiveGrace）有过连接的 IP 都算「在用」，
	// 避免不同来源交替连接时封锁集合反复横跳。
	src       map[string]connSrc   // connID -> 来源（客户端 + IP）
	firstSeen map[string]time.Time // clientID|ip -> 窗口内首次出现（放行名额排序依据）
	lastSeen  map[string]time.Time // clientID|ip -> 最近一次连接活动
}

// connSrc 是一条活跃连接的来源（IP 数限制用）。
type connSrc struct {
	clientID string
	ip       string
}

func newLedger() *ledger {
	return &ledger{
		base:      map[string][2]int64{},
		closed:    map[string]bool{},
		attr:      map[string]aggKey{},
		known:     map[string]bool{},
		pending:   map[aggKey][2]int64{},
		src:       map[string]connSrc{},
		firstSeen: map[string]time.Time{},
		lastSeen:  map[string]time.Time{},
	}
}

func (l *ledger) setKnownClients(ids map[string]bool) { l.known = ids }

// keyOf 把连接的 user/inbound 归因成聚合维度：user 是 cx-box 注入的客户
// 端 ID；不在已知集合里（或为空，如非用户入站的连接）记为入站级流量。
func (l *ledger) keyOf(conn *daemonpb.Connection) aggKey {
	clientID := ""
	if conn.User != "" {
		if l.known[conn.User] {
			clientID = conn.User
		} else if base := renderer.BaseClientID(conn.User); base != conn.User && l.known[base] {
			// 派生用户（多出口订阅节点）的流量归因到基础客户端。
			clientID = base
		}
	}
	return aggKey{clientID: clientID, inbound: conn.Inbound}
}

func (l *ledger) addPending(key aggKey, up, down int64) {
	if up < 0 {
		up = 0
	}
	if down < 0 {
		down = 0
	}
	if up == 0 && down == 0 {
		return
	}
	cur := l.pending[key]
	l.pending[key] = [2]int64{cur[0] + up, cur[1] + down}
}

// applyBatch 处理一批连接事件（Reset 批走全量对齐，其余按事件类型分发）。
func (l *ledger) applyBatch(b *daemonpb.ConnectionEvents) {
	if b == nil {
		return
	}
	if b.Reset_ {
		inBatch := make(map[string]bool, len(b.Events))
		inLive := make(map[string]bool, len(b.Events))
		for _, ev := range b.Events {
			inBatch[ev.Id] = true
			if ev.Connection != nil && ev.Connection.ClosedAt == 0 {
				inLive[ev.Id] = true
			}
			l.applyInitial(ev)
		}
		// 修剪：已关闭且服务端不再上报的连接，其墓碑已完成使命。
		for id := range l.base {
			if l.closed[id] && !inBatch[id] {
				delete(l.base, id)
				delete(l.attr, id)
				delete(l.closed, id)
			}
		}
		// 来源跟踪对齐：不在本批活跃集合里的连接视为已消失（服务端
		// 订阅空窗期关闭的连接可能没有 CLOSED 事件到账）。
		for id := range l.src {
			if !inLive[id] {
				l.untrackConn(id)
			}
		}
		return
	}
	for _, ev := range b.Events {
		switch ev.Type {
		case daemonpb.ConnectionEventType_CONNECTION_EVENT_NEW:
			l.register(ev)
		case daemonpb.ConnectionEventType_CONNECTION_EVENT_UPDATE:
			l.applyUpdate(ev)
		case daemonpb.ConnectionEventType_CONNECTION_EVENT_CLOSED:
			l.applyClosed(ev)
		}
	}
}

// applyInitial 对齐 Reset 批里的一条连接（活跃或已关闭）。
func (l *ledger) applyInitial(ev *daemonpb.ConnectionEvent) {
	conn := ev.Connection
	if conn == nil {
		return
	}
	totals := [2]int64{conn.UplinkTotal, conn.DownlinkTotal}
	key := l.keyOf(conn)
	if prev, ok := l.base[ev.Id]; ok {
		l.addPending(key, totals[0]-prev[0], totals[1]-prev[1])
	} else {
		l.addPending(key, totals[0], totals[1])
	}
	l.base[ev.Id] = totals
	l.attr[ev.Id] = key
	if conn.ClosedAt > 0 {
		l.closed[ev.Id] = true
		l.untrackConn(ev.Id)
	} else {
		l.trackConn(ev.Id, key.clientID, conn.Source)
	}
}

// register 登记一条新建连接（增量将由后续 UPDATE/CLOSED 事件带来）。
func (l *ledger) register(ev *daemonpb.ConnectionEvent) {
	conn := ev.Connection
	if conn == nil {
		return
	}
	l.base[ev.Id] = [2]int64{conn.UplinkTotal, conn.DownlinkTotal}
	key := l.keyOf(conn)
	l.attr[ev.Id] = key
	l.trackConn(ev.Id, key.clientID, conn.Source)
}

// applyUpdate 入账服务端算好的增量。
func (l *ledger) applyUpdate(ev *daemonpb.ConnectionEvent) {
	key, ok := l.attr[ev.Id]
	if !ok {
		return // 没见过这条连接的 NEW（订阅空窗），增量无从归因，宁漏勿错
	}
	l.addPending(key, ev.UplinkDelta, ev.DownlinkDelta)
	cur := l.base[ev.Id]
	l.base[ev.Id] = [2]int64{cur[0] + ev.UplinkDelta, cur[1] + ev.DownlinkDelta}
}

// applyClosed 按最终总量补齐连接尾巴并立墓碑。
func (l *ledger) applyClosed(ev *daemonpb.ConnectionEvent) {
	conn := ev.Connection
	if conn == nil {
		l.closed[ev.Id] = true
		l.untrackConn(ev.Id)
		return
	}
	totals := [2]int64{conn.UplinkTotal, conn.DownlinkTotal}
	key := l.keyOf(conn)
	if prev, ok := l.base[ev.Id]; ok {
		l.addPending(key, totals[0]-prev[0], totals[1]-prev[1])
	} else {
		l.addPending(key, totals[0], totals[1])
	}
	l.base[ev.Id] = totals
	l.attr[ev.Id] = key
	l.closed[ev.Id] = true
	l.untrackConn(ev.Id)
}

// drain 取出全部待落库增量并清空。
func (l *ledger) drain() []service.UsageDelta {
	if len(l.pending) == 0 {
		return nil
	}
	out := make([]service.UsageDelta, 0, len(l.pending))
	for k, v := range l.pending {
		out = append(out, service.UsageDelta{
			ClientID:   k.clientID,
			InboundTag: k.inbound,
			Up:         v[0],
			Down:       v[1],
		})
	}
	l.pending = map[aggKey][2]int64{}
	return out
}

// requeue 把落库失败的增量放回待办（下个周期重试）。
func (l *ledger) requeue(deltas []service.UsageDelta) {
	for _, d := range deltas {
		l.addPending(aggKey{clientID: d.ClientID, inbound: d.InboundTag}, d.Up, d.Down)
	}
}

// ipLiveGrace 是 IP 计数的滑动窗口：窗口内有过连接活动的 IP 都算
// 「在用」。与封锁保持期同为 10 分钟，语义一致。
const ipLiveGrace = 10 * time.Minute

// trackConn 登记一条活跃连接的来源（IP 数限制用）。归因不到客户端
// （入站级连接）或来源为空时不跟踪。
func (l *ledger) trackConn(connID, clientID, source string) {
	if clientID == "" {
		return
	}
	ip := sourceIP(source)
	if ip == "" {
		return
	}
	l.src[connID] = connSrc{clientID: clientID, ip: ip}
	key := clientID + "|" + ip
	now := time.Now()
	if _, ok := l.firstSeen[key]; !ok {
		l.firstSeen[key] = now
	}
	l.lastSeen[key] = now
}

// untrackConn 注销一条连接的来源跟踪，并把该 IP 的最近活动时间记到
// 现在（窗口期内它仍算「在用」）。
func (l *ledger) untrackConn(connID string) {
	s, ok := l.src[connID]
	if !ok {
		return
	}
	delete(l.src, connID)
	l.lastSeen[s.clientID+"|"+s.ip] = time.Now()
}

// liveIPs 返回每个客户端在计数窗口内的来源 IP（有活跃连接、或最近
// 活动在窗口内的 IP），按窗口内首次出现升序；顺手修剪过期记录。
func (l *ledger) liveIPs() map[string][]ipLive {
	now := time.Now()
	byClient := make(map[string]map[string]bool)
	mark := func(clientID, ip string) {
		if byClient[clientID] == nil {
			byClient[clientID] = make(map[string]bool)
		}
		byClient[clientID][ip] = true
	}
	for _, s := range l.src {
		mark(s.clientID, s.ip)
	}
	for key, last := range l.lastSeen {
		if now.Sub(last) < ipLiveGrace {
			clientID, ip := splitFirstSeenKey(key)
			mark(clientID, ip)
		}
	}
	out := make(map[string][]ipLive, len(byClient))
	for clientID, ips := range byClient {
		list := make([]ipLive, 0, len(ips))
		for ip := range ips {
			list = append(list, ipLive{IP: ip, FirstSeen: l.firstSeen[clientID+"|"+ip]})
		}
		sort.Slice(list, func(i, j int) bool {
			if !list[i].FirstSeen.Equal(list[j].FirstSeen) {
				return list[i].FirstSeen.Before(list[j].FirstSeen)
			}
			return list[i].IP < list[j].IP
		})
		out[clientID] = list
	}
	for key, last := range l.lastSeen {
		clientID, ip := splitFirstSeenKey(key)
		if byClient[clientID] == nil || !byClient[clientID][ip] || now.Sub(last) >= ipLiveGrace {
			delete(l.lastSeen, key)
			delete(l.firstSeen, key)
		}
	}
	return out
}

// splitFirstSeenKey 从后往前找分隔符拆 firstSeen 的 key（IP 本身不含
// '|'，客户端 ID 是 UUID 也不含，从后拆最稳）。
func splitFirstSeenKey(key string) (clientID, ip string) {
	for i := len(key) - 1; i >= 0; i-- {
		if key[i] == '|' {
			return key[:i], key[i+1:]
		}
	}
	return key, ""
}
