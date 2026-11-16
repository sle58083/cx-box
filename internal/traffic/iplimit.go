package traffic

import (
	"net"
	"sort"
	"time"
)

// IP 数限制执法（LimitIP）：采集器从连接事件里跟踪每个客户端的来源
// IP（滑动窗口语义：10 分钟窗口内有过连接活动的 IP 都算在用）；窗口
// 内来源 IP 数超过上限时，最早出现的 limit 个 IP 放行，超出的新 IP
// 被判定为「超限来源」。
//
// 内核 API 只有连接事件订阅、没有关连接接口，所以执法落到配置层：
// 超限 IP 经 configsvc 生成 source_ip_cidr + auth_user → block 的路由
// 规则下发。为防抖动：
//   - 同一超限 IP 连续 2 个采集周期都被判超限才真正封锁；
//   - 封锁带 10 分钟保持期，期内即使连接断开也不解除，避免反复
//     封/解导致内核频繁重启；
//   - 被封 IP 若后来落入放行名额（老 IP 都下线了），立即解除。

// ipLive 是一个客户端的一个活跃来源 IP。
type ipLive struct {
	IP        string
	FirstSeen time.Time
}

// sourceIP 从连接事件的 Source（host:port 形式）里取 IP 部分。
func sourceIP(source string) string {
	if source == "" {
		return ""
	}
	if host, _, err := net.SplitHostPort(source); err == nil {
		return host
	}
	if ip := net.ParseIP(source); ip != nil {
		return source
	}
	return ""
}

// ipBlockHold 是单个 IP 被封锁后的最短保持时间。
const ipBlockHold = 10 * time.Minute

// ipBlocker 维护「应下发的封锁集合」的状态机（纯逻辑，便于单测）。
type ipBlocker struct {
	desired    map[string]map[string]time.Time // clientID -> ip -> 封锁到期
	candidates map[string]map[string]int       // clientID -> ip -> 连续超限周期数
	sent       map[string][]string             // 上次成功下发的快照
}

func newIPBlocker() *ipBlocker {
	return &ipBlocker{
		desired:    make(map[string]map[string]time.Time),
		candidates: make(map[string]map[string]int),
		sent:       make(map[string][]string),
	}
}

// evaluate 根据当前活跃 IP 与各客户端上限推进状态机，返回当前应下发
// 的封锁快照与它是否不同于上次成功下发的快照。
func (b *ipBlocker) evaluate(now time.Time, live map[string][]ipLive, limits map[string]int) (map[string][]string, bool) {
	// 过期封锁清理；上限被关掉（limit<=0 或客户端不在 limits 里）的
	// 客户端，其封锁一并解除。
	for clientID, ips := range b.desired {
		if limits[clientID] <= 0 {
			delete(b.desired, clientID)
			continue
		}
		for ip, until := range ips {
			if !until.After(now) {
				delete(ips, ip)
			}
		}
		if len(ips) == 0 {
			delete(b.desired, clientID)
		}
	}

	for clientID, limit := range limits {
		if limit <= 0 {
			continue
		}
		ips := live[clientID] // 已按 FirstSeen 升序
		blocked := b.desired[clientID]

		// 放行名额：最早的 limit 个活跃 IP。被封 IP 若进了名额
		//（更早的 IP 都下线了），立即解除它的封锁。
		allowed := make(map[string]bool)
		for i, li := range ips {
			if i < limit {
				allowed[li.IP] = true
			}
		}
		for ip := range blocked {
			if allowed[ip] {
				delete(blocked, ip)
			}
		}

		// 超限判定：活跃 IP 里排除已封锁者后，超出 limit 的新 IP。
		var excess []string
		count := 0
		for _, li := range ips {
			if blocked != nil {
				if _, isBlocked := blocked[li.IP]; isBlocked {
					continue
				}
			}
			count++
			if count > limit {
				excess = append(excess, li.IP)
			}
		}

		// 候选累计：连续 2 个周期超限才封；本周期不超限的候选清零。
		cand := b.candidates[clientID]
		if cand == nil {
			cand = make(map[string]int)
			b.candidates[clientID] = cand
		}
		excessSet := make(map[string]bool, len(excess))
		for _, ip := range excess {
			excessSet[ip] = true
			cand[ip]++
			if cand[ip] >= 2 {
				if blocked == nil {
					blocked = make(map[string]time.Time)
					b.desired[clientID] = blocked
				}
				blocked[ip] = now.Add(ipBlockHold)
				delete(cand, ip)
			}
		}
		for ip := range cand {
			if !excessSet[ip] {
				delete(cand, ip)
			}
		}
		if len(cand) == 0 {
			delete(b.candidates, clientID)
		}
		if len(blocked) == 0 {
			delete(b.desired, clientID)
		}
	}

	snapshot := make(map[string][]string, len(b.desired))
	for clientID, ips := range b.desired {
		list := make([]string, 0, len(ips))
		for ip := range ips {
			list = append(list, ip)
		}
		sort.Strings(list)
		snapshot[clientID] = list
	}
	return snapshot, !ipSnapshotEqual(snapshot, b.sent)
}

// markSent 记录一次成功下发的快照。
func (b *ipBlocker) markSent(snapshot map[string][]string) {
	cp := make(map[string][]string, len(snapshot))
	for k, v := range snapshot {
		cp[k] = append([]string(nil), v...)
	}
	b.sent = cp
}

func ipSnapshotEqual(a, b map[string][]string) bool {
	if len(a) != len(b) {
		return false
	}
	for k, av := range a {
		bv, ok := b[k]
		if !ok || len(av) != len(bv) {
			return false
		}
		for i := range av {
			if av[i] != bv[i] {
				return false
			}
		}
	}
	return true
}
