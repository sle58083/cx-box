package model

import "testing"

func TestSelectedInboundIDs(t *testing.T) {
	one := "in-a"
	// 都为空 → nil（全部用户入口）。
	if ids := (&Client{}).SelectedInboundIDs(); ids != nil {
		t.Fatalf("empty client should select all (nil), got %v", ids)
	}
	// 只有旧单选 → [单选]。
	if ids := (&Client{InboundID: &one}).SelectedInboundIDs(); len(ids) != 1 || ids[0] != "in-a" {
		t.Fatalf("legacy single binding: got %v", ids)
	}
	// 多选优先于单选。
	c := &Client{InboundID: &one}
	c.SetInboundIDs([]string{"in-b", "in-c"})
	if ids := c.SelectedInboundIDs(); len(ids) != 2 || ids[0] != "in-b" || ids[1] != "in-c" {
		t.Fatalf("multi-select should win: got %v", ids)
	}
	// 清空多选 → 回落到单选。
	c.SetInboundIDs(nil)
	if ids := c.SelectedInboundIDs(); len(ids) != 1 || ids[0] != "in-a" {
		t.Fatalf("cleared multi-select should fall back to single: got %v", ids)
	}
	// 损坏的 JSON → 视为未设置。
	bad := &Client{InboundIDs: "{oops"}
	if ids := bad.SelectedInboundIDs(); ids != nil {
		t.Fatalf("corrupt InboundIDs should be ignored: got %v", ids)
	}
}
