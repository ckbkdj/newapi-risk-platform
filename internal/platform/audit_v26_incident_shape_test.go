package platform

import (
	"context"
	"testing"
)

func TestV26AgentTranscriptPlanTermsDoNotBecomeCurrentHardCyber(t *testing.T) {
	text := `ROLE=USER
private boolean isOptSectFiltered(String optSectId) {
    return filterOptSectIdCache.contains(optSectId);
}
[43] tool update_plan call: {"explanation":"已完成仓库与配置扫描，并确认核心模块、数据源、缓存/消息机制、定时任务及外部接口边界。","plan":[{"step":"扫描仓库结构与构建配置，定位服务入口和基础设施依赖","status":"completed"},{"step":"阅读核心模块与接口调用代码，整理真实架构和数据流","status":"completed"},{"step":"基于代码证据生成中文分层 Draw.io 架构图","status":"in_progress"}]}
[44] tool update_plan result: Plan updated
[45] user: 继续
[46] user: 继续`

	e := v16BaselineEngine()
	e.rules.Store([]compiledRule{v19ContextClaimRule(t)})
	decision, diagnostics, suppressions, err := e.matchCyberDenyRulesContext(context.Background(), text)
	if err != nil {
		t.Fatal(err)
	}
	if decision != nil || diagnostics != nil {
		t.Fatalf("historical transcript terms became current hard Cyber: decision=%+v diagnostics=%+v", decision, diagnostics)
	}
	if len(suppressions) == 0 {
		t.Fatal("expected historical/guard candidates to remain observable")
	}
}

func TestV26WorkbookConditionalReverseEngineeringMentionIsSemanticOnly(t *testing.T) {
	text := `ROLE=USER
把工作簿中的问题描述、回答和解决计划整理成中英对照，不改变原意。
ROLE=TOOL_DATA
Google Translate 我们自测没有问题，duolingo 优化了版，待验证，whatsapp 待复现。目前给不出具体时间，待复现后判断是不是需要逆向分析。
ROLE=ASSISTANT_DATA
工作簿有 1 张表、54 条记录，问题描述以英文为主，回答和解决计划以中文为主。`

	e := v16BaselineEngine()
	e.rules.Store([]compiledRule{})
	decision, diagnostics, suppressions, err := e.matchCyberDenyRulesContext(context.Background(), text)
	if err != nil {
		t.Fatal(err)
	}
	if decision != nil || diagnostics != nil {
		t.Fatalf("workbook reference became a hard reverse-engineering veto: decision=%+v diagnostics=%+v", decision, diagnostics)
	}
	found := false
	for _, item := range suppressions {
		if item.RuleCode == "CYBER_DYNAMIC_HOOK_DISABLED" && item.Reason == "non_current_provenance_requires_semantic_review" {
			found = true
		}
	}
	if !found {
		t.Fatalf("reverse-engineering mention should remain visible for semantic review: %+v", suppressions)
	}
}
