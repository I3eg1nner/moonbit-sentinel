///|
/// LLM 交互预算：极简智能体的硬上限。
/// 任何编排（当前为单次调用 + 一次重试 ≤2 次）都必须经过预算扣减；
/// 预算耗尽后 complete 直接失败，防止未来演化为多步循环时失控。
pub(all) struct CallBudget {
  limit : Int
  mut remaining : Int
} derive(Debug)

///|
/// 极简智能体设计约束：与大模型的交互次数不得超过 20 次
pub const MAX_LLM_CALLS = 20

///|
pub fn CallBudget::new(limit? : Int = MAX_LLM_CALLS) -> CallBudget {
  { limit, remaining: limit, }
}

///|
/// 扣减一次预算；返回 false 表示已耗尽（不得发起调用）
pub fn CallBudget::spend(self : CallBudget) -> Bool {
  if self.remaining <= 0 {
    return false
  }
  self.remaining = self.remaining - 1
  true
}

///|
/// 已用次数
pub fn CallBudget::used(self : CallBudget) -> Int {
  self.limit - self.remaining
}
