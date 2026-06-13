export interface EvalCacheLayer {
  name: string;
  type: string;
  scope?: string;
  hits?: number;
  misses?: number;
  hit_rate?: number;
  global_hits?: number;
  global_misses?: number;
  global_hit_rate?: number;
  global_size?: number;
  agents?: number;
  cost_usd?: number;
  note?: string;
}

export interface EvalSummary {
  total_cost_usd: number;
  cost_if_uncached_usd: number;
  cost_saved_usd: number;
  total_input_tokens: number;
  total_output_tokens: number;
  total_tokens: number;
  total_latency_ms: number;
  llm_cache_hits: number;
  llm_cache_misses: number;
  llm_cache_hit_rate: number;
  cache_layers: EvalCacheLayer[];
}

export interface EvalCall {
  model: string;
  input_tokens: number;
  output_tokens: number;
  total_tokens: number;
  cost_usd: number;
  cost_if_uncached_usd: number;
  cost_saved_usd: number;
  latency_ms: number;
  cache_hit: boolean;
  cache_strategy: string;
}

export interface EvalAgent {
  agent: string;
  label: string;
  type: 'deterministic' | 'external_api' | 'llm';
  latency_ms: number;
  error: boolean;
  cache: {
    strategy: string;
    reason?: string;
    hit?: boolean;
    hits?: number;
    misses?: number;
    hit_rate?: number;
  };
  tokens: { input: number; output: number; total: number };
  cost_usd: number;
  cost_if_uncached_usd: number;
  cost_saved_usd: number;
  model: string | null;
  calls: EvalCall[];
}

export interface EvalRun {
  session_id: string;
  started_at: string;
  completed_at: string | null;
  log_source: string;
  line_count: number;
  summary: EvalSummary;
}

export interface EvalsResponse {
  overall: {
    total_runs: number;
    total_cost_usd: number;
    total_cost_saved_usd: number;
    total_tokens: number;
    llm_cache_hits: number;
    llm_cache_misses: number;
    llm_cache_hit_rate: number;
    global_cache_hit_rate: number;
    global_cache_size: number;
  };
  runs: EvalRun[];
}

export interface EvalSessionDetail {
  session_id: string;
  started_at: string;
  completed_at: string | null;
  log_source: string;
  line_count: number;
  used_fallback: boolean;
  summary: EvalSummary;
  agents: EvalAgent[];
}
