// Core correlation engine logic
const core = require('@actions/core');
const { getArtifactId, getPairKey } = require('./utils/artifacts');
const { resolveTokenToArtifacts, resolveRulePairsToArtifacts } = require('./utils/matching');
const { isCriticalPair, dedupeEvidence, clamp01, hasFileLine } = require('./utils/safety');

// Apply user-defined correlation rules with safety rails
function applyUserDefinedRules(expandedResults, correlationConfig, processedPairs) {
  const correlations = [];
  if (!correlationConfig?.correlationRules) return correlations;
  
  core.info(`Applying ${correlationConfig.correlationRules.length} user-defined correlation rules`);
  
  for (const rule of correlationConfig.correlationRules) {
    // Handle ignore rules with safety rails
    if (rule.type === 'ignore') {
      const sources = resolveTokenToArtifacts(expandedResults, rule.source);
      const targets = resolveTokenToArtifacts(expandedResults, rule.target);
      
      for (const s of sources) {
        for (const t of targets) {
          if (s === t) continue;
          const key = getPairKey(s, t);
          
          // Safety rail: don't ignore critical pairs
          if (isCriticalPair(s, t)) {
            core.warning(`Ignore rule overruled for CRITICAL pair ${key} — rule kept but not applied.`);
            continue;
          }
          
          processedPairs.add(key);
          core.info(`Ignoring correlation: ${key} (${rule.reason || 'user-defined'})`);
        }
      }
      continue;
    }
    
    // Handle explicit mapping rules
    const sources = resolveTokenToArtifacts(expandedResults, rule.source);
    const targets = resolveTokenToArtifacts(expandedResults, rule.target);
    
    sources.forEach(source => {
      targets.forEach(target => {
        if (source !== target) {
          const pairKey = getPairKey(source, target);
          processedPairs.add(pairKey);
          
          correlations.push({
            source,
            target,
            relationship: rule.type,
            confidence: 1.0,
            userDefined: true,
            details: rule.description || `User-defined ${rule.type} correlation`,
            evidence: rule.evidence || [],
            rule
          });
          
          core.info(`Applied user-defined correlation: ${rule.type} between ${getArtifactId(source)} and ${getArtifactId(target)}`);
        }
      });
    });
  }
  
  return correlations;
}

// Select candidate pairs for expensive strategies
function selectCandidatePairs(preliminarySignals, rules, expandedResults, config) {
  const candidates = new Set();
  const thresholds = config?.thresholds || { correlate_min: 0.55 };
  const limits = config?.limits || { top_k_per_source: 3, max_pairs_high_cost: 100 };
  
  // Group by source
  const signalsBySource = new Map();
  preliminarySignals.forEach(signal => {
    const sourceId = getArtifactId(signal.source);
    if (!signalsBySource.has(sourceId)) signalsBySource.set(sourceId, []);
    signalsBySource.get(sourceId).push(signal);
  });
  
  // Select top-K above threshold
  signalsBySource.forEach(signals => {
    signals.sort((a, b) => b.confidence - a.confidence);
    signals.slice(0, limits.top_k_per_source).forEach(signal => {
      if (signal.confidence >= thresholds.correlate_min) {
        candidates.add(getPairKey(signal.source, signal.target));
      }
    });
  });
  
  // Add non-ignore rule pairs only
  const nonIgnoreRules = (rules || []).filter(r => r.type !== 'ignore');
  const rulePairs = resolveRulePairsToArtifacts(expandedResults, nonIgnoreRules);
  rulePairs.forEach(pair => candidates.add(pair));
  
  // Limit total
  if (candidates.size > limits.max_pairs_high_cost) {
    return new Set(Array.from(candidates).slice(0, limits.max_pairs_high_cost));
  }
  
  return candidates;
}

// Aggregate correlations with correct weighted scoring
function aggregateCorrelations(userCorrelations, strategySignals, strategiesByName, processedPairs, config) {
  const correlationMap = new Map();
  const thresholds = config?.thresholds || { block_min: 0.80 };
  
  // Process user-defined first (explicit strategy)
  userCorrelations.forEach(corr => {
    const key = getPairKey(corr.source, corr.target);
    correlationMap.set(key, {
      ...corr,
      strategies: ['explicit'],
      scores: { explicit: 1.0 },
      weights: { explicit: 1.0 },
      finalScore: 1.0, // Monotonicity rule
      relationships: new Set([corr.relationship]),
      evidence: corr.evidence || [],
      explanation: `User-defined: ${corr.details}`
    });
    processedPairs.add(key);
  });
  
  // Aggregate strategy signals
  strategySignals.forEach((signals, strategyName) => {
    const strategy = strategiesByName[strategyName];
    if (!strategy || !strategy.enabled || !signals) return;
    
    signals.forEach(signal => {
      const key = getPairKey(signal.source, signal.target);
      if (processedPairs.has(key)) return;
      
      let correlation = correlationMap.get(key);
      if (!correlation) {
        correlation = {
          source: signal.source,
          target: signal.target,
          strategies: [],
          scores: {},
          weights: {},
          evidence: [],
          relationships: new Set()
        };
        correlationMap.set(key, correlation);
      }
      
      // Track strategy name (avoid duplicates)
      if (!correlation.strategies.includes(strategyName)) {
        correlation.strategies.push(strategyName);
        correlation.weights[strategyName] = strategy.weight;
      }
      
      // Take max confidence if strategy emits multiple signals for same pair
      const prevScore = correlation.scores[strategyName] ?? -1;
      const nextScore = clamp01(signal.confidence);
      
      // Replace on higher confidence, or equal confidence with richer evidence
      if (nextScore > prevScore || 
          (nextScore === prevScore && hasFileLine(signal.evidence))) {
        correlation.scores[strategyName] = nextScore;
        
        // Track evidence from winning signal per strategy
        correlation._evidenceByStrategy ??= {};
        const structured = (signal.evidence || []).slice(0, 2).map(e => 
          typeof e === 'string' 
            ? { reason: e } 
            : { 
                reason: String(e?.reason ?? ''), 
                file: e?.file, 
                line: e?.line 
              }
        );
        correlation._evidenceByStrategy[strategyName] = structured;
      }
      
      // Track all relationships (guard against undefined)
      if (signal.relationship) {
        correlation.relationships.add(signal.relationship);
      }
    });
  });
  
  // Consolidate evidence from all strategies and calculate final scores
  correlationMap.forEach(corr => {
    // Consolidate evidence from winning signals per strategy
    if (corr._evidenceByStrategy) {
      const flat = Object.values(corr._evidenceByStrategy).flat();
      corr.evidence = dedupeEvidence(flat).slice(0, 5);
      delete corr._evidenceByStrategy; // Clean up temp field
    }
    // Calculate score with correct weighting
    if (corr.scores.explicit) {
      corr.finalScore = 1.0; // Monotonicity rule
    } else {
      let weightedSum = 0;
      let totalWeight = 0;
      Object.entries(corr.scores).forEach(([name, confidence]) => {
        const weight = corr.weights[name] || 1.0;
        const clampedConfidence = clamp01(confidence); // Ensure clamped here too
        weightedSum += clampedConfidence * weight;
        totalWeight += weight;
      });
      corr.finalScore = totalWeight > 0 ? Math.min(1.0, weightedSum / totalWeight) : 0;
    }
    
    // Format for backward compatibility
    corr.relationship = [...corr.relationships].sort().join('|');
    corr.confidence = corr.finalScore;
    
    // Build explanation
    const scoreBreakdown = corr.strategies.map(s => {
      const raw = corr.scores[s];
      const w = corr.weights[s] ?? 1;
      return `${s}:${raw.toFixed(2)}×${w.toFixed(1)}`;
    }).join(', ');
    
    corr.explanation = `${getArtifactId(corr.source)} → ${getArtifactId(corr.target)} = ${corr.finalScore.toFixed(2)} [${scoreBreakdown}]`;
  });
  
  return Array.from(correlationMap.values());
}

module.exports = {
  applyUserDefinedRules,
  selectCandidatePairs,
  aggregateCorrelations
};