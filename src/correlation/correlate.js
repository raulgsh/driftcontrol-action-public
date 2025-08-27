// Main cross-layer correlation orchestration
const core = require('@actions/core');
const { expandResults, getArtifactId } = require('./utils/artifacts');
const { extractMetadata } = require('./utils/extraction');
const { applyUserDefinedRules, selectCandidatePairs, aggregateCorrelations } = require('./engine');

// Strategy imports
const EntityCorrelationStrategy = require('./strategies/entity');
const OperationCorrelationStrategy = require('./strategies/operation');
const InfrastructureCorrelationStrategy = require('./strategies/infrastructure');
const DependencyCorrelationStrategy = require('./strategies/dependency');
const TemporalCorrelationStrategy = require('./strategies/temporal');

// Main cross-layer correlation function
async function correlateAcrossLayers(driftResults, files, correlationConfig = null) {
  const processedPairs = new Set();
  const strategiesByName = {};
  
  // Expand multi-item results into atomic artifacts
  const expandedResults = expandResults(driftResults);
  
  // Build metadata and IDs for expanded results
  expandedResults.forEach(result => {
    if (!result.metadata) {
      result.metadata = extractMetadata(result, files);
    }
    result.artifactId = getArtifactId(result);
  });
  
  // Initialize strategies with config
  const strategyConfig = correlationConfig?.strategyConfig || {};
  const strategies = [
    new EntityCorrelationStrategy(strategyConfig.entity || {}),
    new OperationCorrelationStrategy(strategyConfig.operation || {}),
    new InfrastructureCorrelationStrategy(strategyConfig.infrastructure || {}),
    new DependencyCorrelationStrategy(strategyConfig.dependency || {}),
    new TemporalCorrelationStrategy(strategyConfig.temporal || { enabled: false })
  ].filter(s => s.enabled); // Only include enabled strategies
  
  strategies.forEach(s => strategiesByName[s.name] = s);
  
  // Apply user-defined rules first
  const userCorrelations = applyUserDefinedRules(expandedResults, correlationConfig, processedPairs);
  
  // Run low-cost strategies with timing
  const strategySignals = new Map();
  const lowCostStrategies = strategies.filter(s => s.budget === 'low');
  
  for (const strategy of lowCostStrategies) {
    const t0 = Date.now();
    const signals = await strategy.run({
      driftResults: expandedResults, 
      files, 
      config: correlationConfig,
      processedPairs, 
      candidatePairs: null
    });
    core.debug(`[${strategy.name}] ${signals.length} signals in ${Date.now()-t0}ms`);
    strategySignals.set(strategy.name, signals);
  }
  
  // Select candidates
  const preliminarySignals = Array.from(strategySignals.values()).flat();
  const candidatePairs = selectCandidatePairs(
    preliminarySignals,
    correlationConfig?.correlationRules,
    expandedResults,
    correlationConfig
  );
  core.debug(`Selected ${candidatePairs.size} candidate pairs for expensive strategies`);
  
  // Run expensive strategies on candidates
  const expensiveStrategies = strategies.filter(s => s.budget !== 'low');
  for (const strategy of expensiveStrategies) {
    const t0 = Date.now();
    const signals = await strategy.run({
      driftResults: expandedResults, 
      files, 
      config: correlationConfig,
      processedPairs, 
      candidatePairs
    });
    core.debug(`[${strategy.name}] ${signals.length} signals in ${Date.now()-t0}ms`);
    strategySignals.set(strategy.name, signals);
  }
  
  // Aggregate
  return aggregateCorrelations(
    userCorrelations, 
    strategySignals, 
    strategiesByName,
    processedPairs, 
    correlationConfig
  );
}

module.exports = {
  correlateAcrossLayers
};