// Correlation module barrel - re-exports for backward compatibility

// Main correlation orchestration
const { correlateAcrossLayers } = require('./correlate');

// Core engine functions
const { applyUserDefinedRules, selectCandidatePairs, aggregateCorrelations } = require('./engine');

// Relation detection and root cause analysis
const { detectRelation, identifyRootCauses } = require('./relation');

// Base strategy class
const CorrelationStrategy = require('./strategy-base');

// Strategy implementations
const EntityCorrelationStrategy = require('./strategies/entity');
const OperationCorrelationStrategy = require('./strategies/operation');
const InfrastructureCorrelationStrategy = require('./strategies/infrastructure');
const DependencyCorrelationStrategy = require('./strategies/dependency');
const TemporalCorrelationStrategy = require('./strategies/temporal');

// Utility functions
const { 
  getArtifactId, 
  getPairKey, 
  expandResults,
  normPath,
  normApi
} = require('./utils/artifacts');

const {
  matchToken,
  resolveTokenToArtifacts,
  resolveRulePairsToArtifacts
} = require('./utils/matching');

const {
  isCriticalPair,
  dedupeEvidence,
  clamp01,
  hasFileLine
} = require('./utils/safety');

const {
  extractMetadata,
  extractTableNamesWithConfidence
} = require('./utils/extraction');

const {
  generateEntityVariations,
  findBestMatch,
  levenshteinDistance
} = require('./utils/text');

const {
  correlateFields,
  detectApiOperations,
  detectDbOperations,
  operationsCorrelate
} = require('./utils/operations');

module.exports = {
  // Main functions
  correlateAcrossLayers,
  detectRelation,
  identifyRootCauses,
  
  // Engine functions
  applyUserDefinedRules,
  selectCandidatePairs,
  aggregateCorrelations,
  
  // Strategy classes
  CorrelationStrategy,
  EntityCorrelationStrategy,
  OperationCorrelationStrategy,
  InfrastructureCorrelationStrategy,
  DependencyCorrelationStrategy,
  TemporalCorrelationStrategy,
  
  // Utility functions
  getArtifactId,
  getPairKey,
  expandResults,
  normPath,
  normApi,
  matchToken,
  resolveTokenToArtifacts,
  resolveRulePairsToArtifacts,
  isCriticalPair,
  dedupeEvidence,
  clamp01,
  hasFileLine,
  extractMetadata,
  extractTableNamesWithConfidence,
  generateEntityVariations,
  findBestMatch,
  levenshteinDistance,
  correlateFields,
  detectApiOperations,
  detectDbOperations,
  operationsCorrelate
};