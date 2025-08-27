// Comment Generator Module - Barrel Export
// Re-exports all commenting functionality for backward compatibility

const { generateCommentBody } = require('./render');
const { generateFixSuggestion } = require('./templates');
const { getLLMExplanation, generateImpactSummary } = require('./llm');
const { buildCorrelationGraph, shortenPath, globToRegex } = require('./format');

module.exports = {
  generateCommentBody,
  generateFixSuggestion,
  getLLMExplanation,
  generateImpactSummary,
  buildCorrelationGraph,
  shortenPath,
  globToRegex
};