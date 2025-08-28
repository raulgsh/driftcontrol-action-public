// Base class for pluggable correlation strategies

class CorrelationStrategy {
  constructor(name, config = {}) {
    this.name = name;
    this.weight = Math.max(0, Math.min(1, config.weight || 1.0));
    this.enabled = config.enabled !== false;
    this.budget = config.budget || 'low'; // 'low', 'medium', 'high'
  }
  
  async run({ driftResults, files, config, processedPairs, candidatePairs }) {
    // Override in implementations
    return [];
  }
}

module.exports = CorrelationStrategy;