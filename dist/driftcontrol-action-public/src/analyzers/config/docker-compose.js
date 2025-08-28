// Docker Compose analysis
const core = require('@actions/core');
const yaml = require('yaml');
const riskScorer = require('../../risk-scorer');

async function analyzeDockerCompose(octokit, owner, repo, pullRequestHeadSha, pullRequestBaseSha, composePath) {
  try {
    core.info(`Analyzing docker-compose: ${composePath}`);
    
    // Fetch current version
    const { data: headData } = await octokit.rest.repos.getContent({
      owner,
      repo,
      path: composePath,
      ref: pullRequestHeadSha
    });
    
    const headContent = Buffer.from(headData.content, 'base64').toString();
    const headCompose = yaml.parse(headContent);
    
    // Extract service and volume keys only
    const headKeys = [
      ...Object.keys(headCompose.services || {}).map(k => `services.${k}`),
      ...Object.keys(headCompose.volumes || {}).map(k => `volumes.${k}`),
      ...Object.keys(headCompose.networks || {}).map(k => `networks.${k}`)
    ];
    
    // Fetch base version
    let baseKeys = [];
    try {
      const { data: baseData } = await octokit.rest.repos.getContent({
        owner,
        repo,
        path: composePath,
        ref: pullRequestBaseSha
      });
      
      const baseContent = Buffer.from(baseData.content, 'base64').toString();
      const baseCompose = yaml.parse(baseContent);
      
      baseKeys = [
        ...Object.keys(baseCompose.services || {}).map(k => `services.${k}`),
        ...Object.keys(baseCompose.volumes || {}).map(k => `volumes.${k}`),
        ...Object.keys(baseCompose.networks || {}).map(k => `networks.${k}`)
      ];
    } catch (e) {
      core.info(`No base version found for docker-compose`);
    }
    
    const changes = [];
    const baseSet = new Set(baseKeys);
    const headSet = new Set(headKeys);
    
    const added = [...headSet].filter(k => !baseSet.has(k));
    const removed = [...baseSet].filter(k => !headSet.has(k));
    
    for (const key of removed) {
      changes.push(`CONTAINER_REMOVED: ${key}`);
    }
    
    for (const key of added) {
      changes.push(`CONTAINER_ADDED: ${key}`);
    }
    
    if (changes.length > 0) {
      const scoringResult = riskScorer.scoreChanges(changes, 'DOCKER_COMPOSE');
      
      return {
        type: 'configuration',
        file: composePath,
        severity: scoringResult.severity,
        changes: changes,
        reasoning: scoringResult.reasoning
      };
    }
  } catch (error) {
    core.warning(`docker-compose analysis failed: ${error.message}`);
  }
  
  return null;
}

module.exports = {
  analyzeDockerCompose
};