// Main IaC analyzer orchestration
const core = require('@actions/core');
const riskScorer = require('../../risk-scorer');
const terraformAnalysis = require('./terraform');
const cloudformationAnalysis = require('./cloudformation');

class IaCAnalyzer {
  constructor() {
    this.riskScorer = riskScorer;
  }

  async analyzeIaCFiles(files, octokit, owner, repo, pullRequest, terraformPath, cloudformationGlob, costThreshold) {
    const pullRequestHeadSha = pullRequest.head.sha;
    const pullRequestBaseSha = pullRequest.base.sha;
    const driftResults = [];
    let hasHighSeverity = false;
    let hasMediumSeverity = false;

    try {
      // Process Terraform plan if specified
      if (terraformPath && files.some(f => f.filename === terraformPath)) {
        const tfResult = await terraformAnalysis.analyzeTerraformPlan(
          octokit, owner, repo, pullRequest, terraformPath, costThreshold
        );
        if (tfResult) {
          driftResults.push(tfResult);
          if (tfResult.severity === 'high') hasHighSeverity = true;
          if (tfResult.severity === 'medium') hasMediumSeverity = true;
        }
      }

      // Process CloudFormation templates if specified
      if (cloudformationGlob) {
        const cfResults = await cloudformationAnalysis.analyzeCloudFormationTemplates(
          files, octokit, owner, repo, pullRequest, cloudformationGlob, costThreshold
        );
        for (const result of cfResults) {
          driftResults.push(result);
          if (result.severity === 'high') hasHighSeverity = true;
          if (result.severity === 'medium') hasMediumSeverity = true;
        }
      }
    } catch (error) {
      core.warning(`IaC analysis error: ${error.message}`);
    }

    return { driftResults, hasHighSeverity, hasMediumSeverity };
  }
}

module.exports = IaCAnalyzer;