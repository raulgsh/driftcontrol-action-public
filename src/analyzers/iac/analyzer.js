// Main IaC analyzer orchestration
const core = require('@actions/core');
const yaml = require('yaml');
const riskScorer = require('../../risk-scorer');
const terraformAnalysis = require('./terraform');
const cloudformationAnalysis = require('./cloudformation');

class IaCAnalyzer {
  constructor(contentFetcher = null) {
    this.riskScorer = riskScorer;
    this.contentFetcher = contentFetcher;
  }

  async analyzeIaCFiles(files, octokit, owner, repo, pullRequest, terraformPath, cloudformationGlob, costThreshold) {
    const driftResults = [];
    let hasHighSeverity = false;
    let hasMediumSeverity = false;

    try {
      // Process Terraform plan if specified
      if (terraformPath && files.some(f => f.filename === terraformPath)) {
        const tfResult = await terraformAnalysis.analyzeTerraformPlan(
          octokit, owner, repo, pullRequest, terraformPath, costThreshold, this.contentFetcher
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

      // Check for Kubernetes manifests
      const k8sFiles = files.filter(f => 
        (f.filename.endsWith('.yaml') || f.filename.endsWith('.yml'))
      ).filter(f => 
        // Simple heuristic for K8s files
        f.filename.includes('k8s/') || 
        f.filename.includes('kubernetes/') ||
        f.filename.includes('deployment') ||
        f.filename.includes('service.y')
      );

      for (const file of k8sFiles) {
        const k8sResult = await this.analyzeKubernetesManifest(
          octokit, owner, repo, pullRequest, file.filename
        );
        if (k8sResult) {
          driftResults.push(k8sResult);
          if (k8sResult.severity === 'high') hasHighSeverity = true;
          if (k8sResult.severity === 'medium') hasMediumSeverity = true;
        }
      }

      // Check for Terraform HCL files
      const hclFiles = files.filter(f => 
        f.filename.endsWith('.tf') || 
        f.filename.endsWith('.hcl')
      );

      for (const file of hclFiles) {
        const hclResult = await terraformAnalysis.analyzeHCLFile(
          octokit, owner, repo, pullRequest, file.filename, this.contentFetcher
        );
        if (hclResult) {
          driftResults.push(hclResult);
          if (hclResult.severity === 'high') hasHighSeverity = true;
          if (hclResult.severity === 'medium') hasMediumSeverity = true;
        }
      }

      // Check for Pulumi configuration files
      const pulumiFiles = files.filter(f => 
        f.filename === 'Pulumi.yaml' || 
        f.filename === 'Pulumi.prod.yaml' ||
        f.filename === 'Pulumi.dev.yaml'
      );

      for (const file of pulumiFiles) {
        const pulumiResult = await this.detectPulumiChanges(
          octokit, owner, repo, pullRequest, file.filename
        );
        if (pulumiResult) {
          driftResults.push(pulumiResult);
          // Pulumi changes are informational only (low severity)
        }
      }
    } catch (error) {
      core.warning(`IaC analysis error: ${error.message}`);
    }

    return { driftResults, hasHighSeverity, hasMediumSeverity };
  }

  async analyzeKubernetesManifest(octokit, owner, repo, pullRequest, filepath) {
    try {
      let content;
      
      if (this.contentFetcher) {
        const result = await this.contentFetcher.fetchContent(
          filepath, pullRequest.head.sha, `Kubernetes manifest ${filepath}`
        );
        content = result?.content;
      } else {
        // Legacy method for backward compatibility
        const { data: headData } = await octokit.rest.repos.getContent({
          owner, repo, path: filepath, ref: pullRequest.head.sha
        });
        content = Buffer.from(headData.content, 'base64').toString();
      }
      
      if (!content) {
        core.warning(`No content found for K8s manifest: ${filepath}`);
        return null;
      }
      const manifest = yaml.parse(content);
      
      const changes = [];
      
      // Detect high-risk K8s changes
      if (manifest.kind === 'Service' && manifest.spec?.type === 'LoadBalancer') {
        changes.push('K8S_LOADBALANCER_EXPOSED');
      }
      if (manifest.spec?.replicas === 0) {
        changes.push('K8S_REPLICAS_ZERO');
      }
      if (manifest.spec?.template?.spec?.containers?.some(c => !c.resources)) {
        changes.push('K8S_NO_RESOURCE_LIMITS');
      }
      if (manifest.spec?.template?.spec?.containers?.some(c => c.securityContext?.privileged)) {
        changes.push('K8S_PRIVILEGED_CONTAINER');
      }
      if (manifest.spec?.template?.spec?.hostNetwork) {
        changes.push('K8S_HOST_NETWORK_ENABLED');
      }
      
      if (changes.length > 0) {
        const scoringResult = this.riskScorer.scoreChanges(changes, 'KUBERNETES');
        return {
          type: 'infrastructure',
          file: filepath,
          severity: scoringResult.severity,
          changes: changes,
          reasoning: scoringResult.reasoning
        };
      }
    } catch (e) {
      core.warning(`K8s analysis failed for ${filepath}: ${e.message}`);
    }
    return null;
  }

  async detectPulumiChanges(octokit, owner, repo, pullRequest, filepath) {
    try {
      const changes = [`PULUMI_CONFIG_CHANGED: ${filepath}`];
      
      // Basic detection only - full analysis would require Pulumi CLI
      return {
        type: 'infrastructure',
        file: filepath,
        severity: 'low',
        changes: changes,
        reasoning: ['Pulumi configuration changed - run pulumi preview for detailed analysis'],
        note: 'Detection only - install Pulumi CLI for full analysis'
      };
    } catch (e) {
      core.warning(`Pulumi detection failed: ${e.message}`);
    }
    return null;
  }
}

module.exports = IaCAnalyzer;