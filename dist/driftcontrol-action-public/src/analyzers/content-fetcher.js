const core = require('@actions/core');

/**
 * Content Fetcher abstraction layer
 * Decouples analyzers from GitHub API by providing a simple content fetching interface
 * 
 * Extracted from common patterns in:
 * - src/analyzers/openapi/io.js:39-64 (loadSpec function) 
 * - src/analyzers/sql/analyzer.js:45-52
 * - src/analyzers/iac/terraform.js:14-26, 32-44
 * - src/analyzers/config/yaml.js:21-28, 43-49
 * - src/analyzers/config/docker-compose.js:11-18, 31-38
 * - src/analyzers/config/package-lock/index.js:43-49
 */
class ContentFetcher {
  constructor(octokit, owner, repo) {
    this.octokit = octokit;
    this.owner = owner;
    this.repo = repo;
  }

  /**
   * Fetch file content from GitHub repository
   * @param {string} path - File path in repository
   * @param {string} ref - Git reference (SHA, branch, tag)
   * @param {string} description - Optional description for logging
   * @returns {Promise<{content: string, rawData: object}>}
   * @throws {Error} When file cannot be fetched
   */
  async fetchContent(path, ref, description = '') {
    try {
      core.info(`Fetching ${description || path} from ${ref}`);
      
      const { data } = await this.octokit.rest.repos.getContent({
        owner: this.owner,
        repo: this.repo,
        path,
        ref
      });
      
      const content = Buffer.from(data.content, 'base64').toString();
      
      return {
        content,
        rawData: data
      };
    } catch (error) {
      core.info(`Failed to fetch ${description || path} from ${ref}: ${error.message}`);
      throw error;
    }
  }

  /**
   * Safely fetch file content, returns null if file doesn't exist
   * @param {string} path - File path in repository
   * @param {string} ref - Git reference (SHA, branch, tag) 
   * @param {string} description - Optional description for logging
   * @returns {Promise<{content: string, rawData: object} | null>}
   */
  async fetchContentSafe(path, ref, description = '') {
    try {
      return await this.fetchContent(path, ref, description);
    } catch (error) {
      if (error.status === 404 || error.message === 'Not Found') {
        core.info(`No ${description || path} found at ${ref}: ${error.message}`);
        return null;
      }
      // Re-throw non-404 errors
      throw error;
    }
  }

  /**
   * Batch fetch multiple files efficiently
   * @param {Array<{path: string, ref: string, description?: string}>} requests
   * @returns {Promise<Array<{content: string, rawData: object} | null>>}
   */
  async batchFetch(requests) {
    const results = await Promise.allSettled(
      requests.map(request => 
        this.fetchContentSafe(request.path, request.ref, request.description)
      )
    );

    return results.map(result => 
      result.status === 'fulfilled' ? result.value : null
    );
  }
}

module.exports = ContentFetcher;