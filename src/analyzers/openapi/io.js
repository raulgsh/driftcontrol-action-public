const core = require('@actions/core');
const SwaggerParser = require('@apidevtools/swagger-parser');
const yaml = require('yaml');

/**
 * OpenAPI IO utilities - spec loading and rename detection
 */

// Detect OpenAPI spec file renames (add+delete pair per CLAUDE.md:55)
function detectSpecRenames(files, openApiPath) {
  let actualOpenApiPath = openApiPath;
  let renamedFromPath = null;
  
  // Check for OpenAPI spec rename scenario
  const deletedFiles = files.filter(f => f.status === 'removed');
  const addedFiles = files.filter(f => f.status === 'added');
  
  // Look for OpenAPI file extensions in renamed files
  const openApiExtensions = ['.yaml', '.yml', '.json'];
  const isOpenApiFile = (filename) => openApiExtensions.some(ext => filename.endsWith(ext));
  
  for (const deletedFile of deletedFiles) {
    if (isOpenApiFile(deletedFile.filename)) {
      // Check if there's a corresponding added file that could be a rename
      const possibleRename = addedFiles.find(f => isOpenApiFile(f.filename));
      if (possibleRename) {
        renamedFromPath = deletedFile.filename;
        actualOpenApiPath = possibleRename.filename;
        core.info(`Detected OpenAPI spec rename: ${renamedFromPath} → ${actualOpenApiPath}`);
        break;
      }
    }
  }

  return { actualOpenApiPath, renamedFromPath };
}

// Load and parse OpenAPI spec from GitHub
async function loadSpec(octokit, owner, repo, path, ref, description) {
  try {
    const { data } = await octokit.rest.repos.getContent({
      owner,
      repo,
      path,
      ref
    });
    
    const rawContent = Buffer.from(data.content, 'base64').toString();
    
    // Parse based on content format
    const parsedContent = rawContent.trim().startsWith('{') 
      ? JSON.parse(rawContent) 
      : yaml.parse(rawContent);
    
    // Validate using SwaggerParser
    const spec = await SwaggerParser.parse(JSON.parse(JSON.stringify(parsedContent)));
    
    core.info(`Parsed ${description} OpenAPI spec from: ${path}`);
    return { spec, rawContent };
  } catch (error) {
    core.info(`No valid OpenAPI spec found in ${description} branch at ${path}: ${error.message}`);
    return { spec: null, rawContent: null };
  }
}

module.exports = {
  detectSpecRenames,
  loadSpec
};