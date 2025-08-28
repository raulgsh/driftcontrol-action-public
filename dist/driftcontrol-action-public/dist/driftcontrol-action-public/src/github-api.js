const core = require('@actions/core');

// Helper function to post or update existing comment
async function postOrUpdateComment(octokit, owner, repo, pullNumber, body) {
  try {
    // Find existing DriftControl comment
    const { data: comments } = await octokit.rest.issues.listComments({
      owner,
      repo,
      issue_number: pullNumber
    });
    
    const existingComment = comments.find(comment => 
      comment.body.includes('<!-- driftcontrol:comment -->')
    );
    
    if (existingComment) {
      // Update existing comment
      await octokit.rest.issues.updateComment({
        owner,
        repo,
        comment_id: existingComment.id,
        body
      });
      core.info('Updated existing DriftControl comment');
    } else {
      // Create new comment
      await octokit.rest.issues.createComment({
        owner,
        repo,
        issue_number: pullNumber,
        body
      });
      core.info('Posted new DriftControl comment');
    }
  } catch (error) {
    core.error(`Failed to post comment: ${error.message}`);
    throw error;
  }
}

module.exports = {
  postOrUpdateComment
};