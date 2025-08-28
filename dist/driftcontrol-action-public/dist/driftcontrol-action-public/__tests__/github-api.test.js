const { postOrUpdateComment } = require('../src/github-api');

// Mock dependencies
jest.mock('@actions/core');
const core = require('@actions/core');

describe('GitHub API', () => {
  let mockOctokit;

  beforeEach(() => {
    // Clear all mocks
    jest.clearAllMocks();

    // Mock core methods
    core.info = jest.fn();
    core.error = jest.fn();

    // Mock octokit
    mockOctokit = {
      rest: {
        issues: {
          listComments: jest.fn(),
          createComment: jest.fn(),
          updateComment: jest.fn()
        }
      }
    };
  });

  describe('postOrUpdateComment', () => {
    const baseParams = {
      owner: 'test-owner',
      repo: 'test-repo',
      pullNumber: 123,
      body: '<!-- driftcontrol:comment -->\n## Test Comment\nThis is a test comment.'
    };

    test('should create new comment when no existing comment found', async () => {
      mockOctokit.rest.issues.listComments.mockResolvedValue({
        data: [
          { id: 1, body: 'Some other comment' },
          { id: 2, body: 'Another comment without marker' }
        ]
      });

      mockOctokit.rest.issues.createComment.mockResolvedValue({
        data: { id: 3, body: baseParams.body }
      });

      await postOrUpdateComment(
        mockOctokit, 
        baseParams.owner, 
        baseParams.repo, 
        baseParams.pullNumber, 
        baseParams.body
      );

      expect(mockOctokit.rest.issues.listComments).toHaveBeenCalledWith({
        owner: baseParams.owner,
        repo: baseParams.repo,
        issue_number: baseParams.pullNumber
      });

      expect(mockOctokit.rest.issues.createComment).toHaveBeenCalledWith({
        owner: baseParams.owner,
        repo: baseParams.repo,
        issue_number: baseParams.pullNumber,
        body: baseParams.body
      });

      expect(core.info).toHaveBeenCalledWith('Posted new DriftControl comment');
      expect(mockOctokit.rest.issues.updateComment).not.toHaveBeenCalled();
    });

    test('should update existing comment when driftcontrol marker found', async () => {
      const existingCommentId = 456;
      
      mockOctokit.rest.issues.listComments.mockResolvedValue({
        data: [
          { id: 1, body: 'Some other comment' },
          { 
            id: existingCommentId, 
            body: '<!-- driftcontrol:comment -->\n## Old Comment\nThis is the old comment.' 
          },
          { id: 3, body: 'Another regular comment' }
        ]
      });

      mockOctokit.rest.issues.updateComment.mockResolvedValue({
        data: { id: existingCommentId, body: baseParams.body }
      });

      await postOrUpdateComment(
        mockOctokit, 
        baseParams.owner, 
        baseParams.repo, 
        baseParams.pullNumber, 
        baseParams.body
      );

      expect(mockOctokit.rest.issues.listComments).toHaveBeenCalledWith({
        owner: baseParams.owner,
        repo: baseParams.repo,
        issue_number: baseParams.pullNumber
      });

      expect(mockOctokit.rest.issues.updateComment).toHaveBeenCalledWith({
        owner: baseParams.owner,
        repo: baseParams.repo,
        comment_id: existingCommentId,
        body: baseParams.body
      });

      expect(core.info).toHaveBeenCalledWith('Updated existing DriftControl comment');
      expect(mockOctokit.rest.issues.createComment).not.toHaveBeenCalled();
    });

    test('should find driftcontrol comment regardless of position', async () => {
      const existingCommentId = 789;
      
      mockOctokit.rest.issues.listComments.mockResolvedValue({
        data: [
          { id: 1, body: 'First comment' },
          { id: 2, body: 'Second comment' },
          { id: 3, body: 'Third comment' },
          { 
            id: existingCommentId, 
            body: 'Some text\n<!-- driftcontrol:comment -->\n## DriftControl Report\nResults here' 
          },
          { id: 5, body: 'Last comment' }
        ]
      });

      mockOctokit.rest.issues.updateComment.mockResolvedValue({
        data: { id: existingCommentId, body: baseParams.body }
      });

      await postOrUpdateComment(
        mockOctokit, 
        baseParams.owner, 
        baseParams.repo, 
        baseParams.pullNumber, 
        baseParams.body
      );

      expect(mockOctokit.rest.issues.updateComment).toHaveBeenCalledWith({
        owner: baseParams.owner,
        repo: baseParams.repo,
        comment_id: existingCommentId,
        body: baseParams.body
      });

      expect(core.info).toHaveBeenCalledWith('Updated existing DriftControl comment');
    });

    test('should handle empty comments list', async () => {
      mockOctokit.rest.issues.listComments.mockResolvedValue({
        data: []
      });

      mockOctokit.rest.issues.createComment.mockResolvedValue({
        data: { id: 1, body: baseParams.body }
      });

      await postOrUpdateComment(
        mockOctokit, 
        baseParams.owner, 
        baseParams.repo, 
        baseParams.pullNumber, 
        baseParams.body
      );

      expect(mockOctokit.rest.issues.createComment).toHaveBeenCalledWith({
        owner: baseParams.owner,
        repo: baseParams.repo,
        issue_number: baseParams.pullNumber,
        body: baseParams.body
      });

      expect(core.info).toHaveBeenCalledWith('Posted new DriftControl comment');
    });

    test('should find first driftcontrol comment when multiple exist', async () => {
      const firstCommentId = 100;
      const secondCommentId = 200;
      
      mockOctokit.rest.issues.listComments.mockResolvedValue({
        data: [
          { 
            id: firstCommentId, 
            body: '<!-- driftcontrol:comment -->\n## First DriftControl Comment' 
          },
          { id: 2, body: 'Regular comment' },
          { 
            id: secondCommentId, 
            body: '<!-- driftcontrol:comment -->\n## Second DriftControl Comment' 
          }
        ]
      });

      mockOctokit.rest.issues.updateComment.mockResolvedValue({
        data: { id: firstCommentId, body: baseParams.body }
      });

      await postOrUpdateComment(
        mockOctokit, 
        baseParams.owner, 
        baseParams.repo, 
        baseParams.pullNumber, 
        baseParams.body
      );

      expect(mockOctokit.rest.issues.updateComment).toHaveBeenCalledWith({
        owner: baseParams.owner,
        repo: baseParams.repo,
        comment_id: firstCommentId,
        body: baseParams.body
      });

      expect(core.info).toHaveBeenCalledWith('Updated existing DriftControl comment');
    });

    test('should handle listComments API error', async () => {
      const apiError = new Error('GitHub API rate limit exceeded');
      
      mockOctokit.rest.issues.listComments.mockRejectedValue(apiError);

      await expect(
        postOrUpdateComment(
          mockOctokit, 
          baseParams.owner, 
          baseParams.repo, 
          baseParams.pullNumber, 
          baseParams.body
        )
      ).rejects.toThrow('GitHub API rate limit exceeded');

      expect(core.error).toHaveBeenCalledWith('Failed to post comment: GitHub API rate limit exceeded');
    });

    test('should handle createComment API error', async () => {
      const createError = new Error('Failed to create comment');
      
      mockOctokit.rest.issues.listComments.mockResolvedValue({
        data: []
      });

      mockOctokit.rest.issues.createComment.mockRejectedValue(createError);

      await expect(
        postOrUpdateComment(
          mockOctokit, 
          baseParams.owner, 
          baseParams.repo, 
          baseParams.pullNumber, 
          baseParams.body
        )
      ).rejects.toThrow('Failed to create comment');

      expect(core.error).toHaveBeenCalledWith('Failed to post comment: Failed to create comment');
    });

    test('should handle updateComment API error', async () => {
      const updateError = new Error('Failed to update comment');
      const existingCommentId = 123;
      
      mockOctokit.rest.issues.listComments.mockResolvedValue({
        data: [
          { 
            id: existingCommentId, 
            body: '<!-- driftcontrol:comment -->\n## Old Comment' 
          }
        ]
      });

      mockOctokit.rest.issues.updateComment.mockRejectedValue(updateError);

      await expect(
        postOrUpdateComment(
          mockOctokit, 
          baseParams.owner, 
          baseParams.repo, 
          baseParams.pullNumber, 
          baseParams.body
        )
      ).rejects.toThrow('Failed to update comment');

      expect(core.error).toHaveBeenCalledWith('Failed to post comment: Failed to update comment');
    });

    test('should handle network timeout error', async () => {
      const timeoutError = new Error('Request timeout');
      
      mockOctokit.rest.issues.listComments.mockRejectedValue(timeoutError);

      await expect(
        postOrUpdateComment(
          mockOctokit, 
          baseParams.owner, 
          baseParams.repo, 
          baseParams.pullNumber, 
          baseParams.body
        )
      ).rejects.toThrow('Request timeout');

      expect(core.error).toHaveBeenCalledWith('Failed to post comment: Request timeout');
    });

    test('should handle malformed API response', async () => {
      mockOctokit.rest.issues.listComments.mockResolvedValue({
        data: null
      });

      mockOctokit.rest.issues.createComment.mockResolvedValue({
        data: { id: 1, body: baseParams.body }
      });

      // Should not crash and should fall back to creating new comment
      await expect(
        postOrUpdateComment(
          mockOctokit, 
          baseParams.owner, 
          baseParams.repo, 
          baseParams.pullNumber, 
          baseParams.body
        )
      ).rejects.toThrow();
    });

    test('should work with different comment body formats', async () => {
      const htmlBody = '<!-- driftcontrol:comment -->\n<h2>HTML Comment</h2>\n<p>With <strong>formatting</strong></p>';
      
      mockOctokit.rest.issues.listComments.mockResolvedValue({
        data: []
      });

      mockOctokit.rest.issues.createComment.mockResolvedValue({
        data: { id: 1, body: htmlBody }
      });

      await postOrUpdateComment(
        mockOctokit, 
        baseParams.owner, 
        baseParams.repo, 
        baseParams.pullNumber, 
        htmlBody
      );

      expect(mockOctokit.rest.issues.createComment).toHaveBeenCalledWith({
        owner: baseParams.owner,
        repo: baseParams.repo,
        issue_number: baseParams.pullNumber,
        body: htmlBody
      });

      expect(core.info).toHaveBeenCalledWith('Posted new DriftControl comment');
    });

    test('should handle very long comment bodies', async () => {
      const longBody = '<!-- driftcontrol:comment -->\n' + 'A'.repeat(65000) + '\n## End';
      
      mockOctokit.rest.issues.listComments.mockResolvedValue({
        data: []
      });

      mockOctokit.rest.issues.createComment.mockResolvedValue({
        data: { id: 1, body: longBody }
      });

      await postOrUpdateComment(
        mockOctokit, 
        baseParams.owner, 
        baseParams.repo, 
        baseParams.pullNumber, 
        longBody
      );

      expect(mockOctokit.rest.issues.createComment).toHaveBeenCalledWith({
        owner: baseParams.owner,
        repo: baseParams.repo,
        issue_number: baseParams.pullNumber,
        body: longBody
      });
    });

    test('should handle special characters in comment marker detection', async () => {
      const existingCommentId = 999;
      
      mockOctokit.rest.issues.listComments.mockResolvedValue({
        data: [
          { 
            id: existingCommentId, 
            body: 'Some text with <!-- other comment -->\n<!-- driftcontrol:comment -->\n## Report' 
          }
        ]
      });

      mockOctokit.rest.issues.updateComment.mockResolvedValue({
        data: { id: existingCommentId, body: baseParams.body }
      });

      await postOrUpdateComment(
        mockOctokit, 
        baseParams.owner, 
        baseParams.repo, 
        baseParams.pullNumber, 
        baseParams.body
      );

      expect(mockOctokit.rest.issues.updateComment).toHaveBeenCalledWith({
        owner: baseParams.owner,
        repo: baseParams.repo,
        comment_id: existingCommentId,
        body: baseParams.body
      });
    });

    test('should handle numeric parameters correctly', async () => {
      mockOctokit.rest.issues.listComments.mockResolvedValue({
        data: []
      });

      mockOctokit.rest.issues.createComment.mockResolvedValue({
        data: { id: 1, body: baseParams.body }
      });

      // Test with numeric pull number
      await postOrUpdateComment(
        mockOctokit, 
        'owner', 
        'repo', 
        42,  // numeric pull number
        baseParams.body
      );

      expect(mockOctokit.rest.issues.listComments).toHaveBeenCalledWith({
        owner: 'owner',
        repo: 'repo',
        issue_number: 42
      });

      expect(mockOctokit.rest.issues.createComment).toHaveBeenCalledWith({
        owner: 'owner',
        repo: 'repo',
        issue_number: 42,
        body: baseParams.body
      });
    });

    test('should preserve exact comment body content', async () => {
      const complexBody = `<!-- driftcontrol:comment -->
## 🔍 DriftControl Analysis Report

**Summary**: 2 drift issues detected
- 🔴 1 High severity
- 🟡 1 Medium severity

<details>
<summary><strong>🔴 HIGH Severity Issues (1)</strong></summary>

#### DATABASE Drift: \`migrations/001.sql\`

- DROP TABLE users
  💡 **Fix suggestion**: Consider backing up data

</details>`;

      mockOctokit.rest.issues.listComments.mockResolvedValue({
        data: []
      });

      mockOctokit.rest.issues.createComment.mockResolvedValue({
        data: { id: 1, body: complexBody }
      });

      await postOrUpdateComment(
        mockOctokit, 
        baseParams.owner, 
        baseParams.repo, 
        baseParams.pullNumber, 
        complexBody
      );

      expect(mockOctokit.rest.issues.createComment).toHaveBeenCalledWith({
        owner: baseParams.owner,
        repo: baseParams.repo,
        issue_number: baseParams.pullNumber,
        body: complexBody
      });
    });
  });

  describe('module exports', () => {
    test('should export postOrUpdateComment function', () => {
      expect(typeof postOrUpdateComment).toBe('function');
    });

    test('should have correct function arity', () => {
      expect(postOrUpdateComment.length).toBe(5); // octokit, owner, repo, pullNumber, body
    });
  });
});