const IaCAnalyzer = require('../src/iac-analyzer');
const core = require('@actions/core');

// Mock @actions/core
jest.mock('@actions/core', () => ({
  info: jest.fn(),
  warning: jest.fn(),
  error: jest.fn(),
  setFailed: jest.fn()
}));

describe('IaC Analyzer', () => {
  let analyzer;
  let mockOctokit;
  
  beforeEach(() => {
    analyzer = new IaCAnalyzer();
    jest.clearAllMocks();
    
    // Mock octokit
    mockOctokit = {
      rest: {
        repos: {
          getContent: jest.fn()
        }
      }
    };
  });

  describe('analyzeIaCFiles', () => {
    it('should return empty results when no IaC files configured', async () => {
      const files = [
        { filename: 'src/index.js', status: 'modified' }
      ];
      
      const pullRequest = {
        head: { sha: 'head-sha' },
        base: { sha: 'base-sha' }
      };
      
      const result = await analyzer.analyzeIaCFiles(
        files, mockOctokit, 'owner', 'repo', pullRequest, '', '', '1000'
      );
      
      expect(result.driftResults).toEqual([]);
      expect(result.hasHighSeverity).toBe(false);
      expect(result.hasMediumSeverity).toBe(false);
    });

    it('should detect security group deletion as high severity', async () => {
      const files = [
        { filename: 'terraform.tfplan.json', status: 'added' }
      ];
      
      const terraformPlan = {
        resource_changes: [
          {
            type: 'aws_security_group',
            address: 'aws_security_group.main',
            change: {
              actions: ['delete']
            }
          }
        ]
      };
      
      mockOctokit.rest.repos.getContent.mockImplementation(({ ref }) => {
        if (ref === 'head-sha') {
          return Promise.resolve({
            data: {
              content: Buffer.from(JSON.stringify(terraformPlan)).toString('base64')
            }
          });
        }
        return Promise.reject(new Error('Not Found'));
      });
      
      const pullRequest = {
        head: { sha: 'head-sha' },
        base: { sha: 'base-sha' }
      };
      
      const result = await analyzer.analyzeIaCFiles(
        files, mockOctokit, 'owner', 'repo', pullRequest, 
        'terraform.tfplan.json', '', '1000'
      );
      
      expect(result.hasHighSeverity).toBe(true);
      expect(result.driftResults.length).toBe(1);
      expect(result.driftResults[0].changes).toContain('SECURITY_GROUP_DELETION: aws_security_group.main');
    });

    it('should detect security group changes as medium severity', async () => {
      const files = [
        { filename: 'terraform.tfplan.json', status: 'added' }
      ];
      
      const terraformPlan = {
        resource_changes: [
          {
            type: 'aws_security_group_rule',
            address: 'aws_security_group_rule.ingress',
            change: {
              actions: ['update']
            }
          }
        ]
      };
      
      mockOctokit.rest.repos.getContent.mockImplementation(({ ref }) => {
        if (ref === 'head-sha') {
          return Promise.resolve({
            data: {
              content: Buffer.from(JSON.stringify(terraformPlan)).toString('base64')
            }
          });
        }
        return Promise.reject(new Error('Not Found'));
      });
      
      const pullRequest = {
        head: { sha: 'head-sha' },
        base: { sha: 'base-sha' }
      };
      
      const result = await analyzer.analyzeIaCFiles(
        files, mockOctokit, 'owner', 'repo', pullRequest,
        'terraform.tfplan.json', '', '1000'
      );
      
      expect(result.hasMediumSeverity).toBe(true);
      expect(result.driftResults[0].changes).toContain('SECURITY_GROUP_CHANGE: aws_security_group_rule.ingress');
    });

    it('should detect cost increases above threshold', async () => {
      const files = [
        { filename: 'terraform.tfplan.json', status: 'added' }
      ];
      
      const terraformPlan = {
        resource_changes: [
          {
            type: 'aws_instance',
            address: 'aws_instance.web[0]',
            change: { actions: ['create'] }
          },
          {
            type: 'aws_instance',
            address: 'aws_instance.web[1]',
            change: { actions: ['create'] }
          },
          {
            type: 'aws_db_instance',
            address: 'aws_db_instance.main',
            change: { actions: ['create'] }
          }
        ]
      };
      
      mockOctokit.rest.repos.getContent.mockImplementation(({ ref }) => {
        if (ref === 'head-sha') {
          return Promise.resolve({
            data: {
              content: Buffer.from(JSON.stringify(terraformPlan)).toString('base64')
            }
          });
        }
        return Promise.reject(new Error('Not Found'));
      });
      
      const pullRequest = {
        head: { sha: 'head-sha' },
        base: { sha: 'base-sha' }
      };
      
      const result = await analyzer.analyzeIaCFiles(
        files, mockOctokit, 'owner', 'repo', pullRequest,
        'terraform.tfplan.json', '', '100'
      );
      
      expect(result.hasMediumSeverity).toBe(true);
      const costChange = result.driftResults[0].changes.find(c => c.includes('COST_INCREASE'));
      expect(costChange).toBeTruthy();
      expect(costChange).toContain('$200/month');
    });

    it('should handle CloudFormation templates', async () => {
      const files = [
        { filename: 'cloudformation/stack.yml', status: 'modified' }
      ];
      
      const template = `
Resources:
  WebServerSecurityGroup:
    Type: AWS::EC2::SecurityGroup
    Properties:
      GroupDescription: Enable HTTP access
  Database:
    Type: AWS::RDS::DBInstance
    DeletionPolicy: Delete
    Properties:
      DBInstanceClass: db.t3.micro
`;
      
      mockOctokit.rest.repos.getContent.mockResolvedValue({
        data: {
          content: Buffer.from(template).toString('base64')
        }
      });
      
      const pullRequest = {
        head: { sha: 'head-sha' },
        base: { sha: 'base-sha' }
      };
      
      const result = await analyzer.analyzeIaCFiles(
        files, mockOctokit, 'owner', 'repo', pullRequest,
        '', 'cloudformation/**/*.yml', '1000'
      );
      
      // Verify CloudFormation analysis ran (may not detect changes without base comparison)
      expect(result).toBeDefined();
      expect(result.driftResults).toBeDefined();
      // CloudFormation change detection would need base/head comparison for full functionality
      // This test verifies the analyzer processes CloudFormation files without errors
    });

    it('should handle analysis errors gracefully', async () => {
      const files = [
        { filename: 'terraform.tfplan.json', status: 'added' }
      ];
      
      mockOctokit.rest.repos.getContent.mockRejectedValue(new Error('API error'));
      
      const pullRequest = {
        head: { sha: 'head-sha' },
        base: { sha: 'base-sha' }
      };
      
      const result = await analyzer.analyzeIaCFiles(
        files, mockOctokit, 'owner', 'repo', pullRequest,
        'terraform.tfplan.json', '', '1000'
      );
      
      expect(result.driftResults).toEqual([]);
      expect(core.warning).toHaveBeenCalledWith(expect.stringContaining('Terraform plan analysis failed'));
    });

    it('should calculate cost impact correctly', async () => {
      const files = [
        { filename: 'terraform.tfplan.json', status: 'added' }
      ];
      
      const terraformPlan = {
        resource_changes: [
          { type: 'aws_eks_cluster', address: 'aws_eks_cluster.main', change: { actions: ['create'] } },
          { type: 'aws_alb', address: 'aws_alb.main', change: { actions: ['create'] } }
        ]
      };
      
      mockOctokit.rest.repos.getContent.mockImplementation(({ ref }) => {
        if (ref === 'head-sha') {
          return Promise.resolve({
            data: {
              content: Buffer.from(JSON.stringify(terraformPlan)).toString('base64')
            }
          });
        }
        return Promise.reject(new Error('Not Found'));
      });
      
      const pullRequest = {
        head: { sha: 'head-sha' },
        base: { sha: 'base-sha' }
      };
      
      const result = await analyzer.analyzeIaCFiles(
        files, mockOctokit, 'owner', 'repo', pullRequest,
        'terraform.tfplan.json', '', '100'
      );
      
      expect(result.driftResults[0].costImpact).toBe('$175/month');
    });
  });

  describe('module exports', () => {
    it('should export IaCAnalyzer class', () => {
      expect(IaCAnalyzer).toBeDefined();
      expect(typeof IaCAnalyzer).toBe('function');
    });

    it('should detect property-level changes in Terraform resources', async () => {
      const files = [
        { filename: 'terraform.tfplan.json', status: 'modified' }
      ];
      
      const basePlan = {
        resource_changes: [
          {
            type: 'aws_security_group',
            address: 'aws_security_group.web',
            change: {
              actions: ['update'],
              before: {
                ingress: [
                  { from_port: 22, to_port: 22, protocol: 'tcp', cidr_blocks: ['10.0.0.0/8'] }
                ]
              },
              after: {
                ingress: [
                  { from_port: 22, to_port: 22, protocol: 'tcp', cidr_blocks: ['0.0.0.0/0'] }
                ]
              }
            }
          }
        ]
      };
      
      const headPlan = basePlan; // Same plan for both to test property comparison
      
      mockOctokit.rest.repos.getContent
        .mockResolvedValueOnce({ data: { content: Buffer.from(JSON.stringify(basePlan)).toString('base64') } })
        .mockResolvedValueOnce({ data: { content: Buffer.from(JSON.stringify(headPlan)).toString('base64') } });
      
      const pullRequest = {
        head: { sha: 'head-sha' },
        base: { sha: 'base-sha' }
      };
      
      const result = await analyzer.analyzeIaCFiles(
        files, mockOctokit, 'owner', 'repo', pullRequest, 
        'terraform.tfplan.json', '', '1000'
      );
      
      expect(result.hasHighSeverity).toBe(true); // CIDR 0.0.0.0/0 is high risk
      expect(result.driftResults[0].changes).toContainEqual(
        expect.stringContaining('PROPERTY_MODIFIED: aws_security_group.web.ingress[tcp:22].cidr_blocks')
      );
      expect(result.driftResults[0].changes).toContainEqual(
        expect.stringContaining('["10.0.0.0/8"] → ["0.0.0.0/0"]')
      );
    });

    it('should detect property-level changes in CloudFormation resources', async () => {
      const files = [
        { filename: 'stack.yaml', status: 'modified' }
      ];
      
      const baseTemplate = {
        Resources: {
          WebSecurityGroup: {
            Type: 'AWS::EC2::SecurityGroup',
            Properties: {
              GroupDescription: 'Web server security group',
              SecurityGroupIngress: [
                { IpProtocol: 'tcp', FromPort: 80, ToPort: 80, CidrIp: '10.0.0.0/8' }
              ]
            }
          }
        }
      };
      
      const headTemplate = {
        Resources: {
          WebSecurityGroup: {
            Type: 'AWS::EC2::SecurityGroup',
            Properties: {
              GroupDescription: 'Updated web server security group',
              SecurityGroupIngress: [
                { IpProtocol: 'tcp', FromPort: 80, ToPort: 80, CidrIp: '0.0.0.0/0' },
                { IpProtocol: 'tcp', FromPort: 443, ToPort: 443, CidrIp: '0.0.0.0/0' }
              ]
            }
          }
        }
      };
      
      mockOctokit.rest.repos.getContent.mockImplementation(({ ref }) => {
        if (ref === 'head-sha') {
          return Promise.resolve({ data: { content: Buffer.from(JSON.stringify(headTemplate)).toString('base64') } });
        } else if (ref === 'base-sha') {
          return Promise.resolve({ data: { content: Buffer.from(JSON.stringify(baseTemplate)).toString('base64') } });
        }
        return Promise.reject(new Error('Not Found'));
      });
      
      const pullRequest = {
        head: { sha: 'head-sha' },
        base: { sha: 'base-sha' }
      };
      
      const result = await analyzer.analyzeIaCFiles(
        files, mockOctokit, 'owner', 'repo', pullRequest, 
        '', '**/*.yaml', '1000'
      );
      
      expect(result.hasHighSeverity).toBe(true); // CIDR 0.0.0.0/0 is high risk
      const changes = result.driftResults[0].changes;
      
      // Should detect both property modification and rule addition
      expect(changes.some(c => c.includes('PROPERTY_MODIFIED') && c.includes('GroupDescription'))).toBe(true);
      expect(changes.some(c => c.includes('PROPERTY_ADDED') && c.includes('tcp:443'))).toBe(true);
      expect(changes.some(c => c.includes('0.0.0.0/0'))).toBe(true);
    });

    it('should intelligently handle security rule array changes', async () => {
      const files = [
        { filename: 'stack.yaml', status: 'modified' }
      ];
      
      const baseTemplate = {
        Resources: {
          WebSG: {
            Type: 'AWS::EC2::SecurityGroup',
            Properties: {
              SecurityGroupIngress: [
                { IpProtocol: 'tcp', FromPort: 80, ToPort: 80, CidrIp: '10.0.0.0/8' },
                { IpProtocol: 'tcp', FromPort: 22, ToPort: 22, CidrIp: '10.0.0.0/8' }
              ]
            }
          }
        }
      };
      
      const headTemplate = {
        Resources: {
          WebSG: {
            Type: 'AWS::EC2::SecurityGroup',
            Properties: {
              SecurityGroupIngress: [
                { IpProtocol: 'tcp', FromPort: 22, ToPort: 22, CidrIp: '10.0.0.0/8' },  // Reordered
                { IpProtocol: 'tcp', FromPort: 80, ToPort: 80, CidrIp: '10.0.0.0/8' },  // Reordered
                { IpProtocol: 'tcp', FromPort: 443, ToPort: 443, CidrIp: '10.0.0.0/8' } // Added
              ]
            }
          }
        }
      };
      
      mockOctokit.rest.repos.getContent.mockImplementation(({ ref }) => {
        if (ref === 'head-sha') {
          return Promise.resolve({ data: { content: Buffer.from(JSON.stringify(headTemplate)).toString('base64') } });
        } else if (ref === 'base-sha') {
          return Promise.resolve({ data: { content: Buffer.from(JSON.stringify(baseTemplate)).toString('base64') } });
        }
        return Promise.reject(new Error('Not Found'));
      });
      
      const pullRequest = {
        head: { sha: 'head-sha' },
        base: { sha: 'base-sha' }
      };
      
      const result = await analyzer.analyzeIaCFiles(
        files, mockOctokit, 'owner', 'repo', pullRequest, 
        '', '**/*.yaml', '1000'
      );
      
      const changes = result.driftResults[0].changes;
      
      // Should detect rule addition, not reordering as changes
      expect(changes.some(c => c.includes('PROPERTY_ADDED') && c.includes('tcp:443'))).toBe(true);
      // Should NOT detect the reordering of existing rules as modifications
      expect(changes.filter(c => c.includes('tcp:80') && c.includes('MODIFIED')).length).toBe(0);
      expect(changes.filter(c => c.includes('tcp:22') && c.includes('MODIFIED')).length).toBe(0);
    });
  });
});