#!/usr/bin/env node
const { OSVProvider } = require('./src/analyzers/config/utils');

async function testOSVProvider() {
  console.log('🔍 Testing OSV Provider...\n');
  
  const provider = new OSVProvider();
  
  // Test with known vulnerable packages
  const testPackages = ['lodash', 'minimist', 'yargs-parser'];
  
  console.log('🚀 Initializing OSV Provider with test packages...');
  await provider.initialize({ packageNames: testPackages });
  
  // Debug: Check what vulnerabilities were cached
  console.log('📊 Cached vulnerabilities:', provider.vulnerabilities.size);
  for (const [pkg, vulns] of provider.vulnerabilities.entries()) {
    console.log(`   ${pkg}: ${vulns.length} vulnerabilities`);
  }
  
  console.log('\n📦 Testing vulnerability detection:');
  
  // Test vulnerable versions
  const tests = [
    { pkg: 'lodash', version: '4.17.10', expectVuln: true },
    { pkg: 'lodash', version: '4.17.21', expectVuln: false },
    { pkg: 'minimist', version: '1.2.5', expectVuln: true },
    { pkg: 'minimist', version: '1.2.6', expectVuln: false },
    { pkg: 'safe-package', version: '1.0.0', expectVuln: false }
  ];
  
  for (const test of tests) {
    const isVuln = provider.isVulnerable(test.pkg, test.version);
    const status = isVuln === test.expectVuln ? '✅' : '❌';
    console.log(`${status} ${test.pkg}@${test.version}: ${isVuln ? 'VULNERABLE' : 'SAFE'}`);
    
    if (isVuln) {
      const vulnInfo = provider.getVulnerabilityInfo(test.pkg, test.version);
      if (vulnInfo) {
        console.log(`   └─ Found ${vulnInfo.vulnerabilities.length} vulnerabilities (severity: ${vulnInfo.severity})`);
      }
    }
  }
  
  console.log('\n✨ OSV Provider test completed!');
}

testOSVProvider().catch(console.error);