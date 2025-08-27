// Text processing and entity matching utilities

// Generate entity name variations for matching
function generateEntityVariations(entity) {
  if (!entity || typeof entity !== 'string') return [];
  
  const variations = new Set();
  const base = entity.trim();
  const baseLower = base.toLowerCase();
  
  // Add base forms
  variations.add(baseLower);
  
  // Also handle original case for camelCase detection
  if (base !== baseLower) {
    // Convert camelCase to snake_case
    const snakeFromCamel = base.replace(/([a-z])([A-Z])/g, '$1_$2').toLowerCase();
    variations.add(snakeFromCamel);
  }
  
  // Singular/plural forms (use lowercase base for consistency)
  if (baseLower.endsWith('ies')) {
    // entities -> entity, categories -> category
    variations.add(baseLower.slice(0, -3) + 'y');
    // Also try just removing 's' for words like categories -> categorie
    variations.add(baseLower.slice(0, -1));
  } else if (baseLower.endsWith('es')) {
    // branches -> branch
    variations.add(baseLower.slice(0, -2));
    // Also try just removing 's'
    variations.add(baseLower.slice(0, -1));
  } else if (baseLower.endsWith('s') && !baseLower.endsWith('ss')) {
    // users -> user
    variations.add(baseLower.slice(0, -1));
  } else {
    // user -> users
    variations.add(baseLower + 's');
    variations.add(baseLower + 'es');
  }
  
  // Handle camelCase to snake_case and vice versa
  if (baseLower.includes('_')) {
    // snake_case input: convert to camelCase  
    const camelCase = baseLower.replace(/_([a-z])/g, (_, letter) => letter.toUpperCase());
    variations.add(camelCase);
    // Also try without underscores
    variations.add(baseLower.replace(/_/g, ''));
  } else {
    // Try detecting word boundaries for snake_case conversion
    const snakeCase = baseLower.replace(/([a-z])([A-Z])/g, '$1_$2').toLowerCase();
    if (snakeCase !== baseLower) variations.add(snakeCase);
    
    // Try removing underscores
    const noUnderscore = baseLower.replace(/_/g, '');
    if (noUnderscore !== baseLower) variations.add(noUnderscore);
  }
  
  // Remove common prefixes/suffixes
  const prefixes = ['tbl_', 'table_', 'vw_', 'view_'];
  const suffixes = ['_table', '_tbl', '_view', '_vw'];
  
  prefixes.forEach(prefix => {
    if (base.startsWith(prefix)) {
      variations.add(base.slice(prefix.length));
    }
  });
  
  suffixes.forEach(suffix => {
    if (base.endsWith(suffix)) {
      variations.add(base.slice(0, -suffix.length));
    }
  });
  
  return Array.from(variations);
}

// Find best match between two sets of variations
function findBestMatch(variations1, variations2) {
  let bestConfidence = 0;
  let bestMatch = null;
  
  for (const v1 of variations1) {
    for (const v2 of variations2) {
      let confidence = 0;
      
      // Exact match
      if (v1 === v2) {
        confidence = 1.0;
      }
      // Substring match
      else if (v1.includes(v2) || v2.includes(v1)) {
        confidence = 0.8;
      }
      // Levenshtein distance for close matches
      else {
        const distance = levenshteinDistance(v1, v2);
        const maxLen = Math.max(v1.length, v2.length);
        const similarity = 1 - (distance / maxLen);
        if (similarity > 0.7) {
          confidence = similarity * 0.9; // Scale down slightly for fuzzy matches
        }
      }
      
      if (confidence > bestConfidence) {
        bestConfidence = confidence;
        bestMatch = { v1, v2 };
      }
    }
  }
  
  return { confidence: bestConfidence, match: bestMatch };
}

// Calculate Levenshtein distance
function levenshteinDistance(str1, str2) {
  const m = str1.length;
  const n = str2.length;
  const dp = Array(m + 1).fill(null).map(() => Array(n + 1).fill(0));
  
  for (let i = 0; i <= m; i++) dp[i][0] = i;
  for (let j = 0; j <= n; j++) dp[0][j] = j;
  
  for (let i = 1; i <= m; i++) {
    for (let j = 1; j <= n; j++) {
      if (str1[i - 1] === str2[j - 1]) {
        dp[i][j] = dp[i - 1][j - 1];
      } else {
        dp[i][j] = Math.min(
          dp[i - 1][j] + 1,    // deletion
          dp[i][j - 1] + 1,    // insertion
          dp[i - 1][j - 1] + 1 // substitution
        );
      }
    }
  }
  
  return dp[m][n];
}

module.exports = {
  generateEntityVariations,
  findBestMatch,
  levenshteinDistance
};