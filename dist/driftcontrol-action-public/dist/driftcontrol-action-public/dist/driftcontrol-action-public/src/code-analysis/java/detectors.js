// API and database detection for Java via tree-sitter AST traversal

// Detect API handlers in Java (Spring Boot, JAX-RS)
function detectApiHandlers(ast, filename) {
  const handlers = []; // { method: 'GET', path: '/users', file: filename, symbol: 'getUsers', line: 42 }
  
  if (!ast || !ast.rootNode) return handlers;
  
  const content = getContent(filename);
  
  walkNode(ast.rootNode, (node) => {
    // Spring Boot annotations: @GetMapping("/users"), @PostMapping("/users")
    if (node.type === 'method_declaration') {
      const method_name = node.namedChildren.find(child => child.type === 'identifier');
      let methodName = method_name ? getNodeText(method_name, content) : 'anonymous';
      
      // Look for Spring annotations
      const modifiers = node.namedChildren.find(child => child.type === 'modifiers');
      if (modifiers) {
        modifiers.namedChildren.forEach(modifier => {
          if (modifier.type === 'annotation') {
            const annotation_name = modifier.namedChildren.find(child => child.type === 'identifier');
            if (annotation_name) {
              const annotationText = getNodeText(annotation_name, content);
              
              // Spring mapping annotations
              const springMappingMatch = annotationText.match(/(Get|Post|Put|Patch|Delete|Request)Mapping$/);
              if (springMappingMatch) {
                const method = springMappingMatch[1] === 'Request' ? 'GET' : springMappingMatch[1].toUpperCase();
                const path = extractPathFromSpringAnnotation(modifier, content);
                
                handlers.push({
                  method: method,
                  path: path || '/',
                  file: filename,
                  symbol: methodName,
                  line: node.startPosition.row + 1
                });
              }
            }
          }
        });
      }
    }
    
    // JAX-RS annotations: @GET, @POST + @Path("/users")
    if (node.type === 'method_declaration') {
      const method_name = node.namedChildren.find(child => child.type === 'identifier');
      let methodName = method_name ? getNodeText(method_name, content) : 'anonymous';
      
      let httpMethod = null;
      let path = '/';
      
      const modifiers = node.namedChildren.find(child => child.type === 'modifiers');
      if (modifiers) {
        modifiers.namedChildren.forEach(modifier => {
          if (modifier.type === 'annotation') {
            const annotation_name = modifier.namedChildren.find(child => child.type === 'identifier');
            if (annotation_name) {
              const annotationText = getNodeText(annotation_name, content);
              
              // JAX-RS HTTP method annotations
              if (['GET', 'POST', 'PUT', 'DELETE', 'PATCH', 'HEAD', 'OPTIONS'].includes(annotationText.toUpperCase())) {
                httpMethod = annotationText.toUpperCase();
              }
              
              // JAX-RS @Path annotation
              if (annotationText === 'Path') {
                path = extractPathFromJaxRSAnnotation(modifier, content) || '/';
              }
            }
          }
        });
        
        if (httpMethod) {
          handlers.push({
            method: httpMethod,
            path: path,
            file: filename,
            symbol: methodName,
            line: node.startPosition.row + 1
          });
        }
      }
    }
  });
  
  return handlers;
}

// Detect database operations in Java (JPA, Hibernate, MyBatis)
function detectDbOperations(ast, filename) {
  const dbRefs = []; // { orm: 'jpa', table: 'users', op: 'findById', file: filename, symbol: 'getUserById', line: 42 }
  
  if (!ast || !ast.rootNode) return dbRefs;
  
  let currentMethod = null;
  const content = getContent(filename);
  
  walkNode(ast.rootNode, (node) => {
    // Track current method
    if (node.type === 'method_declaration') {
      const name_node = node.namedChildren.find(child => child.type === 'identifier');
      if (name_node) {
        currentMethod = getNodeText(name_node, content);
      }
    }
    
    // JPA Repository method calls: userRepository.findById(), userRepository.save()
    if (node.type === 'method_invocation') {
      const object_expr = node.namedChild(0);
      const method_name = node.namedChildren.find(child => child.type === 'identifier');
      
      if (object_expr && method_name) {
        const methodName = getNodeText(method_name, content);
        
        // Check if it's a repository method
        if (isJPARepositoryMethod(methodName)) {
          let tableName = 'unknown';
          
          // Try to infer table from repository variable name
          if (object_expr.type === 'identifier') {
            const repoName = getNodeText(object_expr, content);
            tableName = extractTableFromRepositoryName(repoName);
          }
          
          dbRefs.push({
            orm: 'jpa',
            table: tableName,
            op: methodName,
            file: filename,
            symbol: currentMethod || 'anonymous',
            line: node.startPosition.row + 1
          });
        }
      }
    }
    
    // JPQL/HQL queries: @Query("SELECT u FROM User u WHERE...")
    if (node.type === 'method_declaration') {
      const modifiers = node.namedChildren.find(child => child.type === 'modifiers');
      if (modifiers) {
        modifiers.namedChildren.forEach(modifier => {
          if (modifier.type === 'annotation') {
            const annotation_name = modifier.namedChildren.find(child => child.type === 'identifier');
            if (annotation_name && getNodeText(annotation_name, content) === 'Query') {
              const query = extractQueryFromAnnotation(modifier, content);
              if (query) {
                const tables = extractTablesFromJPQL(query);
                tables.forEach(({ table, operation }) => {
                  dbRefs.push({
                    orm: 'jpql',
                    table: camelToSnake(table),
                    op: operation,
                    file: filename,
                    symbol: currentMethod || 'anonymous',
                    line: node.startPosition.row + 1
                  });
                });
              }
            }
          }
        });
      }
    }
    
    // EntityManager operations: entityManager.persist(), entityManager.find()
    if (node.type === 'method_invocation') {
      const object_expr = node.namedChild(0);
      const method_name = node.namedChildren.find(child => child.type === 'identifier');
      
      if (object_expr && method_name && object_expr.type === 'identifier') {
        const objectName = getNodeText(object_expr, content);
        const methodName = getNodeText(method_name, content);
        
        if (objectName.includes('entityManager') || objectName.includes('em')) {
          if (isEntityManagerMethod(methodName)) {
            // Try to extract entity type from method arguments
            let tableName = 'unknown';
            const args = node.namedChildren.find(child => child.type === 'argument_list');
            if (args && args.namedChildCount > 0) {
              // For methods like find(User.class, id), get the first argument
              const first_arg = args.namedChild(0);
              if (first_arg && first_arg.type === 'field_access') {
                const type_part = first_arg.namedChild(0);
                if (type_part && type_part.type === 'identifier') {
                  tableName = camelToSnake(getNodeText(type_part, content));
                }
              }
            }
            
            dbRefs.push({
              orm: 'jpa',
              table: tableName,
              op: methodName,
              file: filename,
              symbol: currentMethod || 'anonymous',
              line: node.startPosition.row + 1
            });
          }
        }
      }
    }
  });
  
  return dbRefs;
}

// Helper functions
function walkNode(node, callback) {
  callback(node);
  for (let i = 0; i < node.namedChildCount; i++) {
    walkNode(node.namedChild(i), callback);
  }
}

function getNodeText(node, sourceText) {
  return sourceText.slice(node.startIndex, node.endIndex);
}

function getContent(filename) {
  // In a real implementation, this would get the file content
  return '';
}

function extractPathFromSpringAnnotation(annotation, content) {
  // Look for annotation arguments: @GetMapping("/users") or @GetMapping(value = "/users")
  const args = annotation.namedChildren.find(child => child.type === 'annotation_argument_list');
  if (args) {
    // Simple case: @GetMapping("/users")
    const string_arg = args.namedChildren.find(child => child.type === 'string_literal');
    if (string_arg) {
      return getNodeText(string_arg, content).replace(/"/g, '');
    }
    
    // Named parameter case: @GetMapping(value = "/users")
    const assignment = args.namedChildren.find(child => child.type === 'element_value_pair');
    if (assignment) {
      const key = assignment.namedChildren.find(child => child.type === 'identifier');
      const value = assignment.namedChildren.find(child => child.type === 'string_literal');
      if (key && value && getNodeText(key, content) === 'value') {
        return getNodeText(value, content).replace(/"/g, '');
      }
    }
  }
  return '/';
}

function extractPathFromJaxRSAnnotation(annotation, content) {
  const args = annotation.namedChildren.find(child => child.type === 'annotation_argument_list');
  if (args) {
    const string_arg = args.namedChildren.find(child => child.type === 'string_literal');
    if (string_arg) {
      return getNodeText(string_arg, content).replace(/"/g, '');
    }
  }
  return null;
}

function extractQueryFromAnnotation(annotation, content) {
  const args = annotation.namedChildren.find(child => child.type === 'annotation_argument_list');
  if (args) {
    const string_arg = args.namedChildren.find(child => child.type === 'string_literal');
    if (string_arg) {
      return getNodeText(string_arg, content).replace(/"/g, '');
    }
  }
  return null;
}

function isJPARepositoryMethod(methodName) {
  const jpaPatterns = [
    /^find/, /^get/, /^read/, /^query/, /^stream/, /^count/,
    /^exists/, /^delete/, /^remove/, /^save/, /^saveAll/,
    /^flush/, /^saveAndFlush/
  ];
  return jpaPatterns.some(pattern => pattern.test(methodName));
}

function isEntityManagerMethod(methodName) {
  return ['persist', 'merge', 'remove', 'find', 'refresh', 'detach', 'contains', 'flush', 'clear'].includes(methodName);
}

function extractTableFromRepositoryName(repoName) {
  // Convert userRepository -> user, CustomerRepo -> customer
  const cleaned = repoName.replace(/(Repository|Repo)$/i, '');
  return camelToSnake(cleaned);
}

function extractTablesFromJPQL(jpql) {
  const tables = [];
  
  // JPQL uses entity names, not table names
  const patterns = [
    { regex: /FROM\s+(\w+)/i, op: 'SELECT' },
    { regex: /UPDATE\s+(\w+)/i, op: 'UPDATE' },
    { regex: /DELETE\s+FROM\s+(\w+)/i, op: 'DELETE' }
  ];
  
  patterns.forEach(({ regex, op }) => {
    const match = jpql.match(regex);
    if (match) {
      tables.push({ table: match[1], operation: op });
    }
  });
  
  return tables;
}

function camelToSnake(str) {
  return str.replace(/[A-Z]/g, letter => `_${letter.toLowerCase()}`).replace(/^_/, '').toLowerCase();
}

module.exports = {
  detectApiHandlers,
  detectDbOperations
};