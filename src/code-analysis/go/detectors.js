// API and database detection for Go via tree-sitter AST traversal

// Detect API handlers in Go (Gin, Echo, Gorilla/Mux)
function detectApiHandlers(ast, filename, content) {
  const handlers = []; // { method: 'GET', path: '/users', file: filename, symbol: 'GetUsers', line: 42 }
  
  if (!ast || !ast.rootNode) return handlers;
  
  walkNode(ast.rootNode, (node) => {
    // Gin patterns: r.GET("/users/:id", handler)
    if (node.type === 'call_expression') {
      const function_node = node.namedChild(0);
      
      if (function_node && function_node.type === 'selector_expression') {
        const method_node = function_node.namedChildren.find(child => child.type === 'field_identifier');
        if (method_node) {
          const method = getNodeText(method_node, content);
          
          if (isHTTPMethod(method.toUpperCase())) {
            const args = node.namedChildren.filter(child => child.type === 'argument_list')[0];
            if (args && args.namedChildCount >= 2) {
              const path_arg = args.namedChild(0);
              const handler_arg = args.namedChild(1);
              
              if (path_arg && path_arg.type === 'interpreted_string_literal') {
                const path = getNodeText(path_arg, content).replace(/"/g, '');
                let handlerName = 'anonymous';
                
                if (handler_arg && handler_arg.type === 'identifier') {
                  handlerName = getNodeText(handler_arg, content);
                }
                
                handlers.push({
                  method: method.toUpperCase(),
                  path: path,
                  file: filename,
                  symbol: handlerName,
                  line: node.startPosition.row + 1
                });
              }
            }
          }
        }
      }
    }
    
    // Echo patterns: e.GET("/users/:id", handler)
    if (node.type === 'call_expression') {
      const function_node = node.namedChild(0);
      
      if (function_node && function_node.type === 'selector_expression') {
        const obj_node = function_node.namedChild(0);
        const method_node = function_node.namedChildren.find(child => child.type === 'field_identifier');
        
        if (method_node) {
          const method = getNodeText(method_node, content);
          
          if (isHTTPMethod(method.toUpperCase())) {
            const args = node.namedChildren.filter(child => child.type === 'argument_list')[0];
            if (args && args.namedChildCount >= 2) {
              const path_arg = args.namedChild(0);
              const handler_arg = args.namedChild(1);
              
              if (path_arg && path_arg.type === 'interpreted_string_literal') {
                const path = getNodeText(path_arg, content).replace(/"/g, '');
                let handlerName = 'anonymous';
                
                if (handler_arg && handler_arg.type === 'identifier') {
                  handlerName = getNodeText(handler_arg, content);
                }
                
                handlers.push({
                  method: method.toUpperCase(),
                  path: path,
                  file: filename,
                  symbol: handlerName,
                  line: node.startPosition.row + 1
                });
              }
            }
          }
        }
      }
    }
    
    // Gorilla/Mux patterns: r.HandleFunc("/users", handler).Methods("GET")
    if (node.type === 'call_expression') {
      const function_node = node.namedChild(0);
      
      if (function_node && function_node.type === 'selector_expression') {
        const inner_call = function_node.namedChild(0);
        const methods_node = function_node.namedChildren.find(child => child.type === 'field_identifier');
        
        if (methods_node && getNodeText(methods_node, content) === 'Methods' && 
            inner_call && inner_call.type === 'call_expression') {
          
          const handle_func = inner_call.namedChild(0);
          if (handle_func && handle_func.type === 'selector_expression') {
            const handle_method = handle_func.namedChildren.find(child => child.type === 'field_identifier');
            if (handle_method && getNodeText(handle_method, content) === 'HandleFunc') {
              
              const handle_args = inner_call.namedChildren.filter(child => child.type === 'argument_list')[0];
              const method_args = node.namedChildren.filter(child => child.type === 'argument_list')[0];
              
              if (handle_args && method_args && handle_args.namedChildCount >= 2 && method_args.namedChildCount >= 1) {
                const path_arg = handle_args.namedChild(0);
                const handler_arg = handle_args.namedChild(1);
                const method_arg = method_args.namedChild(0);
                
                if (path_arg && path_arg.type === 'interpreted_string_literal' &&
                    method_arg && method_arg.type === 'interpreted_string_literal') {
                  
                  const path = getNodeText(path_arg, content).replace(/"/g, '');
                  const method = getNodeText(method_arg, content).replace(/"/g, '').toUpperCase();
                  let handlerName = 'anonymous';
                  
                  if (handler_arg && handler_arg.type === 'identifier') {
                    handlerName = getNodeText(handler_arg, content);
                  }
                  
                  handlers.push({
                    method: method,
                    path: path,
                    file: filename,
                    symbol: handlerName,
                    line: node.startPosition.row + 1
                  });
                }
              }
            }
          }
        }
      }
    }
  });
  
  return handlers;
}

// Detect database operations in Go (GORM, sqlx)
function detectDbOperations(ast, filename, content) {
  const dbRefs = []; // { orm: 'gorm', table: 'users', op: 'Find', file: filename, symbol: 'GetUsers', line: 42 }
  
  if (!ast || !ast.rootNode) return dbRefs;
  
  let currentFunction = null;
  
  walkNode(ast.rootNode, (node) => {
    // Track current function
    if (node.type === 'function_declaration') {
      const name_node = node.namedChildren.find(child => child.type === 'identifier');
      if (name_node) {
        currentFunction = getNodeText(name_node, content);
      }
    }
    
    if (node.type === 'method_declaration') {
      const name_node = node.namedChildren.find(child => child.type === 'field_identifier');
      if (name_node) {
        currentFunction = getNodeText(name_node, content);
      }
    }
    
    // GORM patterns: db.Find(&users), db.Where("name = ?", name).First(&user)
    if (node.type === 'call_expression') {
      const function_node = node.namedChild(0);
      
      if (function_node && function_node.type === 'selector_expression') {
        const method_node = function_node.namedChildren.find(child => child.type === 'field_identifier');
        if (method_node) {
          const operation = getNodeText(method_node, content);
          
          if (isGORMOperation(operation)) {
            // Try to extract table name from arguments
            const args = node.namedChildren.filter(child => child.type === 'argument_list')[0];
            let tableName = 'unknown';
            
            if (args && args.namedChildCount > 0) {
              const first_arg = args.namedChild(0);
              if (first_arg) {
                tableName = extractTableFromGoArg(first_arg, content);
              }
            }
            
            dbRefs.push({
              orm: 'gorm',
              table: tableName,
              op: operation,
              file: filename,
              symbol: currentFunction || 'anonymous',
              line: node.startPosition.row + 1
            });
          }
        }
      }
    }
    
    // sqlx patterns: db.Query("SELECT * FROM users"), db.Exec("INSERT INTO users...")
    if (node.type === 'call_expression') {
      const function_node = node.namedChild(0);
      
      if (function_node && function_node.type === 'selector_expression') {
        const method_node = function_node.namedChildren.find(child => child.type === 'field_identifier');
        if (method_node) {
          const operation = getNodeText(method_node, content);
          
          if (isSQLOperation(operation)) {
            const args = node.namedChildren.filter(child => child.type === 'argument_list')[0];
            if (args && args.namedChildCount > 0) {
              const sql_arg = args.namedChild(0);
              if (sql_arg && sql_arg.type === 'interpreted_string_literal') {
                const sql = getNodeText(sql_arg, content).replace(/"/g, '');
                const tables = extractTablesFromSQL(sql);
                
                tables.forEach(({ table, sqlOp }) => {
                  dbRefs.push({
                    orm: 'sqlx',
                    table: table,
                    op: sqlOp,
                    file: filename,
                    symbol: currentFunction || 'anonymous',
                    line: node.startPosition.row + 1
                  });
                });
              }
            }
          }
        }
      }
    }
    
    // database/sql patterns: rows, err := db.Query(), db.QueryRow()
    if (node.type === 'call_expression') {
      const function_node = node.namedChild(0);
      
      if (function_node && function_node.type === 'selector_expression') {
        const method_node = function_node.namedChildren.find(child => child.type === 'field_identifier');
        if (method_node) {
          const operation = getNodeText(method_node, content);
          
          // Check for standard library database operations
          if (isSQLOperation(operation)) {
            const obj_node = function_node.namedChild(0);
            if (obj_node && obj_node.type === 'identifier') {
              const obj_name = getNodeText(obj_node, content);
              // Common database connection variable names
              if (['db', 'conn', 'connection', 'database'].includes(obj_name.toLowerCase())) {
                const args = node.namedChildren.filter(child => child.type === 'argument_list')[0];
                if (args && args.namedChildCount > 0) {
                  const sql_arg = args.namedChild(0);
                  if (sql_arg && sql_arg.type === 'interpreted_string_literal') {
                    const sql = getNodeText(sql_arg, content).replace(/"/g, '');
                    const tables = extractTablesFromSQL(sql);
                    
                    tables.forEach(({ table, sqlOp }) => {
                      dbRefs.push({
                        orm: 'database/sql',
                        table: table,
                        op: sqlOp,
                        file: filename,
                        symbol: currentFunction || 'anonymous',
                        line: node.startPosition.row + 1
                      });
                    });
                  }
                }
              }
            }
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

function isHTTPMethod(method) {
  return ['GET', 'POST', 'PUT', 'PATCH', 'DELETE', 'HEAD', 'OPTIONS'].includes(method);
}

function isGORMOperation(operation) {
  return ['Find', 'First', 'Last', 'Take', 'Create', 'Save', 'Update', 'Updates', 'Delete', 'Count', 'Where', 'Select', 'Order', 'Limit', 'Offset'].includes(operation);
}

function isSQLOperation(operation) {
  return ['Query', 'QueryRow', 'Exec', 'Prepare', 'QueryContext', 'QueryRowContext', 'ExecContext'].includes(operation);
}

function extractTableFromGoArg(arg, content) {
  if (arg.type === 'unary_expression' && arg.namedChildCount > 0) {
    // &User{} pattern
    const operand = arg.namedChild(0);
    if (operand && operand.type === 'composite_literal') {
      const type_node = operand.namedChild(0);
      if (type_node && type_node.type === 'type_identifier') {
        return camelToSnake(getNodeText(type_node, content));
      }
    }
    // &users pattern (slice)
    if (operand && operand.type === 'identifier') {
      return getNodeText(operand, content).toLowerCase();
    }
  }
  
  // []User{} pattern
  if (arg.type === 'composite_literal') {
    const type_node = arg.namedChild(0);
    if (type_node && type_node.type === 'slice_type') {
      const element_type = type_node.namedChild(0);
      if (element_type && element_type.type === 'type_identifier') {
        return camelToSnake(getNodeText(element_type, content));
      }
    }
  }
  
  return 'unknown';
}

function extractTablesFromSQL(sql) {
  const tables = [];
  
  // Simple regex patterns for common SQL operations
  const patterns = [
    { regex: /SELECT.*FROM\s+(\w+)/i, op: 'SELECT' },
    { regex: /INSERT\s+INTO\s+(\w+)/i, op: 'INSERT' },
    { regex: /UPDATE\s+(\w+)/i, op: 'UPDATE' },
    { regex: /DELETE\s+FROM\s+(\w+)/i, op: 'DELETE' }
  ];
  
  patterns.forEach(({ regex, op }) => {
    const match = sql.match(regex);
    if (match) {
      tables.push({ table: match[1].toLowerCase(), sqlOp: op });
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