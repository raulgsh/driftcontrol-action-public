// API and database detection via AST traversal
const walk = require('acorn-walk');

// Detect API handlers in the AST
function detectApiHandlers(ast, filename) {
  const handlers = []; // { method: 'GET', path: '/users', file: filename, symbol: 'getUsersHandler', line: 42 }
  
  if (!ast) return handlers;
  
  walk.ancestor(ast, {
    CallExpression(node, ancestors) {
      // Express/Router patterns: app.get('/path', handler), router.post('/path', handler)
      if (node.callee.type === 'MemberExpression' && 
          node.callee.property && 
          node.arguments.length >= 2) {
        
        const method = node.callee.property.name?.toUpperCase();
        const pathArg = node.arguments[0];
        
        // Check if method is HTTP verb
        if (['GET', 'POST', 'PUT', 'PATCH', 'DELETE', 'HEAD', 'OPTIONS'].includes(method) &&
            pathArg.type === 'Literal' && typeof pathArg.value === 'string') {
          
          const handlerArg = node.arguments[1];
          let handlerName = 'anonymous';
          
          if (handlerArg.type === 'Identifier') {
            handlerName = handlerArg.name;
          } else if (handlerArg.type === 'FunctionExpression' || handlerArg.type === 'ArrowFunctionExpression') {
            // Find containing function or variable name
            for (let i = ancestors.length - 1; i >= 0; i--) {
              const ancestor = ancestors[i];
              if (ancestor.type === 'VariableDeclarator' && ancestor.id.name) {
                handlerName = ancestor.id.name;
                break;
              }
            }
          }
          
          handlers.push({
            method,
            path: pathArg.value,
            file: filename,
            symbol: handlerName,
            line: node.loc?.start.line
          });
        }
      }
      
      // Fastify patterns: fastify.route({ method: 'GET', url: '/path', handler })
      if (node.callee.type === 'MemberExpression' && 
          node.callee.property?.name === 'route' &&
          node.arguments.length >= 1 &&
          node.arguments[0].type === 'ObjectExpression') {
        
        const routeConfig = node.arguments[0];
        let method = null, path = null, handlerName = 'anonymous';
        
        routeConfig.properties.forEach(prop => {
          if (prop.key.name === 'method' && prop.value.type === 'Literal') {
            method = prop.value.value?.toUpperCase();
          } else if ((prop.key.name === 'url' || prop.key.name === 'path') && prop.value.type === 'Literal') {
            path = prop.value.value;
          } else if (prop.key.name === 'handler') {
            if (prop.value.type === 'Identifier') {
              handlerName = prop.value.name;
            }
          }
        });
        
        if (method && path) {
          handlers.push({
            method,
            path,
            file: filename,
            symbol: handlerName,
            line: node.loc?.start.line
          });
        }
      }
    },
    
    // NestJS decorators: @Get('/path'), @Post('/path')
    Decorator(node) {
      if (node.expression.type === 'CallExpression' && 
          node.expression.callee.name &&
          ['Get', 'Post', 'Put', 'Patch', 'Delete', 'Head', 'Options'].includes(node.expression.callee.name)) {
        
        const method = node.expression.callee.name.toUpperCase();
        let path = '/';
        
        if (node.expression.arguments.length > 0 && 
            node.expression.arguments[0].type === 'Literal') {
          path = node.expression.arguments[0].value;
        }
        
        // Find the decorated method
        let methodName = 'anonymous';
        if (node.parent && node.parent.type === 'MethodDefinition') {
          methodName = node.parent.key.name;
        }
        
        handlers.push({
          method,
          path,
          file: filename,
          symbol: methodName,
          line: node.loc?.start.line
        });
      }
    }
  });
  
  return handlers;
}

// Detect database operations in the AST
function detectDbOperations(ast, filename) {
  const dbRefs = []; // { orm: 'prisma', table: 'users', op: 'findMany', file: filename, symbol: 'getUsersHandler', line: 42 }
  
  if (!ast) return dbRefs;
  
  walk.ancestor(ast, {
    MemberExpression(node, ancestors) {
      // Prisma patterns: prisma.user.findMany(), prisma.user.create()
      if (node.object?.type === 'MemberExpression' &&
          node.object.object?.name === 'prisma' &&
          node.object.property?.name) {
        
        const table = node.object.property.name;
        const operation = node.property?.name;
        
        if (operation && isPrismaOperation(operation)) {
          dbRefs.push({
            orm: 'prisma',
            table: pluralizeTableName(table),
            op: operation,
            file: filename,
            symbol: getContainingFunction(ancestors),
            line: node.loc?.start.line
          });
        }
      }
      
      // Knex patterns: knex('table').select(), knex.table.select()
      if (node.object?.type === 'CallExpression' &&
          node.object.callee?.name === 'knex' &&
          node.object.arguments.length > 0 &&
          node.object.arguments[0].type === 'Literal') {
        
        const table = node.object.arguments[0].value;
        const operation = node.property?.name;
        
        if (operation && isKnexOperation(operation)) {
          dbRefs.push({
            orm: 'knex',
            table,
            op: operation,
            file: filename,
            symbol: getContainingFunction(ancestors),
            line: node.loc?.start.line
          });
        }
      }
    },
    
    CallExpression(node, ancestors) {
      // TypeORM patterns: getRepository(User).find(), User.findOne()
      if (node.callee.type === 'MemberExpression' &&
          node.callee.object?.type === 'CallExpression' &&
          node.callee.object.callee?.name === 'getRepository') {
        
        const entityArg = node.callee.object.arguments[0];
        if (entityArg?.name) {
          const table = camelToSnake(entityArg.name);
          const operation = node.callee.property?.name;
          
          if (operation && isTypeOrmOperation(operation)) {
            dbRefs.push({
              orm: 'typeorm',
              table,
              op: operation,
              file: filename,
              symbol: getContainingFunction(ancestors),
              line: node.loc?.start.line
            });
          }
        }
      }
      
      // Sequelize patterns: User.findAll(), User.create()
      if (node.callee.type === 'MemberExpression' &&
          node.callee.object?.name &&
          node.callee.property?.name) {
        
        const modelName = node.callee.object.name;
        const operation = node.callee.property.name;
        
        // Check if it looks like a Sequelize model call
        if (isCapitalized(modelName) && isSequelizeOperation(operation)) {
          dbRefs.push({
            orm: 'sequelize',
            table: camelToSnake(modelName),
            op: operation,
            file: filename,
            symbol: getContainingFunction(ancestors),
            line: node.loc?.start.line
          });
        }
      }
      
      // Raw SQL patterns: db.query('SELECT * FROM users'), pool.query('INSERT INTO...')
      if (node.callee.type === 'MemberExpression' &&
          node.callee.property?.name === 'query' &&
          node.arguments.length > 0 &&
          node.arguments[0].type === 'Literal') {
        
        const sql = node.arguments[0].value;
        const tables = extractTablesFromSql(sql);
        
        tables.forEach(({ table, operation }) => {
          dbRefs.push({
            orm: 'raw',
            table,
            op: operation,
            file: filename,
            symbol: getContainingFunction(ancestors),
            line: node.loc?.start.line
          });
        });
      }
    }
  });
  
  return dbRefs;
}

// Helper functions
function getContainingFunction(ancestors) {
  for (let i = ancestors.length - 1; i >= 0; i--) {
    const ancestor = ancestors[i];
    if (ancestor.type === 'FunctionDeclaration' && ancestor.id) {
      return ancestor.id.name;
    } else if (ancestor.type === 'VariableDeclarator' && 
               (ancestor.init?.type === 'FunctionExpression' || ancestor.init?.type === 'ArrowFunctionExpression')) {
      return ancestor.id.name;
    } else if (ancestor.type === 'MethodDefinition') {
      return ancestor.key.name;
    }
  }
  return 'anonymous';
}

function isPrismaOperation(op) {
  return ['findMany', 'findUnique', 'findFirst', 'create', 'update', 'upsert', 'delete', 'deleteMany', 'updateMany'].includes(op);
}

function isKnexOperation(op) {
  return ['select', 'where', 'insert', 'update', 'delete', 'join', 'leftJoin', 'rightJoin'].includes(op);
}

function isTypeOrmOperation(op) {
  return ['find', 'findOne', 'findAndCount', 'save', 'insert', 'update', 'delete', 'remove'].includes(op);
}

function isSequelizeOperation(op) {
  return ['findAll', 'findOne', 'findByPk', 'create', 'update', 'destroy', 'bulkCreate'].includes(op);
}

function isCapitalized(str) {
  return str && str[0] === str[0].toUpperCase();
}

function camelToSnake(str) {
  return str.replace(/[A-Z]/g, letter => `_${letter.toLowerCase()}`).replace(/^_/, '');
}

function pluralizeTableName(singular) {
  // Simple pluralization - could be enhanced
  if (singular.endsWith('y')) {
    return singular.slice(0, -1) + 'ies';
  } else if (singular.endsWith('s') || singular.endsWith('sh') || singular.endsWith('ch')) {
    return singular + 'es';
  } else {
    return singular + 's';
  }
}

// Extract tables from raw SQL using simple regex (reuse existing extraction logic)
function extractTablesFromSql(sql) {
  const tables = [];
  const patterns = [
    { regex: /CREATE\s+TABLE\s+(?:IF\s+NOT\s+EXISTS\s+)?[`"']?(\w+)[`"']?/gi, op: 'create' },
    { regex: /ALTER\s+TABLE\s+[`"']?(\w+)[`"']?/gi, op: 'alter' },
    { regex: /DROP\s+TABLE\s+(?:IF\s+EXISTS\s+)?[`"']?(\w+)[`"']?/gi, op: 'drop' },
    { regex: /UPDATE\s+[`"']?(\w+)[`"']?\s+SET/gi, op: 'update' },
    { regex: /INSERT\s+INTO\s+[`"']?(\w+)[`"']?/gi, op: 'insert' },
    { regex: /DELETE\s+FROM\s+[`"']?(\w+)[`"']?/gi, op: 'delete' },
    { regex: /FROM\s+[`"']?(\w+)[`"']?/gi, op: 'select' },
    { regex: /JOIN\s+[`"']?(\w+)[`"']?/gi, op: 'select' }
  ];
  
  patterns.forEach(pattern => {
    let match;
    while ((match = pattern.regex.exec(sql)) !== null) {
      const tableName = match[1].toLowerCase();
      // Skip common SQL keywords
      if (!['select', 'from', 'where', 'and', 'or', 'as', 'on', 'set'].includes(tableName)) {
        tables.push({ table: tableName, operation: pattern.op });
      }
    }
  });
  
  return tables;
}

module.exports = {
  detectApiHandlers,
  detectDbOperations
};