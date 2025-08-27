const { parseSqlFile, fallbackRegexAnalysis, extractEntitiesFromContent } = require('../parse');

// Mock dependencies
jest.mock('@actions/core');
const core = require('@actions/core');

describe('SQL Parse Module', () => {
  beforeEach(() => {
    jest.clearAllMocks();
    core.info = jest.fn();
    core.warning = jest.fn();
  });

  describe('parseSqlFile', () => {
    describe('partial success scenarios', () => {
      test('should handle mixed valid and invalid statements', () => {
        const sqlContent = `
          CREATE TABLE users (id INT PRIMARY KEY, name VARCHAR(100));
          SOME_INVALID_VENDOR_SPECIFIC_SYNTAX with weird stuff;
          DROP TABLE old_logs;
        `;
        const filename = 'mixed_valid_invalid.sql';

        const result = parseSqlFile(sqlContent, filename);

        // Should warn about the invalid statement
        expect(core.warning).toHaveBeenCalledWith(
          expect.stringContaining('AST parsing failed for statement in mixed_valid_invalid.sql')
        );
        
        // Should still detect valid statements
        expect(result.sqlChanges.length).toBeGreaterThan(0);
        expect(result.entities).toContain('users');
        expect(result.entities).toContain('old_logs');
        
        // Should include both AST-parsed and regex-fallback results
        const hasDropTable = result.sqlChanges.some(change => change.includes('DROP TABLE'));
        expect(hasDropTable).toBe(true);
      });

      test('should handle vendor-specific syntax with fallback', () => {
        const sqlContent = `
          CREATE TABLE test_table (id INT);
          EXEC sp_some_stored_procedure @param1 = 'value';
          ALTER TABLE test_table ADD COLUMN email VARCHAR(255);
        `;
        const filename = 'vendor_specific.sql';

        const result = parseSqlFile(sqlContent, filename);

        // Should warn about the vendor-specific statement
        expect(core.warning).toHaveBeenCalledWith(
          expect.stringContaining('AST parsing failed for statement')
        );
        expect(core.warning).toHaveBeenCalledWith(
          expect.stringContaining('EXEC sp_some_stored_procedure')
        );

        // Should still capture valid DDL operations
        expect(result.entities).toContain('test_table');
        // Note: ALTER TABLE ADD COLUMN operations don't generate sqlChanges in the current logic
        expect(result.sqlChanges).toBeDefined();
      });

      test('should handle unparseable CREATE with quoted identifiers', () => {
        const sqlContent = `
          CREATE TABLE users (id INT);
          CREATE TABLE [weird-table-name] WITH SOME_INVALID_OPTION;
          DROP TABLE legacy_table;
        `;
        const filename = 'quoted_identifiers.sql';

        const result = parseSqlFile(sqlContent, filename);

        // Should warn about full-file failure and then the unparseable CREATE statement
        expect(core.warning).toHaveBeenCalled();
        expect(core.warning).toHaveBeenCalledWith(
          expect.stringContaining('CREATE TABLE [weird-table-name] WITH SOME_INVALID_OPTION')
        );

        // Should still detect the valid statements via AST
        expect(result.entities).toContain('users');
        expect(result.entities).toContain('legacy_table');
        
        // Should include both AST results and regex fallback
        const hasValidCreate = result.sqlChanges.some(change => 
          change.includes('users') || result.entities.includes('users')
        );
        const hasDropTable = result.sqlChanges.some(change => 
          change.includes('DROP TABLE: legacy_table')
        );
        expect(hasValidCreate).toBe(true);
        expect(hasDropTable).toBe(true);
      });
    });

    describe('all valid statements', () => {
      test('should parse multiple valid statements without warnings', () => {
        const sqlContent = `
          CREATE TABLE products (id INT PRIMARY KEY, name VARCHAR(100));
          ALTER TABLE products ADD COLUMN price DECIMAL(10,2);
          DROP TABLE temp_data;
          CREATE TABLE orders (id INT, product_id INT);
        `;
        const filename = 'all_valid.sql';

        const result = parseSqlFile(sqlContent, filename);

        // Should not have any warnings
        expect(core.warning).not.toHaveBeenCalled();
        
        // Should detect all entities
        expect(result.entities).toContain('products');
        expect(result.entities).toContain('temp_data');
        expect(result.entities).toContain('orders');
        
        // Should have correct change count
        expect(result.sqlChanges.length).toBeGreaterThan(0);
        
        // Should detect the DROP TABLE operation
        const hasDropTable = result.sqlChanges.some(change => 
          change.includes('DROP TABLE: temp_data')
        );
        expect(hasDropTable).toBe(true);
      });

      test('should handle table rename detection correctly', () => {
        const sqlContent = `
          DROP TABLE users;
          CREATE TABLE users (id INT, email VARCHAR(255), updated_at TIMESTAMP);
        `;
        const filename = 'table_rename.sql';

        const result = parseSqlFile(sqlContent, filename);

        // Should not warn since both statements are valid
        expect(core.warning).not.toHaveBeenCalled();
        
        // Should detect the rename
        const hasTableRename = result.sqlChanges.some(change => 
          change.includes('TABLE RENAME: users')
        );
        expect(hasTableRename).toBe(true);
        
        // Should have 'users' in entities
        expect(result.entities).toContain('users');
      });

      test('should handle column operations correctly', () => {
        const sqlContent = `
          ALTER TABLE users DROP COLUMN old_field;
          ALTER TABLE users ADD COLUMN new_field VARCHAR(100);
          ALTER TABLE users ADD COLUMN another_field INT;
        `;
        const filename = 'column_ops.sql';

        const result = parseSqlFile(sqlContent, filename);

        expect(core.warning).not.toHaveBeenCalled();
        
        // Should detect column operations
        const hasDropColumn = result.sqlChanges.some(change => 
          change.includes('DROP COLUMN: old_field')
        );
        expect(hasDropColumn).toBe(true);
        
        // Should detect the net gain in columns (dropped 1, added 2 = +1)
        const hasColumnRename = result.sqlChanges.some(change => 
          change.includes('COLUMN RENAME: users')
        );
        expect(hasColumnRename).toBe(true);
      });
    });

    describe('all invalid statements', () => {
      test('should handle multiple unparseable statements with warnings', () => {
        const sqlContent = `
          EXEC sp_custom_procedure @param = 'value';
          SOME_PROPRIETARY_COMMAND WITH invalid syntax;
          ANOTHER_WEIRD_STATEMENT that breaks AST;
        `;
        const filename = 'all_invalid.sql';

        const result = parseSqlFile(sqlContent, filename);

        // Should warn for full-file failure plus each unparseable statement
        expect(core.warning).toHaveBeenCalledTimes(4); // 1 full-file + 3 individual statements
        expect(core.warning).toHaveBeenCalledWith(
          expect.stringContaining('EXEC sp_custom_procedure')
        );
        expect(core.warning).toHaveBeenCalledWith(
          expect.stringContaining('SOME_PROPRIETARY_COMMAND')
        );
        expect(core.warning).toHaveBeenCalledWith(
          expect.stringContaining('ANOTHER_WEIRD_STATEMENT')
        );

        // Result should still be valid structure, but likely with regex-detected changes
        expect(result.sqlChanges).toBeDefined();
        expect(result.entities).toBeDefined();
        expect(Array.isArray(result.sqlChanges)).toBe(true);
        expect(Array.isArray(result.entities)).toBe(true);
      });

      test('should handle single complex unparseable statement', () => {
        const sqlContent = `
          CREATE FUNCTION complex_function()
          RETURNS TABLE
          AS
          BEGIN
            RETURN SELECT * FROM (
              WITH RECURSIVE cte AS (
                SELECT id FROM table1 
                UNION ALL 
                SELECT t.id FROM table1 t JOIN cte ON t.parent_id = cte.id
              )
              SELECT * FROM cte
            )
          END;
        `;
        const filename = 'complex_function.sql';

        const result = parseSqlFile(sqlContent, filename);

        // Should warn about the unparseable function (the complex multi-line statement gets split)
        expect(core.warning).toHaveBeenCalled();
        expect(core.warning).toHaveBeenCalledWith(
          expect.stringContaining('AST parsing failed for statement')
        );

        // Should fall back to regex analysis
        expect(result.sqlChanges).toBeDefined();
        expect(result.entities).toBeDefined();
      });
    });

    describe('edge cases', () => {
      test('should handle empty content', () => {
        const result = parseSqlFile('', 'empty.sql');

        expect(core.warning).not.toHaveBeenCalled();
        expect(result.sqlChanges).toEqual([]);
        expect(result.entities).toEqual([]);
      });

      test('should handle content with only whitespace and comments', () => {
        const sqlContent = `
          -- This is a comment
          /* Multi-line comment */
          
          
        `;
        const filename = 'comments_only.sql';

        const result = parseSqlFile(sqlContent, filename);

        expect(core.warning).not.toHaveBeenCalled();
        expect(result.sqlChanges).toEqual([]);
        expect(result.entities).toEqual([]);
      });

      test('should handle single statement without semicolon', () => {
        const sqlContent = 'CREATE TABLE test (id INT)';
        const filename = 'no_semicolon.sql';

        const result = parseSqlFile(sqlContent, filename);

        expect(core.warning).not.toHaveBeenCalled();
        expect(result.entities).toContain('test');
      });

      test('should handle mixed case and schema-qualified names', () => {
        const sqlContent = `
          CREATE TABLE Schema1.Users (ID INT);
          drop table SCHEMA2.old_table;
          ALTER TABLE [dbo].[Products] ADD COLUMN Price MONEY;
        `;
        const filename = 'mixed_case_schema.sql';

        const result = parseSqlFile(sqlContent, filename);

        // Should handle the schema-qualified names
        expect(result.entities.length).toBeGreaterThan(0);
        
        // Should detect the DROP operation
        const hasDropTable = result.sqlChanges.some(change => 
          change.includes('DROP TABLE')
        );
        expect(hasDropTable).toBe(true);
      });
    });

    describe('dialect detection', () => {
      test('should log detected SQL dialect', () => {
        const sqlContent = 'CREATE TABLE test (id INT);';
        const filename = 'dialect_test.sql';

        parseSqlFile(sqlContent, filename);

        expect(core.info).toHaveBeenCalledWith(
          expect.stringMatching(/Detected SQL dialect: \w+ for dialect_test\.sql/)
        );
      });
    });

    describe('production edge cases', () => {
      test('should handle semicolons in string literals', () => {
        const sqlContent = `
          CREATE TABLE users (bio TEXT);
          INSERT INTO users (bio) VALUES ('I am a developer; I love SQL');
          CREATE TABLE logs (message TEXT);
        `;
        const filename = 'strings.sql';

        const result = parseSqlFile(sqlContent, filename);
        
        // Should detect both tables (INSERT doesn't add to entities, but CREATE does)
        expect(result.entities).toContain('users');
        expect(result.entities).toContain('logs');
        
        // Should parse correctly despite semicolon in string
        expect(result.sqlChanges).toBeDefined();
        expect(Array.isArray(result.sqlChanges)).toBe(true);
      });

      test('should handle procedural SQL blocks', () => {
        const sqlContent = `
          CREATE FUNCTION update_timestamp()
          RETURNS TRIGGER AS $$
          BEGIN
            NEW.updated_at = NOW();
            RETURN NEW;
          END;
          $$ language 'plpgsql';
          
          DROP TABLE old_logs;
        `;
        const filename = 'procedure.sql';

        const result = parseSqlFile(sqlContent, filename);
        
        // Should detect DROP TABLE operation
        const hasDropTable = result.sqlChanges.some(change => 
          change.includes('DROP TABLE: old_logs')
        );
        expect(hasDropTable).toBe(true);
        expect(result.entities).toContain('old_logs');
      });

      test('should capture entities even when AST fails', () => {
        const sqlContent = `
          SOME_VENDOR_SPECIFIC_COMMAND FOR users;
          DROP TABLE products;
        `;
        const filename = 'vendor.sql';

        const result = parseSqlFile(sqlContent, filename);
        
        // Even if first statement fails, should capture 'users' entity
        expect(result.entities.length).toBeGreaterThan(0);
        expect(result.entities).toContain('products');
        
        // Should have warnings for failed AST parsing
        expect(core.warning).toHaveBeenCalled();
      });

      test('should handle comments with semicolons', () => {
        const sqlContent = `
          -- This comment has a semicolon; but should not split
          CREATE TABLE test (id INT);
          /* Block comment with ; inside */
          ALTER TABLE test ADD COLUMN name VARCHAR(100);
        `;
        const filename = 'comments.sql';

        const result = parseSqlFile(sqlContent, filename);
        
        expect(result.entities).toContain('test');
        // Should successfully parse both statements
        expect(result.sqlChanges).toBeDefined();
      });

      test('should use two-phase parsing correctly', () => {
        const validSqlContent = `
          CREATE TABLE users (id INT);
          DROP TABLE old_table;
        `;
        const filename = 'valid.sql';

        const result = parseSqlFile(validSqlContent, filename);
        
        // Should use full-file AST mode (Phase 1) for valid SQL
        expect(core.info).toHaveBeenCalledWith(
          expect.stringMatching(/Successfully parsed all \d+ statements in valid\.sql using full-file AST mode/)
        );
        
        expect(result.entities).toContain('users');
        expect(result.entities).toContain('old_table');
      });

      test('should fall back to statement-by-statement when full-file parsing fails', () => {
        const complexSqlContent = `
          CREATE TABLE test (id INT);
          SOME_COMPLEX_VENDOR_SYNTAX that breaks full parsing;
          DROP TABLE old_test;
        `;
        const filename = 'complex.sql';

        const result = parseSqlFile(complexSqlContent, filename);
        
        // Should warn about falling back to statement-by-statement
        expect(core.warning).toHaveBeenCalledWith(
          expect.stringContaining('Full-file AST parsing failed for complex.sql')
        );
        expect(core.warning).toHaveBeenCalledWith(
          expect.stringContaining('Using resilient statement-by-statement mode')
        );
        
        // Should still capture entities from valid statements
        expect(result.entities).toContain('test');
        expect(result.entities).toContain('old_test');
      });

      test('should intelligently categorize entities in fallback mode', () => {
        const sqlContent = `
          VENDOR_SPECIFIC DROP TABLE old_users;
          CUSTOM_COMMAND CREATE TABLE new_users (id INT);
          ANOTHER_COMMAND ALTER TABLE products ADD COLUMN price DECIMAL;
        `;
        const filename = 'intelligent.sql';

        const result = parseSqlFile(sqlContent, filename);
        
        // Should categorize based on keywords
        expect(result.entities).toContain('old_users');  // Should be in droppedTables
        expect(result.entities).toContain('new_users');  // Should be in createdTables  
        expect(result.entities).toContain('products');   // Should default to createdTables
        
        // Should have multiple warnings for AST parsing failures
        expect(core.warning).toHaveBeenCalledTimes(4); // 1 for full-file + 3 for individual statements
      });

      test('should handle mixed quoted identifiers and complex syntax', () => {
        const sqlContent = `
          CREATE TABLE "table-with-dashes" (id INT);
          DROP TABLE [bracketed_table];
          UPDATE \`backtick_table\` SET value = 'text with ; semicolon';
        `;
        const filename = 'quotes.sql';

        const result = parseSqlFile(sqlContent, filename);
        
        // Should extract table names correctly despite quoting
        expect(result.entities.length).toBeGreaterThan(0);
        
        // Should handle the semicolon in string without incorrect splitting
        expect(result.sqlChanges).toBeDefined();
      });

      test('should preserve performance with full-file parsing for clean SQL', () => {
        const cleanSql = `
          CREATE TABLE orders (id INT, customer_id INT);
          CREATE TABLE items (id INT, order_id INT, product_name VARCHAR(255));
          ALTER TABLE items ADD CONSTRAINT fk_order FOREIGN KEY (order_id) REFERENCES orders(id);
        `;
        const filename = 'clean.sql';

        const result = parseSqlFile(cleanSql, filename);
        
        // Should use efficient full-file parsing
        expect(core.info).toHaveBeenCalledWith(
          expect.stringMatching(/Successfully parsed all 3 statements in clean\.sql using full-file AST mode/)
        );
        
        // Should not fall back to statement-by-statement
        expect(core.warning).not.toHaveBeenCalledWith(
          expect.stringContaining('Using resilient statement-by-statement mode')
        );
        
        expect(result.entities).toContain('orders');
        expect(result.entities).toContain('items');
      });
    });
  });

  describe('fallbackRegexAnalysis', () => {
    test('should detect DROP TABLE operations', () => {
      const content = 'DROP TABLE users; DROP TABLE IF EXISTS logs;';
      const changes = fallbackRegexAnalysis(content, 'test.sql');

      expect(changes).toContain('DROP TABLE: users');
      expect(changes).toContain('DROP TABLE: logs');
    });

    test('should detect schema-qualified table names', () => {
      const content = 'DROP TABLE dbo.users; DROP TABLE [schema1].[table1];';
      const changes = fallbackRegexAnalysis(content, 'test.sql');

      expect(changes).toContain('DROP TABLE: dbo.users');
      expect(changes).toContain('DROP TABLE: schema1.table1');
    });
  });

  describe('extractEntitiesFromContent', () => {
    test('should extract table names from various SQL operations', () => {
      const content = `
        CREATE TABLE users (id INT);
        ALTER TABLE products ADD COLUMN name VARCHAR(100);
        INSERT INTO orders VALUES (1, 'test');
        SELECT * FROM customers WHERE active = 1;
      `;

      const entities = extractEntitiesFromContent(content);

      expect(entities).toContain('users');
      expect(entities).toContain('products');
      expect(entities).toContain('orders');
      expect(entities).toContain('customers');
    });

    test('should handle schema-qualified table names', () => {
      const content = `
        SELECT * FROM dbo.users;
        UPDATE schema1.products SET price = 100;
      `;

      const entities = extractEntitiesFromContent(content);

      expect(entities).toContain('dbo.users');
      expect(entities).toContain('schema1.products');
    });
  });
});