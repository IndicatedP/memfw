import Database from 'better-sqlite3';
import { v4 as uuidv4 } from 'uuid';
import { TrustLevel, Memory, MemoryProvenance, DetectionResult } from '../core/types.js';
import { IngressTagger, TagOptions } from '../tagger/index.js';
import { ProvenanceStore } from './provenance.js';

/**
 * Result of writing a memory
 */
export interface WriteResult {
  /** Whether the write was allowed */
  allowed: boolean;
  /** Memory ID if written, quarantine ID if quarantined */
  id: string;
  /** Detection result from analysis */
  detection: DetectionResult;
  /** Provenance metadata */
  provenance: MemoryProvenance;
}

/**
 * Options for reading memories
 */
export interface ReadOptions {
  /** Minimum trust level to include */
  minTrust?: TrustLevel;
  /** Maximum trust level to include */
  maxTrust?: TrustLevel;
  /** Filter by source */
  source?: string;
  /** Filter by session */
  sessionId?: string;
  /** Maximum number of results */
  limit?: number;
  /** Offset for pagination */
  offset?: number;
  /** Search text (partial match) */
  search?: string;
}

/**
 * Trust level ordering for comparisons
 */
const TRUST_ORDER: Record<TrustLevel, number> = {
  [TrustLevel.USER]: 5,
  [TrustLevel.TOOL_VERIFIED]: 4,
  [TrustLevel.TOOL_UNVERIFIED]: 3,
  [TrustLevel.AGENT]: 2,
  [TrustLevel.EXTERNAL]: 1,
};

/**
 * Provenance-aware memory store
 */
export class MemoryStore {
  private db: Database.Database;
  private tagger: IngressTagger;
  private provenanceStore: ProvenanceStore;

  constructor(options: {
    dbPath: string;
    tagger: IngressTagger;
    provenanceStore: ProvenanceStore;
  }) {
    this.db = new Database(options.dbPath);
    this.tagger = options.tagger;
    this.provenanceStore = options.provenanceStore;
    this.initSchema();
  }

  /**
   * Initialize database schema
   */
  private initSchema(): void {
    this.db.exec(`
      CREATE TABLE IF NOT EXISTS memories (
        id TEXT PRIMARY KEY,
        text TEXT NOT NULL,
        provenance_id TEXT NOT NULL,
        created_at TEXT NOT NULL,
        last_accessed_at TEXT,
        FOREIGN KEY (provenance_id) REFERENCES provenance(id)
      );

      CREATE INDEX IF NOT EXISTS idx_memories_provenance ON memories(provenance_id);
      CREATE INDEX IF NOT EXISTS idx_memories_created ON memories(created_at);
      CREATE VIRTUAL TABLE IF NOT EXISTS memories_fts USING fts5(text, content='memories', content_rowid='rowid');

      CREATE TRIGGER IF NOT EXISTS memories_ai AFTER INSERT ON memories BEGIN
        INSERT INTO memories_fts(rowid, text) VALUES (NEW.rowid, NEW.text);
      END;

      CREATE TRIGGER IF NOT EXISTS memories_ad AFTER DELETE ON memories BEGIN
        INSERT INTO memories_fts(memories_fts, rowid, text) VALUES('delete', OLD.rowid, OLD.text);
      END;

      CREATE TRIGGER IF NOT EXISTS memories_au AFTER UPDATE ON memories BEGIN
        INSERT INTO memories_fts(memories_fts, rowid, text) VALUES('delete', OLD.rowid, OLD.text);
        INSERT INTO memories_fts(rowid, text) VALUES (NEW.rowid, NEW.text);
      END;
    `);
  }

  /**
   * Write a memory with provenance tagging and detection
   */
  async write(options: TagOptions): Promise<WriteResult> {
    // Run through tagger (detection + provenance)
    const tagResult = await this.tagger.tag(options);

    // If quarantined, don't write to memory store
    if (!tagResult.allowed) {
      return {
        allowed: false,
        id: tagResult.quarantineId!,
        detection: tagResult.detection,
        provenance: tagResult.provenance,
      };
    }

    // Write to memory store
    const id = uuidv4();
    const createdAt = new Date();

    const stmt = this.db.prepare(`
      INSERT INTO memories (id, text, provenance_id, created_at)
      VALUES (?, ?, ?, ?)
    `);

    stmt.run(id, options.text, tagResult.provenance.id, createdAt.toISOString());

    return {
      allowed: true,
      id,
      detection: tagResult.detection,
      provenance: tagResult.provenance,
    };
  }

  /**
   * Read memories with trust level filtering
   */
  read(options?: ReadOptions): Memory[] {
    const conditions: string[] = [];
    const params: (string | number)[] = [];

    // Build query with provenance join
    let query = `
      SELECT m.*, p.source, p.trust_level, p.timestamp as prov_timestamp,
             p.session_id, p.trigger_context, p.detection_score, p.flags
      FROM memories m
      JOIN provenance p ON m.provenance_id = p.id
    `;

    // Trust level filters
    if (options?.minTrust) {
      const minOrder = TRUST_ORDER[options.minTrust];
      const validLevels = Object.entries(TRUST_ORDER)
        .filter(([_, order]) => order >= minOrder)
        .map(([level]) => level);
      conditions.push(`p.trust_level IN (${validLevels.map(() => '?').join(', ')})`);
      params.push(...validLevels);
    }

    if (options?.maxTrust) {
      const maxOrder = TRUST_ORDER[options.maxTrust];
      const validLevels = Object.entries(TRUST_ORDER)
        .filter(([_, order]) => order <= maxOrder)
        .map(([level]) => level);
      conditions.push(`p.trust_level IN (${validLevels.map(() => '?').join(', ')})`);
      params.push(...validLevels);
    }

    if (options?.source) {
      conditions.push('p.source = ?');
      params.push(options.source);
    }

    if (options?.sessionId) {
      conditions.push('p.session_id = ?');
      params.push(options.sessionId);
    }

    if (options?.search) {
      // Use FTS for text search
      conditions.push('m.rowid IN (SELECT rowid FROM memories_fts WHERE memories_fts MATCH ?)');
      params.push(options.search);
    }

    if (conditions.length > 0) {
      query += ' WHERE ' + conditions.join(' AND ');
    }

    query += ' ORDER BY m.created_at DESC';

    if (options?.limit) {
      query += ' LIMIT ?';
      params.push(options.limit);
    }

    if (options?.offset) {
      query += ' OFFSET ?';
      params.push(options.offset);
    }

    const stmt = this.db.prepare(query);
    const rows = stmt.all(...params) as MemoryRow[];
    return rows.map((row) => this.rowToMemory(row));
  }

  /**
   * Get a memory by ID
   */
  get(id: string): Memory | null {
    const stmt = this.db.prepare(`
      SELECT m.*, p.source, p.trust_level, p.timestamp as prov_timestamp,
             p.session_id, p.trigger_context, p.detection_score, p.flags
      FROM memories m
      JOIN provenance p ON m.provenance_id = p.id
      WHERE m.id = ?
    `);
    const row = stmt.get(id) as MemoryRow | undefined;

    if (row) {
      // Update last accessed timestamp
      this.db.prepare('UPDATE memories SET last_accessed_at = ? WHERE id = ?')
        .run(new Date().toISOString(), id);
    }

    return row ? this.rowToMemory(row) : null;
  }

  /**
   * Delete a memory
   */
  delete(id: string): boolean {
    const stmt = this.db.prepare('DELETE FROM memories WHERE id = ?');
    const result = stmt.run(id);
    return result.changes > 0;
  }

  /**
   * Get total count
   */
  getTotal(): number {
    const stmt = this.db.prepare('SELECT COUNT(*) as count FROM memories');
    const row = stmt.get() as { count: number };
    return row.count;
  }

  /**
   * Get counts by trust level
   */
  getCountsByTrust(): Record<TrustLevel, number> {
    const stmt = this.db.prepare(`
      SELECT p.trust_level, COUNT(*) as count
      FROM memories m
      JOIN provenance p ON m.provenance_id = p.id
      GROUP BY p.trust_level
    `);
    const rows = stmt.all() as { trust_level: string; count: number }[];

    const counts: Record<TrustLevel, number> = {
      [TrustLevel.USER]: 0,
      [TrustLevel.TOOL_VERIFIED]: 0,
      [TrustLevel.TOOL_UNVERIFIED]: 0,
      [TrustLevel.AGENT]: 0,
      [TrustLevel.EXTERNAL]: 0,
    };

    for (const row of rows) {
      counts[row.trust_level as TrustLevel] = row.count;
    }

    return counts;
  }

  /**
   * Convert database row to Memory
   */
  private rowToMemory(row: MemoryRow): Memory {
    return {
      id: row.id,
      text: row.text,
      createdAt: new Date(row.created_at),
      lastAccessedAt: row.last_accessed_at ? new Date(row.last_accessed_at) : undefined,
      provenance: {
        id: row.provenance_id,
        source: row.source,
        trustLevel: row.trust_level as TrustLevel,
        timestamp: new Date(row.prov_timestamp),
        sessionId: row.session_id ?? undefined,
        triggerContext: row.trigger_context ?? undefined,
        detectionScore: row.detection_score ?? undefined,
        flags: row.flags ? JSON.parse(row.flags) : undefined,
      },
    };
  }

  /**
   * Close database connection
   */
  close(): void {
    this.db.close();
  }
}

/**
 * Database row type
 */
interface MemoryRow {
  id: string;
  text: string;
  provenance_id: string;
  created_at: string;
  last_accessed_at: string | null;
  source: string;
  trust_level: string;
  prov_timestamp: string;
  session_id: string | null;
  trigger_context: string | null;
  detection_score: number | null;
  flags: string | null;
}
