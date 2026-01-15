import { Storage } from './storage';

export class Database {
  private storage: Storage;

  constructor() {
    this.storage = new Storage();
  }

  init() {
    console.log('✅ Database initialized (JSON storage)');
  }

  getStorage() {
    return this.storage;
  }
}
