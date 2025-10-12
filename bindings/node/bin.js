#!/usr/bin/env node

const { run } = require('./index.js');

const args = process.argv.slice(2);

try {
  run(args);
} catch (err) {
  console.error(err);
  process.exit(1);
}
