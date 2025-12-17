#!/usr/bin/env node

const { run } = require('./index.js');

const args = process.argv.slice(2);

run(args).catch((err) => {
  console.error(err.message || err);
  process.exit(1);
});
