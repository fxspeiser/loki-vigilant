#!/usr/bin/env node
/**
 * Post-install script for npm package.
 * Prints setup instructions — does NOT auto-run setup (requires sudo).
 */

const path = require('path');
const pkg = require(path.join(__dirname, '..', 'package.json'));

const BOLD = '\x1b[1m';
const GREEN = '\x1b[32m';
const BLUE = '\x1b[34m';
const DIM = '\x1b[2m';
const RESET = '\x1b[0m';

console.log('');
console.log(`${BOLD}Loki Vigilant v${pkg.version}${RESET} installed successfully.`);
console.log('');
console.log(`${BOLD}Quick start:${RESET}`);
console.log(`  ${GREEN}loki-vigilant setup${RESET}          ${DIM}# Interactive dependency setup${RESET}`);
console.log(`  ${GREEN}loki-vigilant start${RESET}          ${DIM}# Start the dashboard${RESET}`);
console.log('');
console.log(`${BOLD}Agent/CI setup:${RESET}`);
console.log(`  ${GREEN}loki-vigilant agent-setup --api-key${RESET}   ${DIM}# Auto-install + API key${RESET}`);
console.log(`  ${GREEN}loki-vigilant agent-setup --headless${RESET}  ${DIM}# Install as service${RESET}`);
console.log('');
console.log(`${BOLD}Requirements:${RESET} Python 3.9+, nmap, tcpdump, sudo`);
console.log(`${BOLD}Dashboard:${RESET}    ${BLUE}http://127.0.0.1:5150${RESET}`);
console.log('');
