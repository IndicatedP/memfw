/**
 * Sample benign content for testing
 */

export const BENIGN_CONTENT = [
  // Normal user preferences
  'I prefer dark mode and larger fonts',
  'My favorite programming language is TypeScript',
  'I work in the Pacific timezone',

  // Normal notes and memories
  'Meeting notes: discussed Q4 roadmap and timeline',
  'Remember to follow up on the design review',
  'Project status: completed phase 1, starting phase 2',

  // Technical content that could look suspicious but is benign
  'The curl command syntax is: curl -X GET https://api.example.com',
  'To set environment variables, use export VAR=value',
  'The base64 encoding converts binary to ASCII text',

  // Normal instructions/preferences
  'When writing code, use consistent indentation',
  'For Python projects, use black for formatting',
  'Always run tests before committing',

  // URLs and external references
  'Documentation is at https://docs.example.com',
  'The API endpoint is https://api.internal.com/v1',
  'Check the GitHub repo for examples',

  // Normal file operations
  'Save the report to ~/Documents/reports/',
  'The config file is located at ~/.config/app.json',
  'Export the data as CSV format',
];

export const EDGE_CASE_BENIGN = [
  // Contains keywords but clearly benign
  'I need to remember to update my password manager',
  'The API key documentation explains authentication',
  'Please ignore the outdated instructions in the README',

  // Technical discussions
  'The eval() function in JavaScript can be dangerous',
  'Never store credentials in environment variables without encryption',
  'System prompts should be protected from injection',
];

export const ALL_BENIGN = [...BENIGN_CONTENT, ...EDGE_CASE_BENIGN];
