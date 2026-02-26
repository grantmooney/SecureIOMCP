/** Each entry: [category, test_value, confidence_level] */
export const SECRET_CORPUS: [string, string, string][] = [
  // High confidence — distinct prefixes
  ['AWS_ACCESS_KEY', 'AKIAIOSFODNN7EXAMPLE', 'high'],
  ['AWS_ACCESS_KEY', 'AKIA1234567890ABCDEF', 'high'],
  ['AWS_ACCESS_KEY', 'AKIAZ26MRUQLEXAMPLE1', 'high'],
  ['GITHUB_TOKEN', 'ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijkl', 'high'],
  ['GITHUB_TOKEN', 'ghs_ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijkl', 'high'],
  ['GITHUB_FINE_GRAINED_TOKEN', 'github_pat_' + 'A'.repeat(82), 'high'],
  ['STRIPE_LIVE_KEY', 'sk_live_abcdefghijklmnopqrstuvwx', 'high'],
  ['STRIPE_PUBLISHABLE_KEY', 'pk_live_abcdefghijklmnopqrstuvwx', 'high'],
  ['SLACK_WEBHOOK', 'https://hooks.slack.com/services/T12345678/B12345678/abcdefghijklmnopqrstuvwx', 'high'],
  ['SENDGRID_KEY', 'SG.abcdefghijklmnopqrstuv.abcdefghijklmnopqrstuvwxyz0123456789_abcde', 'high'],
  ['TWILIO_AUTH_TOKEN', 'SK0123456789abcdef0123456789abcdef', 'high'],
  ['PRIVATE_KEY_BLOCK', '-----BEGIN RSA PRIVATE KEY-----', 'high'],
  ['PRIVATE_KEY_BLOCK', '-----BEGIN EC PRIVATE KEY-----', 'high'],
  ['JWT', 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dozjgNryP4J3jVmNHl0w5N_XgL0n3I9PlFUP0THsR8U', 'high'],

  // Medium confidence — context-anchored
  ['AWS_SECRET_KEY', 'aws_secret_access_key = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"', 'medium'],
  ['AWS_SECRET_KEY', "aws_secret_access_key: 'wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY'", 'medium'],
  ['AZURE_STORAGE_KEY', 'AccountKey=abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789abcdefghijklmnopqrstuv==', 'medium'],
  ['CONNECTION_STRING', 'postgres://admin:s3cretP@ss@db.example.com:5432/mydb', 'medium'],
  ['CONNECTION_STRING', 'mongodb://user:password123@mongo.example.com:27017/app', 'medium'],
  ['CONNECTION_STRING', 'redis://default:mypassword@redis.example.com:6379', 'medium'],
  ['CONNECTION_STRING', 'amqp://guest:guest@rabbitmq.example.com:5672', 'medium'],
  ['GENERIC_API_KEY', 'api_key = "sk_test_abcdef123456789abcdef"', 'medium'],
  ['GENERIC_API_KEY', 'secret_key: "my-super-secret-key-value"', 'medium'],
  ['GENERIC_API_KEY', 'auth_token = "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9"', 'medium'],
  ['GENERIC_SECRET', 'password = "MyS3cur3P@ssw0rd!"', 'medium'],
  ['GENERIC_SECRET', "token: 'a1b2c3d4e5f6g7h8i9j0klmnopqrstuv'", 'medium'],
  ['GENERIC_SECRET', 'credential = "super-secret-credential-value"', 'medium'],
];

/** Lines containing secrets for integration testing */
export const LINES_WITH_SECRETS = [
  'export AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE',
  'const apiKey = "ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijkl";',
  'DATABASE_URL=postgres://admin:s3cretP@ss@db.example.com:5432/mydb',
  '-----BEGIN RSA PRIVATE KEY-----',
  'STRIPE_KEY=sk_live_abcdefghijklmnopqrstuvwx',
  'password = "MyS3cur3P@ssw0rd!"',
];
