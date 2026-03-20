import { Type } from '@sinclair/typebox'
import type { AgentTool } from '@mariozechner/pi-agent-core'
import type { Env } from '../config.js'

interface DecoyFile {
  path: string
  content: string
  category: string
  monitoring_hint: string
}

const TEMPLATE_LIBRARY: Record<string, DecoyFile[]> = {
  ssh: [
    {
      path: '~/.aws/credentials',
      content: `[default]\naws_access_key_id = AKIAIOSFODNN7EXAMPLE\naws_secret_access_key = wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY\nregion = us-east-1`,
      category: 'credentials',
      monitoring_hint: 'Monitor file read access via Falco',
    },
    {
      path: '~/.ssh/id_rsa',
      content: `-----BEGIN OPENSSH PRIVATE KEY-----\nb3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAAAlwAAAAdzc2gtcn\nNhAAAAAwEAAQAAAIEA6Hn8rVFOxTmq9VE9qEonKMzFp5jCzK1EJwq3TFvFrdXmGmoQcR\nfake_key_data_for_deception_purposes_only_do_not_use\n-----END OPENSSH PRIVATE KEY-----`,
      category: 'credentials',
      monitoring_hint: 'Monitor file read access via Falco',
    },
    {
      path: '/etc/shadow.bak',
      content: `root:$6$rounds=656000$fakesalt$fakehashdatafordeceptionDKJFe8a9fDJKFjkd./:19000:0:99999:7:::\ndaemon:*:18858:0:99999:7:::\nbin:*:18858:0:99999:7:::`,
      category: 'system',
      monitoring_hint: 'Monitor file read access via Falco',
    },
    {
      path: '~/passwords.txt',
      content: `# Internal service passwords - DO NOT SHARE\ndb_prod: Pr0d_DB!2024_master\nredis_cache: r3d1s_C@che_s3cret\njira_api: jira-tok-AKfake123456789\nslack_webhook: https://hooks.slack.com/services/T00000000/B00000000/XXXXXXXXXXXXXXXXXXXXXXXX`,
      category: 'credentials',
      monitoring_hint: 'Monitor file read access via Falco',
    },
    {
      path: '~/.bash_history',
      content: `ssh admin@10.0.1.50\nmysql -u root -p'Pr0d_DB!2024_master' -h db-primary.internal\naws s3 ls s3://company-backups/\nkubectl get secrets -n production\ncurl -H "Authorization: Bearer eyJhbGciOiJIUzI1NiJ9.fake" http://api-internal:8080/admin`,
      category: 'history',
      monitoring_hint: 'Monitor file read access via Falco',
    },
  ],
  http: [
    {
      path: '/var/www/.env',
      content: `APP_ENV=production\nAPP_KEY=base64:fakekey1234567890abcdefghijklmnopqrstuvwx==\nDB_HOST=db-primary.internal\nDB_DATABASE=app_production\nDB_USERNAME=app_user\nDB_PASSWORD=Pr0d_DB!2024_master\nREDIS_HOST=redis-primary.internal\nREDIS_PASSWORD=r3d1s_C@che_s3cret\nAWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE\nAWS_SECRET_ACCESS_KEY=wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY`,
      category: 'credentials',
      monitoring_hint: 'Monitor file read access via Falco',
    },
    {
      path: '/var/www/backup/db.sql',
      content: `-- MySQL dump 10.13  Distrib 8.0.33\n-- Host: db-primary.internal\n-- Database: app_production\n\nCREATE TABLE users (\n  id INT PRIMARY KEY AUTO_INCREMENT,\n  email VARCHAR(255),\n  password_hash VARCHAR(255),\n  api_key VARCHAR(64)\n);\n\nINSERT INTO users VALUES (1,'admin@company.com','$2b$12$fakehashdata','sk-fake-api-key-001');`,
      category: 'data',
      monitoring_hint: 'Monitor file read access via Falco',
    },
    {
      path: '/var/www/config/secrets.yml',
      content: `production:\n  secret_key_base: 3f8a2b9c4d5e6f7a8b9c0d1e2f3a4b5c6d7e8f9a0b1c2d3e4f5a6b7c8d9e0f1\n  database:\n    host: db-primary.internal\n    username: rails_app\n    password: R@ils_Pr0d_2024\n  redis:\n    url: redis://:r3d1s_C@che_s3cret@redis-primary.internal:6379/0\n  smtp:\n    password: smtp_s3cret_2024`,
      category: 'credentials',
      monitoring_hint: 'Monitor file read access via Falco',
    },
    {
      path: '/var/www/.git/config',
      content: `[core]\n  repositoryformatversion = 0\n  filemode = true\n[remote "origin"]\n  url = https://deploy-token:glpat-faketoken123456@gitlab.company.com/platform/web-app.git\n  fetch = +refs/heads/*:refs/remotes/origin/*\n[branch "main"]\n  remote = origin\n  merge = refs/heads/main`,
      category: 'credentials',
      monitoring_hint: 'Monitor file read access via Falco',
    },
  ],
  mysql: [
    {
      path: '/var/backups/dump.sql',
      content: `-- MySQL dump 10.13  Distrib 8.0.33\n-- Host: localhost\n-- Database: production\n\nCREATE TABLE api_keys (\n  id INT PRIMARY KEY,\n  key_hash VARCHAR(255),\n  plaintext_key VARCHAR(64),\n  owner VARCHAR(255)\n);\n\nINSERT INTO api_keys VALUES (1,'$2b$12$hash','sk-prod-key-abc123','service-account');`,
      category: 'data',
      monitoring_hint: 'Monitor file read access via Falco',
    },
    {
      path: '/root/.my.cnf',
      content: `[client]\nuser=root\npassword=MySQL_R00t_2024!\nhost=localhost\nport=3306`,
      category: 'credentials',
      monitoring_hint: 'Monitor file read access via Falco',
    },
    {
      path: '/var/backups/mysql-cron.sh',
      content: `#!/bin/bash\n# Nightly backup script\nmysqldump -u root -p'MySQL_R00t_2024!' --all-databases > /var/backups/full-$(date +%F).sql\naws s3 cp /var/backups/full-$(date +%F).sql s3://company-db-backups/`,
      category: 'system',
      monitoring_hint: 'Monitor file read access via Falco',
    },
  ],
  postgres: [
    {
      path: '/var/backups/dump.sql',
      content: `--\n-- PostgreSQL database dump\n--\n\nCREATE TABLE credentials (\n  id serial PRIMARY KEY,\n  service varchar(255),\n  username varchar(255),\n  password varchar(255)\n);\n\nINSERT INTO credentials VALUES (1,'internal-api','svc-account','Pr0d_AP1_s3cret!');`,
      category: 'data',
      monitoring_hint: 'Monitor file read access via Falco',
    },
    {
      path: '/root/.pgpass',
      content: `db-primary.internal:5432:production:postgres:PG_Sup3r_S3cret_2024\nlocalhost:5432:*:postgres:PG_Sup3r_S3cret_2024`,
      category: 'credentials',
      monitoring_hint: 'Monitor file read access via Falco',
    },
  ],
  redis: [
    {
      path: '/var/redis/dump.rdb.bak',
      content: `REDIS0009\xfa\tredis-ver\x057.2.4\xfa\nredis-bits\xc0@`,
      category: 'data',
      monitoring_hint: 'Monitor file read access via Falco',
    },
    {
      path: '/etc/redis/redis.conf',
      content: `bind 0.0.0.0\nport 6379\nrequirepass r3d1s_C@che_s3cret\nmasterauth r3d1s_M@ster_2024\ndir /var/redis/data`,
      category: 'credentials',
      monitoring_hint: 'Monitor file read access via Falco',
    },
  ],
  mongodb: [
    {
      path: '/root/.mongoshrc.js',
      content: `// Auto-connect to production\ndb = connect("mongodb://admin:M0ng0_Pr0d_2024@localhost:27017/admin")`,
      category: 'credentials',
      monitoring_hint: 'Monitor file read access via Falco',
    },
    {
      path: '/var/backups/mongo-dump.archive',
      content: `{"_id":"admin","users":[{"user":"root","pwd":"M0ng0_Pr0d_2024","roles":["root"]}]}`,
      category: 'data',
      monitoring_hint: 'Monitor file read access via Falco',
    },
  ],
  ftp: [
    {
      path: '/home/ftpuser/.netrc',
      content: `machine ftp.company.com\nlogin admin\npassword FTP_Adm1n_2024!`,
      category: 'credentials',
      monitoring_hint: 'Monitor file read access via Falco',
    },
  ],
  smb: [
    {
      path: '/etc/samba/credentials.txt',
      content: `username=svc-backup\npassword=SMB_B@ckup_2024!\ndomain=CORP`,
      category: 'credentials',
      monitoring_hint: 'Monitor file read access via Falco',
    },
  ],
}

// Map service aliases to template keys
const SERVICE_MAP: Record<string, string> = {
  ssh: 'ssh',
  http: 'http',
  https: 'http',
  mysql: 'mysql',
  postgres: 'postgres',
  redis: 'redis',
  mongodb: 'mongodb',
  ftp: 'ftp',
  smb: 'smb',
  telnet: 'ssh',
  rdp: 'ssh',
  smtp: 'http',
  pop3: 'http',
  imap: 'http',
}

const GenerateDecoyFilesParams = Type.Object({
  honeypot_type: Type.String({ description: 'Service type of the honeypot (e.g., ssh, http, mysql, redis)' }),
  categories: Type.Optional(
    Type.Array(Type.String(), { description: 'Filter by category: credentials, data, system, history' }),
  ),
  count: Type.Optional(Type.Number({ description: 'Maximum number of decoy files to return', minimum: 1, maximum: 20 })),
})

export function createGenerateDecoyFilesTool(_env: Env): AgentTool<typeof GenerateDecoyFilesParams> {
  return {
    name: 'generate_decoy_files',
    label: 'Generate Decoy Files',
    description:
      'Generate realistic decoy files (fake credentials, backups, configs) for a honeypot type. Files are designed to attract attacker attention and trigger monitoring when accessed. Pass results into persona fake_files/file_contents.',
    parameters: GenerateDecoyFilesParams,
    execute: async (_toolCallId, params) => {
      const templateKey = SERVICE_MAP[params.honeypot_type] ?? 'ssh'
      let files = TEMPLATE_LIBRARY[templateKey] ?? TEMPLATE_LIBRARY.ssh

      if (params.categories && params.categories.length > 0) {
        const allowed = new Set(params.categories)
        files = files.filter((f) => allowed.has(f.category))
      }

      if (params.count && params.count < files.length) {
        files = files.slice(0, params.count)
      }

      return {
        content: [{ type: 'text' as const, text: JSON.stringify(files, null, 2) }],
        details: { count: files.length, honeypot_type: params.honeypot_type },
      }
    },
  }
}
