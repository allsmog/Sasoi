import { Type } from '@sinclair/typebox'
import type { AgentTool } from '@mariozechner/pi-agent-core'
import type { Env } from '../config.js'
import { queryDeploymentsByCluster } from '../clients/db.js'

interface Breadcrumb {
  type: string
  target_deployment_id: string
  content: string
  placement_path: string
}

type DeploymentRow = Record<string, unknown>

function generateSSHConfig(target: DeploymentRow): Breadcrumb {
  const ip = `10.0.${Math.floor(Math.random() * 254) + 1}.${Math.floor(Math.random() * 254) + 1}`
  const hostname = (target.hostname as string) ?? `hp-${(target.deployment_id as string).slice(0, 8)}`
  return {
    type: 'ssh_config',
    target_deployment_id: target.deployment_id as string,
    content: `Host ${hostname}\n  HostName ${ip}\n  User admin\n  Port ${(target.port as number) ?? 22}\n  IdentityFile ~/.ssh/id_rsa_internal`,
    placement_path: '~/.ssh/config',
  }
}

function generateBashHistory(target: DeploymentRow): Breadcrumb {
  const ip = `10.0.${Math.floor(Math.random() * 254) + 1}.${Math.floor(Math.random() * 254) + 1}`
  const hostname = (target.hostname as string) ?? `hp-${(target.deployment_id as string).slice(0, 8)}`
  const service = (target.service_type as string) ?? 'ssh'
  const commands: Record<string, string> = {
    ssh: `ssh admin@${ip}\nssh -i ~/.ssh/id_rsa_internal admin@${hostname}`,
    redis: `redis-cli -h ${ip} -a r3d1s_s3cret\nredis-cli -h ${hostname} INFO`,
    mysql: `mysql -h ${ip} -u root -p'db_s3cret_2024' production\nmysqldump -h ${hostname} --all-databases`,
    postgres: `psql -h ${ip} -U postgres -d production\npg_dump -h ${hostname} production`,
    http: `curl -H "Authorization: Bearer tok_fake123" http://${ip}:8080/api/admin\nwget http://${hostname}/backup.tar.gz`,
    mongodb: `mongosh "mongodb://admin:m0ng0_s3cret@${ip}:27017/admin"`,
  }
  return {
    type: 'bash_history',
    target_deployment_id: target.deployment_id as string,
    content: commands[service] ?? commands.ssh,
    placement_path: '~/.bash_history',
  }
}

function generateCachedCredentials(target: DeploymentRow): Breadcrumb {
  const ip = `10.0.${Math.floor(Math.random() * 254) + 1}.${Math.floor(Math.random() * 254) + 1}`
  const service = (target.service_type as string) ?? 'ssh'
  const configs: Record<string, { content: string; path: string }> = {
    mysql: {
      content: `[client]\nuser=root\npassword=db_s3cret_2024\nhost=${ip}\nport=3306`,
      path: '~/.my.cnf',
    },
    postgres: {
      content: `${ip}:5432:production:postgres:pg_s3cret_2024`,
      path: '~/.pgpass',
    },
    redis: {
      content: `redis-cli -h ${ip} -a r3d1s_s3cret`,
      path: '~/.rediscli_history',
    },
    mongodb: {
      content: `mongodb://admin:m0ng0_s3cret@${ip}:27017/admin`,
      path: '~/.mongosh/mongosh_repl_history',
    },
    ssh: {
      content: `${ip} ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABgQCfakekey...`,
      path: '~/.ssh/known_hosts',
    },
    http: {
      content: `machine ${ip}\nlogin admin\npassword api_s3cret_2024`,
      path: '~/.netrc',
    },
  }
  const config = configs[service] ?? configs.ssh
  return {
    type: 'cached_credentials',
    target_deployment_id: target.deployment_id as string,
    content: config.content,
    placement_path: config.path,
  }
}

function generateKnownHosts(target: DeploymentRow): Breadcrumb {
  const ip = `10.0.${Math.floor(Math.random() * 254) + 1}.${Math.floor(Math.random() * 254) + 1}`
  return {
    type: 'known_hosts',
    target_deployment_id: target.deployment_id as string,
    content: `${ip} ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABgQCfakeknownhostkey...`,
    placement_path: '~/.ssh/known_hosts',
  }
}

function generateAWSConfig(target: DeploymentRow): Breadcrumb {
  return {
    type: 'aws_config',
    target_deployment_id: target.deployment_id as string,
    content: `[profile internal]\naws_access_key_id = AKIAIOSFODNN7EXAMPLE\naws_secret_access_key = wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY\nregion = us-east-1`,
    placement_path: '~/.aws/credentials',
  }
}

function generateDockerConfig(target: DeploymentRow): Breadcrumb {
  return {
    type: 'docker_config',
    target_deployment_id: target.deployment_id as string,
    content: JSON.stringify({
      auths: {
        'registry.company.com': {
          auth: btoa('deploy:R3g1stry_T0k3n_2024'),
        },
      },
    }, null, 2),
    placement_path: '~/.docker/config.json',
  }
}

const GENERATORS: Record<string, (target: DeploymentRow) => Breadcrumb> = {
  ssh_config: generateSSHConfig,
  bash_history: generateBashHistory,
  cached_credentials: generateCachedCredentials,
  known_hosts: generateKnownHosts,
  aws_config: generateAWSConfig,
  docker_config: generateDockerConfig,
}

const BREADCRUMB_TYPES = ['ssh_config', 'bash_history', 'cached_credentials', 'known_hosts', 'aws_config', 'docker_config'] as const

const GenerateBreadcrumbsParams = Type.Object({
  tenant_id: Type.String({ description: 'Tenant UUID' }),
  source_deployment_id: Type.String({ description: 'Deployment ID of the honeypot where breadcrumbs will be placed' }),
  cluster_id: Type.Optional(Type.String({ description: 'Limit targets to same cluster' })),
  breadcrumb_types: Type.Optional(
    Type.Array(Type.String(), { description: 'Types: ssh_config, bash_history, cached_credentials, known_hosts, aws_config, docker_config' }),
  ),
  max_breadcrumbs: Type.Optional(Type.Number({ description: 'Maximum breadcrumbs to generate', minimum: 1, maximum: 20 })),
})

export function createGenerateBreadcrumbsTool(env: Env): AgentTool<typeof GenerateBreadcrumbsParams> {
  return {
    name: 'generate_breadcrumbs',
    label: 'Generate Breadcrumbs',
    description:
      'Generate breadcrumb artifacts (SSH configs, bash history, cached credentials) that reference sibling honeypots, creating a deception web. Attackers who find these will be led to other honeypots.',
    parameters: GenerateBreadcrumbsParams,
    execute: async (_toolCallId, params) => {
      const { results } = await queryDeploymentsByCluster(
        env.DB,
        params.tenant_id,
        params.cluster_id,
      )

      // Exclude source deployment
      const targets = (results ?? []).filter(
        (d: Record<string, unknown>) => d.deployment_id !== params.source_deployment_id,
      )

      if (targets.length === 0) {
        return {
          content: [{ type: 'text' as const, text: 'No sibling deployments found to create breadcrumbs for.' }],
          details: { count: 0 },
        }
      }

      const allowedTypes = params.breadcrumb_types
        ? BREADCRUMB_TYPES.filter((t) => params.breadcrumb_types!.includes(t))
        : [...BREADCRUMB_TYPES]

      const breadcrumbs: Breadcrumb[] = []
      const max = params.max_breadcrumbs ?? 10

      for (const target of targets) {
        if (breadcrumbs.length >= max) break
        for (const bType of allowedTypes) {
          if (breadcrumbs.length >= max) break
          const generator = GENERATORS[bType]
          if (generator) {
            breadcrumbs.push(generator(target as DeploymentRow))
          }
        }
      }

      return {
        content: [{ type: 'text' as const, text: JSON.stringify(breadcrumbs, null, 2) }],
        details: { count: breadcrumbs.length, targets: targets.length },
      }
    },
  }
}
