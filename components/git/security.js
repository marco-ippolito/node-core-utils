import CLI from '../../lib/cli.js';
import SecurityReleaseSteward from '../../lib/prepare_security.js';

export const command = 'security [issue] [options]';
export const describe = 'Manage an in-progress security release or start a new one.';

const securityOptions = {
  start: {
    describe: 'Start security release process',
    type: 'boolean'
  },
  requestCVEs: {
    describe: 'Request CVEs from hackerone',
    type: 'boolean'
  }
};

let yargsInstance;

export function builder(yargs) {
  yargsInstance = yargs;
  return yargs.options(securityOptions)
    .positional('issue', {
      type: 'string',
      describe: 'ID or URL of the security release issue'
    })
    .check(argv => {
      if (argv.requestCVEs && !argv.issue) {
        throw new Error('The --requestCVEs flag requires an issue');
      }
      return true;
    })
    .example(
      'git node security --start',
      'Prepare a security release of Node.js')
    .example(
      'git node security 514 --requestCVEs',
      'Request CVEs for the security release issue');
}

export function handler(argv) {
  if (argv.start) {
    return startSecurityRelease(argv);
  }
  if (argv.requestCVEs) {
    return requestCVEs(argv);
  }
  yargsInstance.showHelp();
}

async function startSecurityRelease(argv) {
  const logStream = process.stdout.isTTY ? process.stdout : process.stderr;
  const cli = new CLI(logStream);
  const release = new SecurityReleaseSteward(cli);
  return release.start();
}

async function requestCVEs(argv) {
  return 'TODO: request CVEs';
}
