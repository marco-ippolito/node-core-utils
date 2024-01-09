import CLI from '../../lib/cli.js';
import SecurityReleaseSteward from '../../lib/prepare_security.js';
import SecurityReleasereserveCVEIds from '../../lib/request-cve.js';

export const command = 'security [issueNumber] [options]';
export const describe = 'Manage an in-progress security release or start a new one.';

const securityOptions = {
  start: {
    describe: 'Start security release process',
    type: 'boolean'
  },
  reserveCVEIds: {
    describe: 'Reserve CVEs ids for the security release',
    type: 'boolean'
  }
};

let yargsInstance;

export function builder(yargs) {
  yargsInstance = yargs;
  return yargs.options(securityOptions)
    .positional('issueNumber', {
      type: 'number',
      describe: 'Number of the security release issue'
    })
    .check(argv => {
      if (argv.reserveCVEIds && !argv.issueNumber) {
        throw new Error('The --reserveCVEIds flag requires an issue');
      }
      return true;
    })
    .example(
      'git node security --start',
      'Prepare a security release of Node.js')
    .example(
      'git node security 514 --reserveCVEIds',
      'Reserve CVE ids for the security release');
}

export function handler(argv) {
  if (argv.start) {
    return startSecurityRelease(argv);
  }
  if (argv.reserveCVEIds) {
    return reserveCVEIds(argv.issueNumber);
  }
  yargsInstance.showHelp();
}

async function startSecurityRelease(argv) {
  const logStream = process.stdout.isTTY ? process.stdout : process.stderr;
  const cli = new CLI(logStream);
  const release = new SecurityReleaseSteward(cli);
  return release.start();
}

async function reserveCVEIds(issueNumber) {
  const logStream = process.stdout.isTTY ? process.stdout : process.stderr;
  const cli = new CLI(logStream);
  cli.setFigureIndent(0);
  const request = new SecurityReleasereserveCVEIds(cli, issueNumber);
  return request.start();
}
