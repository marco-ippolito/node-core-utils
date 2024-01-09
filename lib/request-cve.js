import auth from './auth.js';
import Request from './request.js';
import { LinkParser } from './links.js';
import fs from 'node:fs/promises';
import { join } from 'node:path';

export default class SecurityReleaseRequestCVEs {
  constructor(cli, issueNumber) {
    this.cli = cli;
    this.issueNumber = issueNumber;
  }

  async start() {
    const { cli, issueNumber } = this;
    const credentials = await auth({
      github: true,
      h1: true
    });

    const repository = {
      owner: 'nodejs-private',
      repo: 'node-private'
    };

    const data = await getReleaseIssue(issueNumber, { credentials, cli, repository });
    const urls = getHackerOneRefs(data, { repository, cli });
    await cli.startSpinner('Retrieving HackerOne reports');
    const reports = await getReports(urls, { credentials, cli });
    await cli.stopSpinner(`Retrieved ${reports.length} HackerOne reports`);
    await requestCVEs(reports, { credentials, cli });
  }
}

async function requestCVEs(reports, { cli }) {
  try {
    const tmpDir = await fs.mkdtemp(`nodejs-cve-requests-${Date.now()}`);
    for (const report of reports) {
      await requestCVE(report, tmpDir, { cli });
    }
    await fs.rmdir(tmpDir);
  } catch (error) {
    cli.error('Could not request CVEs', error);
    process.exit(1);
  }
}

async function requestCVE(report, dir, { cli }) {
  const { id, cve_ids } = report;
  try {
    const filename = `cve-request-${id}.json`;
    const filePath = join(dir, filename);
    cli.info(`Please verify the contents of ${filename} and edit if necessary`);
    if (cve_ids?.length) {
      cli.warn(`The report ${id} already has CVEs assigned: ${cve_ids.join(', ')}`);
    }
    await fs.writeFile(filePath, JSON.stringify(report, null, 2));

    const create = await cli.prompt(
      `Request CVE for report ${id}?`,
      { defaultAnswer: true, noSeparator: true });

    if (!create) {
      cli.error(`Request for report ${id} skipped`);
      await fs.rm(filePath);
      return;
    }

    const redactedFile = JSON.parse(await fs.readFile(filePath, 'utf8'));
    await fs.rm(filePath);
  } catch (error) {
    cli.error(`Could not request CVE for report ${id}`, error);
  }
}

async function getReports(urls, { credentials, cli }) {
  const results = [];
  for (const url of urls) {
    try {
      const req = new Request(credentials);
      const reportId = new URLSearchParams(url).get('report_id');
      const { data } = await req.getHackerOneReport(reportId);
      const { id } = data;
      const { vulnerability_information, title, created_at, cve_ids } = data.attributes;
      const report = {
        id,
        title,
        createdAt: created_at,
        summary: vulnerability_information,
        url,
        cve_ids
      };
      cli.updateSpinner(`Retrieved report: ${title}`);
      results.push(report);
    } catch (error) {
      cli.error(`Could not retrieve report for ${url}`, error);
    }
  }

  if (!results.length) {
    cli.error('Could not find any Hackerone reports');
    process.exit(1);
  }
  return results;
}

function getHackerOneRefs(data, { repository, cli }) {
  const { bodyHTML } = data.repository.issue;
  const parser = new LinkParser(repository.owner, repository.repo, bodyHTML);
  const results = parser.getHackerOneRefs();

  if (results?.length) {
    cli.ok(`Found ${results.length} HackerOne references`);
  } else {
    cli.error('Could not find any HackerOne references');
    process.exit(1);
  }

  return results;
}

async function getReleaseIssue(issueNumber, { credentials, cli, repository }) {
  const req = new Request(credentials);
  const data = await req.gql('Issue', {
    ...repository,
    id: issueNumber
  });

  if (data?.repository?.issue) {
    cli.ok('Found issue: ' + data.repository.issue.title);
  } else {
    cli.error('Could not find issue: ' + issueNumber);
    process.exit(1);
  }

  return data;
}
