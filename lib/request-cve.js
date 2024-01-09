import auth from './auth.js';
import Request from './request.js';
import { LinkParser } from './links.js';

export default class SecurityReleaseRequestCVEs {
  constructor(cli, issueNumber) {
    this.cli = cli;
    this.issueNumber = issueNumber;
  }

  async start() {
    const { cli, issueNumber } = this;
    const credentials = await auth({
      github: true,
      h1: true,
      mitre: true
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
    await reserveCVEIds(reports, { cli });
  }
}

async function reserveCVEIds(reports, { cli }) {
  try {
    for (const report of reports) {
      await reserveCVEId(report, { cli });
    }
  } catch (error) {
    cli.error('Could not request CVEs', error);
    process.exit(1);
  }
}

async function reserveCVEId(report, { cli, credentials }) {
  const { id, cve_ids } = report;

  if (cve_ids?.length) {
    const proceed = await cli.prompt(
      `⚠️ The report ${id} already has CVEs assigned: ${cve_ids.join(', ')}\n` +
      'Proceed anyway?',
      { defaultAnswer: false });

    if (!proceed) {
      return;
    }
  }

  const req = new Request(credentials);
  const response = await req.mitreReserveCVEid();
  return 'TODO';
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
