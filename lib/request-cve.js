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
      h1: true
    });

    const repository = {
      owner: 'nodejs-private',
      repo: 'node-private'
    };

    const data = await getReleaseIssue(issueNumber, { credentials, cli, repository });
    const urls = getHackerOneRefs(data, { repository, cli });
    const reports = await getReports(urls, { credentials, cli });
    console.log(reports);
  }
}

async function getReports(urls, { credentials, cli }) {
  const results = [];
  for (const url of urls) {
    try {
      const req = new Request(credentials);
      const reportId = new URLSearchParams(url).get('report_id');
      const { data } = await req.getHackerOneReport(reportId);
      const { vulnerability_information, title, created_at } = data.attributes;
      const report = {
        title,
        createdAt: created_at,
        summary: vulnerability_information,
        url
      };
      cli.info(`Found report: ${title}`);
      results.push(report);
    } catch (error) {
      cli.error(`Could not retrieve report for ${url}`, error);
    }
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
