import auth from './auth.js';
import Request from './request.js';
import { LinkParser } from './links.js';

const repository = {
  owner: 'nodejs-private',
  repo: 'node-private'
};

export default class SecurityReleaseRequestCVEs {
  constructor(cli, issueNumber) {
    this.cli = cli;
    this.issueNumber = issueNumber;
  }

  async start() {
    const { cli, issueNumber } = this;
    const credentials = await auth({
      github: true
      // h1: true
    });

    const req = new Request(credentials);
    const data = await req.gql('Issue', {
      ...repository,
      id: issueNumber
    });

    if (data?.repository?.issue) {
      cli.ok('Found issue: ' + data.repository.issue.title);
    } else {
      cli.error('Could not find issue: ' + issueNumber);
    }

    const { bodyHTML } = data.repository.issue;
    const parser = new LinkParser(repository.owner, repository.repo, bodyHTML);
    const urls = parser.getHackerOneRefs();
    console.log(urls);
  }
}
