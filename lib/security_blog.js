import fs from 'node:fs';
import path from 'node:path';
import _ from 'lodash';
import {
  PLACEHOLDERS,
  getVulnerabilitiesJSON,
  checkoutOnSecurityReleaseBranch,
  NEXT_SECURITY_RELEASE_REPOSITORY,
  validateDate,
  getSummary,
  commitAndPushVulnerabilitiesJSON,
  NEXT_SECURITY_RELEASE_FOLDER
} from './security-release/security-release.js';
import auth from './auth.js';
import Request from './request.js';

const kChanged = Symbol('changed');

export default class SecurityBlog {
  repository = NEXT_SECURITY_RELEASE_REPOSITORY;
  req;
  constructor(cli) {
    this.cli = cli;
  }

  async createPreRelease() {
    const { cli } = this;

    // checkout on security release branch
    checkoutOnSecurityReleaseBranch(cli, this.repository);

    // read vulnerabilities JSON file
    const content = getVulnerabilitiesJSON(cli);
    // validate the release date read from vulnerabilities JSON
    if (!content.releaseDate) {
      cli.error('Release date is not set in vulnerabilities.json,' +
        ' run `git node security --update-date=YYYY/MM/DD` to set the release date.');
      process.exit(1);
    }

    validateDate(content.releaseDate);
    const releaseDate = new Date(content.releaseDate);

    const template = this.getSecurityPreReleaseTemplate();
    const data = {
      annoucementDate: await this.getAnnouncementDate(cli),
      releaseDate: this.formatReleaseDate(releaseDate),
      affectedVersions: this.getAffectedVersions(content),
      vulnerabilities: this.getVulnerabilities(content),
      slug: this.getSlug(releaseDate),
      impact: this.getImpact(content)
    };
    const month = releaseDate.toLocaleString('en-US', { month: 'long' }).toLowerCase();
    const year = releaseDate.getFullYear();
    const fileName = `${month}-${year}-security-releases.md`;
    const preRelease = this.buildPreRelease(template, data);
    const file = path.join(process.cwd(), fileName);
    fs.writeFileSync(file, preRelease);
    cli.ok(`Pre-release announcement file created at ${file}`);
  }

  async createPostRelease() {
    const { cli } = this;
    const credentials = await auth({
      github: true,
      h1: true
    });

    this.req = new Request(credentials);

    // checkout on security release branch
    checkoutOnSecurityReleaseBranch(cli, this.repository);

    // read vulnerabilities JSON file
    const content = getVulnerabilitiesJSON(cli);
    if (!content.releaseDate) {
      cli.error('Release date is not set in vulnerabilities.json,' +
        ' run `git node security --update-date=YYYY/MM/DD` to set the release date.');
      process.exit(1);
    }

    validateDate(content.releaseDate);
    const releaseDate = new Date(content.releaseDate);
    const template = this.getSecurityPostReleaseTemplate();
    const data = {
      annoucementDate: await this.getAnnouncementDate(cli),
      releaseDate: this.formatReleaseDate(releaseDate),
      affectedVersions: this.getAffectedVersions(content),
      vulnerabilities: this.getVulnerabilities(content),
      slug: this.getSlug(releaseDate),
      author: await this.promptAuthor(cli),
      dependencyUpdates: content.dependencies
    };
    const postReleaseContent = await this.buildPostRelease(template, data, content);

    const pathPreRelease = await this.promptExistingPreRelease(cli);
    // read the existing pre-release announcement
    let preReleaseContent = fs.readFileSync(pathPreRelease, 'utf-8');
    // cut the part before summary
    const preSummary = preReleaseContent.indexOf('# Summary');
    if (preSummary !== -1) {
      preReleaseContent = preReleaseContent.substring(preSummary);
    }

    const updatedContent = postReleaseContent + preReleaseContent;

    fs.writeFileSync(pathPreRelease, updatedContent);
    cli.ok(`Post-release announcement file updated at ${pathPreRelease}`);

    // if the vulnerabilities.json has been changed, update the file
    if (!content[kChanged]) return;
    this.updateVulnerabilitiesJSON(content);
  }

  updateVulnerabilitiesJSON(content) {
    try {
      this.cli.info('Updating vulnerabilities.json');
      const vulnerabilitiesJSONPath = path.join(process.cwd(),
        NEXT_SECURITY_RELEASE_FOLDER, 'vulnerabilities.json');
      fs.writeFileSync(vulnerabilitiesJSONPath, JSON.stringify(content, null, 2));
      const commitMessage = 'chore: updated vulnerabilities.json';
      commitAndPushVulnerabilitiesJSON(vulnerabilitiesJSONPath,
        commitMessage,
        { cli: this.cli, repository: this.repository });
    } catch (error) {
      this.cli.error('Error updating vulnerabilities.json');
      this.cli.error(error);
    }
  }

  async promptExistingPreRelease(cli) {
    const pathPreRelease = await cli.prompt(
      'Please provide the path of the existing pre-release announcement:', {
        questionType: 'input',
        defaultAnswer: ''
      });

    if (!pathPreRelease || !fs.existsSync(path.resolve(pathPreRelease))) {
      return this.promptExistingPreRelease(cli);
    }
    return pathPreRelease;
  }

  promptAuthor(cli) {
    return cli.prompt('Who is the author of this security release? If multiple' +
      ' use & as separator', {
      questionType: 'input',
      defaultAnswer: PLACEHOLDERS.author
    });
  }

  formatReleaseDate(releaseDate) {
    const options = {
      weekday: 'long',
      month: 'long',
      day: 'numeric',
      year: 'numeric'
    };
    return releaseDate.toLocaleDateString('en-US', options);
  }

  buildPreRelease(template, data) {
    const {
      annoucementDate,
      releaseDate,
      affectedVersions,
      vulnerabilities,
      slug,
      impact
    } = data;
    return template.replaceAll(PLACEHOLDERS.annoucementDate, annoucementDate)
      .replaceAll(PLACEHOLDERS.slug, slug)
      .replaceAll(PLACEHOLDERS.affectedVersions, affectedVersions)
      .replaceAll(PLACEHOLDERS.vulnerabilities, vulnerabilities)
      .replaceAll(PLACEHOLDERS.releaseDate, releaseDate)
      .replaceAll(PLACEHOLDERS.impact, impact);
  }

  async buildPostRelease(template, data, content) {
    const {
      annoucementDate,
      releaseDate,
      affectedVersions,
      vulnerabilities,
      slug,
      impact,
      author,
      dependencyUpdates
    } = data;
    return template.replaceAll(PLACEHOLDERS.annoucementDate, annoucementDate)
      .replaceAll(PLACEHOLDERS.slug, slug)
      .replaceAll(PLACEHOLDERS.affectedVersions, affectedVersions)
      .replaceAll(PLACEHOLDERS.vulnerabilities, vulnerabilities)
      .replaceAll(PLACEHOLDERS.releaseDate, releaseDate)
      .replaceAll(PLACEHOLDERS.impact, impact)
      .replaceAll(PLACEHOLDERS.author, author)
      .replaceAll(PLACEHOLDERS.reports, await this.getReportsTemplate(content))
      .replaceAll(PLACEHOLDERS.dependencyUpdates,
        this.getDependencyUpdatesTemplate(dependencyUpdates))
      .replaceAll(PLACEHOLDERS.downloads, this.getDownloadsTemplate());
  }

  async getReportsTemplate(content) {
    const reports = content.reports;
    let template = '';
    for (const report of reports) {
      let cveId = report.cve_ids?.join(', ');
      if (!cveId) {
        // ask for the CVE ID
        // it should have been created with the step `--request-cve`
        cveId = await this.cli.prompt(`What is the CVE ID for vulnerability https://hackerone.com/reports/${report.id} ${report.title}?`, {
          questionType: 'input',
          defaultAnswer: 'TBD'
        });
        report.cve_ids = [cveId];
        content[kChanged] = true;
      }
      template += `## ${report.title} (${cveId}) - (${report.severity.rating})\n\n`;
      if (!report.summary) {
        const fetchIt = await this.cli.prompt(`Summary missing for vulnerability https://hackerone.com/reports/${report.id} ${report.title}.\
 Do you want to try fetch it from HackerOne??`, {
          questionType: 'confirm',
          defaultAnswer: true
        });

        if (fetchIt) {
          report.summary = await getSummary(report.id, this.req);
          content[kChanged] = true;
        }

        if (!report.summary) {
          this.cli.error(`Summary missing for vulnerability https://hackerone.com/reports/${report.id} ${report.title}. Please create it before continuing.`);
          process.exit(1);
        }
      }
      template += `${report.summary}\n\n`;
      const releaseLines = report.affectedVersions.join(', ');
      template += `Impact:\n\n- This vulnerability affects all users\
 in active release lines: ${releaseLines}\n\n`;
      if (!report.patchAuthors) {
        const author = await this.cli.prompt(`Who fixed vulnerability https://hackerone.com/reports/${report.id} ${report.title}? If multiple use & as separator`, {
          questionType: 'input',
          defaultAnswer: 'TBD'
        });
        report.patchAuthors = author.split('&').map((p) => p.trim());
        content[kChanged] = true;
      }
      template += `Thank you, to ${report.reporter} for reporting this vulnerability\
 and thank you ${report.patchAuthors.join(' and ')} for fixing it.\n\n`;
    }
    return template;
  }

  getDependencyUpdatesTemplate(dependencyUpdates) {
    if (!dependencyUpdates) return '';
    let template = 'This security release includes the following dependency' +
      ' updates to address public vulnerabilities:\n\n';
    for (const dependencyUpdate of Object.values(dependencyUpdates)) {
      for (const dependency of dependencyUpdate) {
        const title = dependency.title.substring(dependency.title.indexOf(':') + ':'.length).trim();
        template += `- ${title}\
 on ${dependency.affectedVersions.join(', ')}\n`;
      }
    }
    return template;
  }

  getDownloadsTemplate() {
    return '';
  }

  getSlug(releaseDate) {
    const month = releaseDate.toLocaleString('en-US', { month: 'long' });
    const year = releaseDate.getFullYear();
    return `${month.toLocaleLowerCase()}-${year}-security-releases`;
  }

  async getAnnouncementDate(cli) {
    try {
      const date = await this.promptAnnouncementDate(cli);
      validateDate(date);
      return new Date(date).toISOString();
    } catch (error) {
      return PLACEHOLDERS.annoucementDate;
    }
  }

  promptAnnouncementDate(cli) {
    const today = new Date().toISOString().substring(0, 10).replace(/-/g, '/');
    return cli.prompt('When is the security release going to be announced? ' +
      'Enter in YYYY/MM/DD format:', {
      questionType: 'input',
      defaultAnswer: today
    });
  }

  getImpact(content) {
    const impact = content.reports.reduce((acc, report) => {
      for (const affectedVersion of report.affectedVersions) {
        if (acc[affectedVersion]) {
          acc[affectedVersion].push(report);
        } else {
          acc[affectedVersion] = [report];
        }
      }
      return acc;
    }, {});

    const impactText = [];
    for (const [key, value] of Object.entries(impact)) {
      const groupedByRating = Object.values(_.groupBy(value, 'severity.rating'))
        .map(severity => {
          if (!severity[0]?.severity?.rating) {
            this.cli.error(`severity.rating not found for the report ${severity[0].id}. \
              Please add it manually before continuing.`);
            process.exit(1);
          }
          const firstSeverityRating = severity[0].severity.rating.toLocaleLowerCase();
          return `${severity.length} ${firstSeverityRating} severity issues`;
        }).join(', ');

      impactText.push(`The ${key} release line of Node.js is vulnerable to ${groupedByRating}.`);
    }

    return impactText.join('\n');
  }

  getVulnerabilities(content) {
    const grouped = _.groupBy(content.reports, 'severity.rating');
    const text = [];
    for (const [key, value] of Object.entries(grouped)) {
      text.push(`- ${value.length} ${key.toLocaleLowerCase()} severity issues.`);
    }
    return text.join('\n');
  }

  getAffectedVersions(content) {
    const affectedVersions = new Set();
    for (const report of Object.values(content.reports)) {
      for (const affectedVersion of report.affectedVersions) {
        affectedVersions.add(affectedVersion);
      }
    }
    return Array.from(affectedVersions).join(', ');
  }

  getSecurityPreReleaseTemplate() {
    return fs.readFileSync(
      new URL(
        './github/templates/security-pre-release.md',
        import.meta.url
      ),
      'utf-8'
    );
  }

  getSecurityPostReleaseTemplate() {
    return fs.readFileSync(
      new URL(
        './github/templates/security-post-release.md',
        import.meta.url
      ),
      'utf-8'
    );
  }
}
