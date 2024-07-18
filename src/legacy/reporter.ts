import { API } from 'teamcity-service-messages';
import { IConfig } from '../config';
import { debug } from '../util';
import { IAuditLegacyMetadata, IAuditLegacyOutput } from './model';

function isVulnerable(auditMetadata: IAuditLegacyMetadata) {
  return (
    auditMetadata.vulnerabilities.info +
      auditMetadata.vulnerabilities.low +
      auditMetadata.vulnerabilities.moderate +
      auditMetadata.vulnerabilities.high +
      auditMetadata.vulnerabilities.critical >
    0
  );
}

export function legacyReporter(
  tsm: API<true>,
  { inspectionTypeId, inspectionName, inspectionCategory }: IConfig,
  auditResult: IAuditLegacyOutput,
) {
  if (isVulnerable(auditResult.metadata)) {
    tsm.inspectionType({
      category: inspectionCategory,
      description: 'https://docs.npmjs.com/cli/audit.html',
      id: inspectionTypeId,
      name: inspectionName,
    });

    Object.keys(auditResult.advisories).forEach((advisoryId) => {
      const advisoryElement = auditResult.advisories[advisoryId];
      debug('current element:', advisoryElement);
      const severity = ['high', 'critical'].indexOf(advisoryElement.severity) >= 0 ? 'ERROR' : 'WARNING';

      tsm.inspection({
        SEVERITY: severity,
        file: `module: ${advisoryElement.module_name}`,
        message: `${advisoryElement.title}`,
        typeId: inspectionTypeId,
      });
    });
  }
}

export default legacyReporter;
