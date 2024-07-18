import { defaultConfig } from '../src/config';
import { processReport } from '../src/reporter';

import { multipleVulnerabilities, noVulnerability, simpleVulnerability } from './mocks/index';

// eslint-disable-next-line @typescript-eslint/no-var-requires
const tsm = require('teamcity-service-messages');
jest.mock('teamcity-service-messages');
const mockedTsm = jest.mocked(tsm);

describe('npm audit teamcity reporter', () => {
  beforeEach(() => {
    mockedTsm.inspectionType.mockReset();
    mockedTsm.inspection.mockReset();
  });

  test('one vulnerability found', () => {
    processReport(mockedTsm, defaultConfig, simpleVulnerability);
    expect(mockedTsm.inspectionType).toHaveBeenCalledTimes(1);
    expect(mockedTsm.inspection).toHaveBeenCalledTimes(1);
  });

  test('no vulnerabilities found', () => {
    processReport(mockedTsm, defaultConfig, noVulnerability);
    expect(mockedTsm.inspectionType).not.toHaveBeenCalled();
    expect(mockedTsm.inspection).not.toHaveBeenCalled();
  });

  test('output matches snapshot with some vulnerabilities', () => {
    processReport(mockedTsm, defaultConfig, multipleVulnerabilities);
    expect(mockedTsm.inspection).toHaveBeenCalledWith({
      SEVERITY: 'ERROR',
      file: 'module: underscore',
      message: `Arbitrary Code Execution in underscore`,
      typeId: defaultConfig.inspectionTypeId,
    });
    expect(mockedTsm.inspection).toHaveBeenLastCalledWith({
      SEVERITY: 'WARNING',
      file: 'module: video.js',
      message: `Cross-site Scripting in video.js`,
      typeId: defaultConfig.inspectionTypeId,
    });
  });
});
