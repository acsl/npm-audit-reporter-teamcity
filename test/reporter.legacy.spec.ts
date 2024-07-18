import { defaultConfig } from '../src/config';
import reporterFactory from '../src/legacy/reporter';

import { multipleVulnerabilities, noVulnerabilities } from './mocks/legacy';

// eslint-disable-next-line @typescript-eslint/no-var-requires
const tsm = require('teamcity-service-messages');
jest.mock('teamcity-service-messages');
const mockedTsm = jest.mocked(tsm);

describe('npm audit teamcity reporter', () => {
  beforeEach(() => {
    mockedTsm.inspectionType.mockReset();
    mockedTsm.inspection.mockReset();
  });

  test('a couple of vulnerabilities found', () => {
    reporterFactory(mockedTsm, defaultConfig, multipleVulnerabilities);
    expect(mockedTsm.inspectionType).toHaveBeenCalledTimes(1);
    expect(mockedTsm.inspection).toHaveBeenCalledTimes(9);
  });

  test('no vulnerabilities found', () => {
    reporterFactory(mockedTsm, defaultConfig, noVulnerabilities);
    expect(mockedTsm.inspectionType).not.toHaveBeenCalled();
    expect(mockedTsm.inspection).not.toHaveBeenCalled();
  });

  test('output matches snapshot with some vulnerabilities', () => {
    reporterFactory(mockedTsm, defaultConfig, multipleVulnerabilities);
    expect(mockedTsm.inspection).toHaveBeenCalledWith({
      SEVERITY: 'ERROR',
      file: 'module: webpack-dev-server',
      message: 'Missing Origin Validation',
      typeId: defaultConfig.inspectionTypeId,
    });
    expect(mockedTsm.inspection).toHaveBeenLastCalledWith({
      SEVERITY: 'WARNING',
      file: 'module: js-yaml',
      message: 'Denial of Service',
      typeId: defaultConfig.inspectionTypeId,
    });
  });
});
