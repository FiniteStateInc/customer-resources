import { describe, it, expect } from 'vitest'
import {
  generateWorkflow,
  type WizardAnswers,
  buildSetupStep,
  buildUploadStep,
  buildReportStep,
  buildGateStep,
  buildCommentStep,
  buildSbomStep,
} from './generate-workflow'

describe('buildSetupStep', () => {
  it('returns a setup step with standard secrets/vars', () => {
    const step = buildSetupStep()
    expect(step.uses).toBe('finite-state/setup@v1')
    expect(step.with!['api-token']).toBe('${{ secrets.FS_API_TOKEN }}')
    expect(step.with!['domain']).toBe('${{ vars.FS_DOMAIN }}')
    expect(step.with!['project-id']).toBe('${{ vars.FS_PROJECT_ID }}')
  })
})

describe('buildUploadStep', () => {
  it('builds SCA upload step', () => {
    const step = buildUploadStep({ scanType: 'sca' })
    expect(step.uses).toBe('finite-state/upload-scan@v1')
    expect(step.with!.type).toBe('sca')
    expect(step.with!.file).toContain('build/')
  })

  it('builds SBOM upload step with format', () => {
    const step = buildUploadStep({ scanType: 'sbom', sbomFormat: 'cdx' })
    expect(step.with!.type).toBe('sbom')
    expect(step.with!['sbom-format']).toBe('cdx')
  })

  it('builds third-party upload step with scanner type', () => {
    const step = buildUploadStep({ scanType: 'third-party', scannerType: 'grype' })
    expect(step.with!.type).toBe('third-party')
    expect(step.with!['scanner-type']).toBe('grype')
  })
})

describe('buildReportStep', () => {
  it('includes selected recipes', () => {
    const step = buildReportStep({
      recipes: ['Triage Prioritization', 'Version Comparison'],
    })
    expect(step.with!.recipe).toBe('Triage Prioritization,Version Comparison')
  })

  it('includes scoring file when provided', () => {
    const step = buildReportStep({
      recipes: ['Triage Prioritization'],
      scoringFile: '.github/fs-scoring.yaml',
    })
    expect(step.with!['scoring-file']).toBe('.github/fs-scoring.yaml')
  })

  it('includes period', () => {
    const step = buildReportStep({
      recipes: ['Triage Prioritization'],
      period: '30d',
    })
    expect(step.with!.period).toBe('30d')
  })
})

describe('buildGateStep', () => {
  it('builds delta gate', () => {
    const step = buildGateStep({ gateModes: ['delta'] })
    expect(step.with!.mode).toBe('delta')
    expect(step.with!['max-new-critical']).toBe(0)
  })

  it('builds triage-priority gate', () => {
    const step = buildGateStep({ gateModes: ['triage-priority'] })
    expect(step.with!.mode).toBe('triage-priority')
    expect(step.with!['fail-on-p0']).toBe(true)
  })

  it('combines multiple modes', () => {
    const step = buildGateStep({ gateModes: ['delta', 'triage-priority'] })
    expect(step.with!.mode).toBe('delta,triage-priority')
  })
})

describe('buildCommentStep', () => {
  it('uses triage template when triage-priority gate is active', () => {
    const step = buildCommentStep({ template: 'triage' } as Parameters<typeof buildCommentStep>[0])
    expect(step.with!.template).toBe('triage')
    expect(step.if).toBe('always()')
  })

  it('uses summary template by default', () => {
    const step = buildCommentStep({})
    expect(step.with!.template).toBe('summary')
  })
})

describe('buildSbomStep', () => {
  it('builds download-sbom step with defaults', () => {
    const step = buildSbomStep({})
    expect(step.uses).toBe('finite-state/download-sbom@v1')
    expect(step.with!.format).toBe('cyclonedx')
    expect(step.with!['include-vex']).toBe(true)
  })

  it('respects format override', () => {
    const step = buildSbomStep({ sbomExportFormat: 'spdx' })
    expect(step.with!.format).toBe('spdx')
  })
})

describe('generateWorkflow', () => {
  it('generates minimal upload-only workflow', () => {
    const yaml = generateWorkflow({
      scanType: 'sca',
      gateModes: [],
      prComments: false,
      sbomExport: false,
      recipes: [],
    })

    expect(yaml).toContain('finite-state/setup@v1')
    expect(yaml).toContain('finite-state/upload-scan@v1')
    expect(yaml).not.toContain('quality-gate')
    expect(yaml).not.toContain('pr-comment')
    expect(yaml).not.toContain('download-sbom')
  })

  it('generates full pipeline workflow', () => {
    const yaml = generateWorkflow({
      scanType: 'sca',
      gateModes: ['delta', 'triage-priority'],
      prComments: true,
      sbomExport: true,
      recipes: ['Triage Prioritization', 'Version Comparison'],
      commentTemplate: 'triage',
    })

    expect(yaml).toContain('finite-state/setup@v1')
    expect(yaml).toContain('finite-state/upload-scan@v1')
    expect(yaml).toContain('finite-state/run-report@v1')
    expect(yaml).toContain('finite-state/quality-gate@v1')
    expect(yaml).toContain('finite-state/pr-comment@v1')
    expect(yaml).toContain('finite-state/download-sbom@v1')
  })

  it('generates valid YAML', () => {
    const yaml = generateWorkflow({
      scanType: 'sca',
      gateModes: ['delta'],
      prComments: true,
      sbomExport: false,
      recipes: ['Version Comparison'],
    })

    // Should not throw
    const jsYaml = require('js-yaml')
    const parsed = jsYaml.load(yaml)
    expect(parsed.name).toBeDefined()
    expect(parsed.on).toBeDefined()
    expect(parsed.jobs).toBeDefined()
  })

  it('includes run-report when gate is active', () => {
    const yaml = generateWorkflow({
      scanType: 'sca',
      gateModes: ['threshold'],
      prComments: false,
      sbomExport: false,
      recipes: [],
    })

    // Gate requires run-report, so it should be included even if no explicit recipes
    expect(yaml).toContain('finite-state/run-report@v1')
  })

  it('adds correct trigger for PR workflows', () => {
    const yaml = generateWorkflow({
      scanType: 'sca',
      gateModes: ['delta'],
      prComments: true,
      sbomExport: false,
      recipes: ['Version Comparison'],
    })

    expect(yaml).toContain('pull_request')
  })
})
