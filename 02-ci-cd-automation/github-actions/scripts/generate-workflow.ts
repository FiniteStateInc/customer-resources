#!/usr/bin/env node

import * as yaml from 'js-yaml'

// --- Types ---

export interface WizardAnswers {
  scanType: 'sca' | 'sast' | 'sbom' | 'third-party' | 'vulnerability-analysis'
  sbomFormat?: 'cdx' | 'spdx'
  scannerType?: string
  gateModes: Array<'delta' | 'threshold' | 'triage-priority'>
  prComments: boolean
  commentTemplate?: 'summary' | 'triage' | 'comparison' | 'detailed'
  sbomExport: boolean
  sbomExportFormat?: 'cyclonedx' | 'spdx'
  recipes: string[]
  scoringFile?: string
  period?: string
}

interface WorkflowStep {
  name?: string
  uses?: string
  id?: string
  if?: string
  with?: Record<string, unknown>
  run?: string
}

interface Workflow {
  name: string
  on: Record<string, unknown>
  permissions: Record<string, string>
  jobs: Record<string, {
    name: string
    'runs-on': string
    steps: WorkflowStep[]
  }>
}

// --- Step Builders ---

export function buildSetupStep(): WorkflowStep {
  return {
    name: 'Authenticate with Finite State',
    uses: 'finite-state/setup@v1',
    id: 'fs',
    with: {
      'api-token': '${{ secrets.FS_API_TOKEN }}',
      domain: '${{ vars.FS_DOMAIN }}',
      'project-id': '${{ vars.FS_PROJECT_ID }}',
    },
  }
}

export function buildUploadStep(answers: Partial<WizardAnswers>): WorkflowStep {
  const step: WorkflowStep = {
    name: 'Upload for analysis',
    uses: 'finite-state/upload-scan@v1',
    id: 'upload',
    with: {
      type: answers.scanType || 'sca',
      file: answers.scanType === 'sbom'
        ? 'build/sbom.json'
        : answers.scanType === 'third-party'
          ? 'scan-results.json'
          : 'build/firmware.bin',
      version: 'pr-${{ github.event.number }}',
    },
  }

  if (answers.scanType === 'sbom' && answers.sbomFormat) {
    step.with!['sbom-format'] = answers.sbomFormat
  }
  if (answers.scanType === 'third-party' && answers.scannerType) {
    step.with!['scanner-type'] = answers.scannerType
  }

  return step
}

export function buildReportStep(answers: Partial<WizardAnswers>): WorkflowStep {
  const recipes = answers.recipes?.length
    ? answers.recipes
    : ['Triage Prioritization']

  const step: WorkflowStep = {
    name: 'Run security reports',
    uses: 'finite-state/run-report@v1',
    id: 'report',
    with: {
      recipe: recipes.join(','),
    },
  }

  if (answers.period) {
    step.with!.period = answers.period
  } else {
    step.with!.period = '30d'
  }

  if (answers.scoringFile) {
    step.with!['scoring-file'] = answers.scoringFile
  }

  return step
}

export function buildGateStep(answers: Partial<WizardAnswers>): WorkflowStep {
  const modes = answers.gateModes || ['delta']

  const step: WorkflowStep = {
    name: 'Quality gate',
    uses: 'finite-state/quality-gate@v1',
    id: 'gate',
    with: {
      mode: modes.join(','),
      'report-dir': '${{ steps.report.outputs.report-dir }}',
    },
  }

  if (modes.includes('delta')) {
    step.with!['max-new-critical'] = 0
    step.with!['max-new-high'] = 0
  }

  if (modes.includes('threshold')) {
    step.with!['max-critical'] = 0
    step.with!['max-high'] = 20
  }

  if (modes.includes('triage-priority')) {
    step.with!['fail-on-p0'] = true
    step.with!['fail-on-p1'] = false
  }

  return step
}

export function buildCommentStep(answers: Partial<WizardAnswers> & { template?: string }): WorkflowStep {
  return {
    name: 'Post PR comment',
    uses: 'finite-state/pr-comment@v1',
    if: 'always()',
    with: {
      template: answers.commentTemplate || answers.template || 'summary',
      'gate-result': '${{ steps.gate.outputs.result }}',
      'gate-summary': '${{ steps.gate.outputs.summary }}',
      'report-dir': '${{ steps.report.outputs.report-dir }}',
    },
  }
}

export function buildSbomStep(answers: Partial<WizardAnswers>): WorkflowStep {
  return {
    name: 'Export SBOM',
    uses: 'finite-state/download-sbom@v1',
    with: {
      'version-id': '${{ steps.upload.outputs.version-id }}',
      format: answers.sbomExportFormat || 'cyclonedx',
      'include-vex': true,
    },
  }
}

// --- Workflow Generator ---

export function generateWorkflow(answers: WizardAnswers): string {
  const steps: WorkflowStep[] = []

  // Always start with checkout + setup
  steps.push({ uses: 'actions/checkout@v4' })
  steps.push(buildSetupStep())

  // Upload
  steps.push(buildUploadStep(answers))

  // Reports (required if gate or comments are active)
  const needsReport = answers.gateModes.length > 0 || answers.prComments
  if (needsReport || answers.recipes.length > 0) {
    // Ensure appropriate recipes for the gate modes
    const recipes = new Set(answers.recipes || [])
    if (answers.gateModes.includes('delta')) {
      recipes.add('Version Comparison')
    }
    if (answers.gateModes.includes('triage-priority')) {
      recipes.add('Triage Prioritization')
    }
    if (recipes.size === 0) {
      recipes.add('Triage Prioritization')
    }

    steps.push(buildReportStep({
      ...answers,
      recipes: Array.from(recipes),
    }))
  }

  // Quality gate
  if (answers.gateModes.length > 0) {
    steps.push(buildGateStep(answers))
  }

  // PR comment
  if (answers.prComments) {
    steps.push(buildCommentStep(answers))
  }

  // SBOM export
  if (answers.sbomExport) {
    steps.push(buildSbomStep(answers))
  }

  // Build the workflow object
  const hasPrTrigger = answers.prComments || answers.gateModes.length > 0
  const workflow: Workflow = {
    name: 'Finite State Security',
    on: hasPrTrigger
      ? { pull_request: { branches: ['main'] } }
      : { push: { branches: ['main'] } },
    permissions: {
      contents: 'read',
      ...(answers.prComments ? { 'pull-requests': 'write' } : {}),
    },
    jobs: {
      security: {
        name: 'Security Analysis',
        'runs-on': 'ubuntu-latest',
        steps,
      },
    },
  }

  // Generate YAML with header comment
  const header = [
    '# Generated by: npx finite-state-actions init',
    '# See https://github.com/FiniteStateInc/customer-resources/tree/main/github-actions',
    '#',
    '# Prerequisites:',
    '#   - Secret: FS_API_TOKEN (Finite State API token)',
    '#   - Variable: FS_DOMAIN (e.g., app.finitestate.io)',
    '#   - Variable: FS_PROJECT_ID (your project ID)',
    '',
  ].join('\n')

  return header + yaml.dump(workflow, {
    lineWidth: 120,
    noRefs: true,
    quotingType: '"',
    forceQuotes: false,
  })
}

// --- Interactive CLI ---

async function runWizard(): Promise<void> {
  // Dynamic import for inquirer (only needed in interactive mode)
  const { select, checkbox, confirm, input } = await import('@inquirer/prompts')

  console.log('\n  Finite State GitHub Actions — Workflow Generator\n')

  const scanType = await select({
    message: 'What do you want to scan?',
    choices: [
      { value: 'sca', name: 'Binary (SCA)' },
      { value: 'vulnerability-analysis', name: 'Binary (reachability analysis)' },
      { value: 'sbom', name: 'SBOM file' },
      { value: 'third-party', name: 'Third-party scanner results' },
    ],
  }) as WizardAnswers['scanType']

  let sbomFormat: 'cdx' | 'spdx' | undefined
  if (scanType === 'sbom') {
    sbomFormat = await select({
      message: 'SBOM format?',
      choices: [
        { value: 'cdx', name: 'CycloneDX' },
        { value: 'spdx', name: 'SPDX' },
      ],
    }) as 'cdx' | 'spdx'
  }

  let scannerType: string | undefined
  if (scanType === 'third-party') {
    scannerType = await input({
      message: 'Scanner type (e.g., grype, trivy, snyk):',
    })
  }

  const gateModes = await checkbox({
    message: 'Which quality gates do you want?',
    choices: [
      { value: 'delta', name: 'Delta — block new critical/high findings' },
      { value: 'triage-priority', name: 'Triage Priority — block P0/P1 exploitable findings' },
      { value: 'threshold', name: 'Threshold — absolute finding count limits' },
    ],
  }) as WizardAnswers['gateModes']

  const prComments = await confirm({
    message: 'Post findings summary as a PR comment?',
    default: true,
  })

  let commentTemplate: WizardAnswers['commentTemplate']
  if (prComments) {
    commentTemplate = await select({
      message: 'Comment template?',
      choices: [
        { value: 'triage', name: 'Triage — priority band summary' },
        { value: 'summary', name: 'Summary — compact severity overview' },
        { value: 'comparison', name: 'Comparison — version delta table' },
        { value: 'detailed', name: 'Detailed — full findings table' },
      ],
    }) as WizardAnswers['commentTemplate']
  }

  const sbomExport = await confirm({
    message: 'Export SBOM as workflow artifact?',
    default: false,
  })

  // Build answers
  const answers: WizardAnswers = {
    scanType,
    sbomFormat,
    scannerType,
    gateModes,
    prComments,
    commentTemplate,
    sbomExport,
    recipes: [],
    period: '30d',
  }

  // Generate and output
  const workflowYaml = generateWorkflow(answers)

  console.log('\n--- Generated workflow ---\n')
  console.log(workflowYaml)
  console.log('---\n')

  const save = await confirm({
    message: 'Save to .github/workflows/finite-state.yml?',
    default: true,
  })

  if (save) {
    const fs = await import('fs')
    const path = await import('path')
    const dir = path.join(process.cwd(), '.github', 'workflows')
    fs.mkdirSync(dir, { recursive: true })
    fs.writeFileSync(path.join(dir, 'finite-state.yml'), workflowYaml)
    console.log('\n  Saved to .github/workflows/finite-state.yml')
    console.log('\n  Next steps:')
    console.log('    1. Add FS_API_TOKEN as a repository secret')
    console.log('    2. Add FS_DOMAIN and FS_PROJECT_ID as repository variables')
    console.log('    3. Update the file path in the upload-scan step')
    console.log('    4. Commit and push\n')
  }
}

// Run if invoked directly
const isMainModule = typeof require !== 'undefined' && require.main === module
if (isMainModule) {
  runWizard().catch((err) => {
    console.error('Error:', err.message)
    process.exit(1)
  })
}
