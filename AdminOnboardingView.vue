<script setup>
import { computed, onMounted, ref, watch } from 'vue'

import { api } from '../services/api.js'

const step = ref(1)
const previewTab = ref('bundle')
const copied = ref(false)

const targets = ref({
  ssh_targets: [],
  database_targets: [],
})
const targetsLoading = ref(false)
const targetsError = ref('')

const actions = ref([])
const actionsLoading = ref(false)
const actionsError = ref('')

const assistantLoading = ref(false)
const assistantError = ref('')
const assistantMessage = ref('')
const assistantMissing = ref([])
const assistantIssues = ref([])
const assistantReady = ref(false)
const hasDraft = ref(false)

const activationConfirmed = ref(false)
const activationLoading = ref(false)
const activationError = ref('')
const activationResult = ref(null)

let applyingDraft = false

const review = ref({
  summary: '',
  sop_review_points: [],
  action_review_points: [],
  activation_requirements: [],
})

const form = ref({
  dagId: '',
  exceptionTypes: '',
  monitoringDescription: '',
  investigationLogic: '',
  investigationSop: '',

  targetMode: 'EXISTING',
  targetId: '',
  targetDisplayName: '',
  hostname: '',
  sshPort: 22,
  databasePort: 3306,
  databaseName: '',

  verifierCredentialName: '',
  verifierUsername: '',
  verifierPassword: '',

  executorCredentialName: '',
  executorUsername: '',
  executorPassword: '',

  databaseCredentialName: '',
  databaseUsername: '',
  databasePassword: '',

  operatingMode: 'INVESTIGATE_ONLY',
  selectedActionId: '',
})

const steps = [
  {
    number: 1,
    label: 'DAG and SOP',
  },
  {
    number: 2,
    label: 'Target',
  },
  {
    number: 3,
    label: 'Operating mode',
  },
  {
    number: 4,
    label: 'Review and activate',
  },
]

const targetModes = [
  {
    value: 'EXISTING',
    label: 'Existing SSH',
    description: 'Use an enabled registered SSH target.',
  },
  {
    value: 'EXISTING_DATABASE',
    label: 'Existing database',
    description: 'Use an enabled read-only database target.',
  },
  {
    value: 'NEW',
    label: 'New SSH',
    description: 'Validate and register a new SSH server.',
  },
  {
    value: 'NEW_DATABASE',
    label: 'New database',
    description: 'Validate and register a read-only database.',
  },
]

const sshTargets = computed(
  () => targets.value.ssh_targets || [],
)

const databaseTargets = computed(
  () => targets.value.database_targets || [],
)

const isDatabase = computed(() =>
  [
    'EXISTING_DATABASE',
    'NEW_DATABASE',
  ].includes(form.value.targetMode),
)

const isNewTarget = computed(() =>
  [
    'NEW',
    'NEW_DATABASE',
  ].includes(form.value.targetMode),
)

const selectedAction = computed(() =>
  actions.value.find(
    (item) =>
      item.action_id ===
      form.value.selectedActionId,
  ) || null,
)

function splitValues(value) {
  return String(value || '')
    .split(/\r?\n|,/)
    .map((item) => item.trim())
    .filter(Boolean)
}

function validPort(value, fallback) {
  const parsed = Number.parseInt(value, 10)

  if (
    Number.isInteger(parsed) &&
    parsed >= 1 &&
    parsed <= 65535
  ) {
    return parsed
  }

  return fallback
}

function generatedCredentialName(role) {
  const target =
    form.value.targetId
      .trim()
      .toLowerCase()
      .replace(/[^a-z0-9_.-]+/g, '_') ||
    'new_target'

  return `${target}_${role}`
}

function credentialName(value, role) {
  return (
    value.trim() ||
    generatedCredentialName(role)
  )
}

const targetRegistration = computed(() => {
  if (form.value.targetMode === 'EXISTING') {
    return {
      mode: 'EXISTING',
      target_id: form.value.targetId.trim(),
    }
  }

  if (
    form.value.targetMode ===
    'EXISTING_DATABASE'
  ) {
    return {
      mode: 'EXISTING_DATABASE',
      database_target_id:
        form.value.targetId.trim(),
    }
  }

  if (
    form.value.targetMode ===
    'NEW_DATABASE'
  ) {
    return {
      mode: 'NEW_DATABASE',

      target: {
        database_target_id:
          form.value.targetId.trim(),

        display_name:
          form.value.targetDisplayName.trim(),

        hostname:
          form.value.hostname.trim(),

        database_port: validPort(
          form.value.databasePort,
          3306,
        ),

        database_name:
          form.value.databaseName.trim(),

        read_only_required: true,
        enabled: false,
      },

      credential: {
        credential_name: credentialName(
          form.value.databaseCredentialName,
          'database_read_only',
        ),

        credential_type:
          'DATABASE_PASSWORD',

        purpose:
          'DATABASE_READ_ONLY',

        username:
          form.value.databaseUsername.trim(),

        secret_required: true,
      },
    }
  }

  return {
    mode: 'NEW',

    target: {
      target_id:
        form.value.targetId.trim(),

      display_name:
        form.value.targetDisplayName.trim(),

      hostname:
        form.value.hostname.trim(),

      ssh_port: validPort(
        form.value.sshPort,
        22,
      ),

      ssh_host_key_policy:
        'DISCOVER_AND_PIN_ON_ACTIVATION',

      enabled: false,
    },

    credential_plan: {
      verifier: {
        credential_name: credentialName(
          form.value.verifierCredentialName,
          'verifier',
        ),

        credential_type:
          'SSH_PASSWORD',

        purpose:
          'VERIFIER_READ_ONLY',

        username:
          form.value.verifierUsername.trim(),

        secret_required: true,
      },

      executor:
        form.value.operatingMode ===
        'APPROVAL_REQUIRED_ACTION'
          ? {
              credential_name:
                credentialName(
                  form.value.executorCredentialName,
                  'executor',
                ),

              credential_type:
                'SSH_PASSWORD',

              purpose:
                'EXECUTOR_REMEDIATION',

              username:
                form.value.executorUsername.trim(),

              secret_required: true,
            }
          : null,
    },
  }
})

const selectedActionId = computed(() => {
  if (
    form.value.operatingMode !==
    'APPROVAL_REQUIRED_ACTION'
  ) {
    return null
  }

  return (
    form.value.selectedActionId ||
    null
  )
})

const structuredInput = computed(() => ({
  dag_id:
    form.value.dagId.trim(),

  exception_types:
    splitValues(
      form.value.exceptionTypes,
    ),

  monitoring_description:
    form.value.monitoringDescription.trim(),

  operating_mode:
    form.value.operatingMode,

  target_registration:
    targetRegistration.value,

  investigation_logic:
    form.value.investigationLogic.trim(),

  selected_action_id:
    selectedActionId.value,
}))

const bundle = computed(() => ({
  schema_version: 1,
  lifecycle_status: 'DRAFT',

  operating_mode:
    form.value.operatingMode,

  dag: {
    dag_id:
      form.value.dagId.trim(),

    exception_types:
      splitValues(
        form.value.exceptionTypes,
      ),

    investigation_sop:
      form.value.investigationSop.trim(),
  },

  target_registration:
    targetRegistration.value,

  selected_action_id:
    selectedActionId.value,

  review_template:
    review.value,
}))

const assistantRequest = computed(() => ({
  message:
    'Generate the onboarding draft from the structured form.',

  conversation: [],

  current_draft:
    hasDraft.value
      ? bundle.value
      : null,

  structured_input:
    structuredInput.value,
}))

const credentials = computed(() => {
  if (!isNewTarget.value) {
    return {
      credential_kind: 'NONE',
    }
  }

  if (
    form.value.targetMode ===
    'NEW_DATABASE'
  ) {
    return {
      credential_kind:
        'DATABASE_PASSWORD',

      password:
        form.value.databasePassword,
    }
  }

  return {
    credential_kind:
      'SSH_PASSWORDS',

    verifier_password:
      form.value.verifierPassword,

    executor_password:
      form.value.operatingMode ===
      'APPROVAL_REQUIRED_ACTION'
        ? form.value.executorPassword
        : null,
  }
})

const activationRequest = computed(() => ({
  draft:
    bundle.value,

  credentials:
    credentials.value,

  confirmation:
    'ACTIVATE',
}))

const redactedActivationRequest = computed(
  () => {
    const redactedCredentials = {
      credential_kind:
        credentials.value.credential_kind,
    }

    if (
      credentials.value.credential_kind ===
      'DATABASE_PASSWORD'
    ) {
      redactedCredentials.password =
        '[REDACTED]'
    }

    if (
      credentials.value.credential_kind ===
      'SSH_PASSWORDS'
    ) {
      redactedCredentials.verifier_password =
        '[REDACTED]'

      redactedCredentials.executor_password =
        credentials.value.executor_password
          ? '[REDACTED]'
          : null
    }

    return {
      draft:
        bundle.value,

      credentials:
        redactedCredentials,

      confirmation:
        'ACTIVATE',
    }
  },
)

const formIssues = computed(() => {
  const issues = []

  if (!form.value.dagId.trim()) {
    issues.push(
      'Enter the DAG ID.',
    )
  }

  if (
    !splitValues(
      form.value.exceptionTypes,
    ).length
  ) {
    issues.push(
      'Enter at least one exception type.',
    )
  }

  if (
    !form.value.monitoringDescription.trim()
  ) {
    issues.push(
      'Describe what the DAG monitors.',
    )
  }

  if (
    !form.value.investigationLogic.trim()
  ) {
    issues.push(
      'Enter the investigation logic and exact diagnostic operations.',
    )
  }

  if (!form.value.targetId.trim()) {
    issues.push(
      'Select or enter a target.',
    )
  }

  if (
    form.value.targetMode === 'NEW'
  ) {
    if (
      !form.value.targetDisplayName.trim()
    ) {
      issues.push(
        'Enter the SSH target display name.',
      )
    }

    if (!form.value.hostname.trim()) {
      issues.push(
        'Enter the SSH hostname or IP address.',
      )
    }

    if (
      !form.value.verifierUsername.trim()
    ) {
      issues.push(
        'Enter the Verifier username.',
      )
    }

    if (
      form.value.operatingMode ===
        'APPROVAL_REQUIRED_ACTION' &&
      !form.value.executorUsername.trim()
    ) {
      issues.push(
        'Enter the Executor username.',
      )
    }
  }

  if (
    form.value.targetMode ===
    'NEW_DATABASE'
  ) {
    if (
      !form.value.targetDisplayName.trim()
    ) {
      issues.push(
        'Enter the database target display name.',
      )
    }

    if (!form.value.hostname.trim()) {
      issues.push(
        'Enter the database hostname or IP address.',
      )
    }

    if (
      !form.value.databaseName.trim()
    ) {
      issues.push(
        'Enter the database name.',
      )
    }

    if (
      !form.value.databaseUsername.trim()
    ) {
      issues.push(
        'Enter the read-only database username.',
      )
    }
  }

  if (
    form.value.operatingMode ===
      'APPROVAL_REQUIRED_ACTION' &&
    !form.value.selectedActionId
  ) {
    issues.push(
      'Select an existing ACTIVE remediation action.',
    )
  }

  if (
    isDatabase.value &&
    form.value.operatingMode ===
      'APPROVAL_REQUIRED_ACTION'
  ) {
    issues.push(
      'Database targets support investigate-only mode.',
    )
  }

  return [
    ...new Set(issues),
  ]
})

const activationIssues = computed(() => {
  const issues = [
    ...formIssues.value,
  ]

  if (
    !form.value.investigationSop.trim()
  ) {
    issues.push(
      'Generate and review the investigation SOP.',
    )
  }

  if (
    !hasDraft.value ||
    !assistantReady.value
  ) {
    issues.push(
      'Generate a valid assistant-reviewed draft.',
    )
  }

  if (
    form.value.targetMode ===
      'NEW' &&
    !form.value.verifierPassword
  ) {
    issues.push(
      'Enter the Verifier password.',
    )
  }

  if (
    form.value.targetMode ===
      'NEW' &&
    form.value.operatingMode ===
      'APPROVAL_REQUIRED_ACTION' &&
    !form.value.executorPassword
  ) {
    issues.push(
      'Enter the Executor password.',
    )
  }

  if (
    form.value.targetMode ===
      'NEW_DATABASE' &&
    !form.value.databasePassword
  ) {
    issues.push(
      'Enter the database password.',
    )
  }

  issues.push(
    ...assistantMissing.value,
    ...assistantIssues.value,
  )

  return [
    ...new Set(issues),
  ]
})

const preview = computed(() => {
  if (
    previewTab.value ===
    'assistant'
  ) {
    return assistantRequest.value
  }

  if (
    previewTab.value ===
    'activation'
  ) {
    return redactedActivationRequest.value
  }

  return bundle.value
})

const previewJson = computed(() =>
  JSON.stringify(
    preview.value,
    null,
    2,
  ),
)

async function loadTargets() {
  targetsLoading.value = true
  targetsError.value = ''

  try {
    const response =
      await api.onboardingTargets()

    targets.value = {
      ssh_targets:
        response?.ssh_targets || [],

      database_targets:
        response?.database_targets || [],
    }
  } catch (error) {
    targetsError.value =
      error.message
  } finally {
    targetsLoading.value = false
  }
}

async function loadActions() {
  actions.value = []
  actionsError.value = ''

  if (
    form.value.operatingMode !==
      'APPROVAL_REQUIRED_ACTION' ||
    isDatabase.value ||
    !form.value.dagId.trim() ||
    !form.value.targetId.trim()
  ) {
    return
  }

  actionsLoading.value = true

  try {
    const response =
      await api.onboardingActions({
        componentId:
          form.value.dagId.trim(),

        targetId:
          form.value.targetId.trim(),
      })

    actions.value =
      response?.items || []

    if (
      form.value.selectedActionId &&
      !actions.value.some(
        (action) =>
          action.action_id ===
          form.value.selectedActionId,
      )
    ) {
      form.value.selectedActionId = ''
    }
  } catch (error) {
    actionsError.value =
      error.message
  } finally {
    actionsLoading.value = false
  }
}

function invalidateDraft() {
  if (!hasDraft.value) {
    return
  }

  assistantReady.value = false
  activationResult.value = null
}

function changeTargetMode() {
  form.value.targetId = ''
  form.value.selectedActionId = ''
  actions.value = []

  if (isDatabase.value) {
    form.value.operatingMode =
      'INVESTIGATE_ONLY'
  }

  invalidateDraft()
}

function selectTarget(id) {
  form.value.targetId = id
  form.value.selectedActionId = ''
  actions.value = []

  invalidateDraft()
}

function applyDraft(draft) {
  if (!draft) {
    return
  }

  applyingDraft = true
  hasDraft.value = true

  form.value.dagId =
    draft.dag?.dag_id || ''

  form.value.exceptionTypes =
    (
      draft.dag?.exception_types ||
      []
    ).join('\n')

  form.value.investigationSop =
    draft.dag?.investigation_sop ||
    ''

  form.value.operatingMode =
    draft.operating_mode ||
    'INVESTIGATE_ONLY'

  form.value.selectedActionId =
    draft.selected_action_id ||
    ''

  review.value =
    draft.review_template ||
    review.value

  const registration =
    draft.target_registration || {}

  form.value.targetMode =
    registration.mode ||
    'EXISTING'

  if (
    registration.mode ===
    'EXISTING'
  ) {
    form.value.targetId =
      registration.target_id ||
      ''
  }

  if (
    registration.mode ===
    'EXISTING_DATABASE'
  ) {
    form.value.targetId =
      registration.database_target_id ||
      ''
  }

  if (
    registration.mode ===
    'NEW'
  ) {
    form.value.targetId =
      registration.target?.target_id ||
      ''

    form.value.targetDisplayName =
      registration.target?.display_name ||
      ''

    form.value.hostname =
      registration.target?.hostname ||
      ''

    form.value.sshPort =
      registration.target?.ssh_port ??
      22

    form.value.verifierCredentialName =
      registration
        .credential_plan
        ?.verifier
        ?.credential_name ||
      ''

    form.value.verifierUsername =
      registration
        .credential_plan
        ?.verifier
        ?.username ||
      ''

    form.value.executorCredentialName =
      registration
        .credential_plan
        ?.executor
        ?.credential_name ||
      ''

    form.value.executorUsername =
      registration
        .credential_plan
        ?.executor
        ?.username ||
      ''
  }

  if (
    registration.mode ===
    'NEW_DATABASE'
  ) {
    form.value.targetId =
      registration
        .target
        ?.database_target_id ||
      ''

    form.value.targetDisplayName =
      registration
        .target
        ?.display_name ||
      ''

    form.value.hostname =
      registration
        .target
        ?.hostname ||
      ''

    form.value.databasePort =
      registration
        .target
        ?.database_port ??
      3306

    form.value.databaseName =
      registration
        .target
        ?.database_name ||
      ''

    form.value.databaseCredentialName =
      registration
        .credential
        ?.credential_name ||
      ''

    form.value.databaseUsername =
      registration
        .credential
        ?.username ||
      ''
  }

  Promise.resolve().then(() => {
    applyingDraft = false
  })
}

async function generateDraft() {
  assistantError.value = ''
  assistantMessage.value = ''
  assistantMissing.value = []
  assistantIssues.value = []

  if (formIssues.value.length) {
    assistantError.value =
      'Complete the required fields before generating the draft.'

    return
  }

  assistantLoading.value = true

  try {
    const response =
      await api.onboardingAssistant(
        assistantRequest.value,
      )

    applyDraft(
      response.draft,
    )

    assistantMessage.value =
      response.assistant_message ||
      ''

    assistantMissing.value =
      response.missing_fields ||
      []

    assistantIssues.value =
      response.validation_issues ||
      []

    assistantReady.value =
      Boolean(
        response.ready_for_review,
      )

    if (assistantReady.value) {
      step.value = 4
    }
  } catch (error) {
    assistantError.value =
      error.message
  } finally {
    assistantLoading.value = false
  }
}

async function activate() {
  activationError.value = ''
  activationResult.value = null

  if (
    activationIssues.value.length
  ) {
    activationError.value =
      'Resolve every validation item before activation.'

    return
  }

  if (
    !activationConfirmed.value
  ) {
    activationError.value =
      'Confirm the activation review checkbox.'

    return
  }

  activationLoading.value = true

  try {
    activationResult.value =
      await api.activateOnboarding(
        activationRequest.value,
      )

    activationConfirmed.value =
      false
  } catch (error) {
    activationError.value =
      error.message
  } finally {
    activationLoading.value =
      false
  }
}

function goTo(nextStep) {
  step.value = Math.max(
    1,
    Math.min(4, nextStep),
  )

  if (step.value === 3) {
    loadActions()
  }
}

async function copyPreview() {
  try {
    await navigator.clipboard.writeText(
      previewJson.value,
    )

    copied.value = true

    window.setTimeout(() => {
      copied.value = false
    }, 1500)
  } catch {
    copied.value = false
  }
}

function downloadDraft() {
  const name =
    form.value.dagId
      .replace(
        /[^a-z0-9_-]+/gi,
        '_',
      ) ||
    'new_dag'

  const blob = new Blob(
    [
      JSON.stringify(
        bundle.value,
        null,
        2,
      ),
    ],
    {
      type: 'application/json',
    },
  )

  const url =
    URL.createObjectURL(blob)

  const link =
    document.createElement('a')

  link.href = url

  link.download =
    `${name}_onboarding_draft.json`

  link.click()

  URL.revokeObjectURL(url)
}

watch(
  () =>
    form.value.operatingMode,

  (mode) => {
    if (applyingDraft) {
      return
    }

    form.value.selectedActionId = ''
    actions.value = []

    invalidateDraft()

    if (
      mode ===
      'APPROVAL_REQUIRED_ACTION'
    ) {
      loadActions()
    }
  },
)

watch(
  structuredInput,

  () => {
    if (applyingDraft) {
      return
    }

    invalidateDraft()
  },

  {
    deep: true,
  },
)

onMounted(loadTargets)
</script>

<template>
  <div class="page onboarding-page">
    <div class="page-heading">
      <div>
        <span class="eyebrow">
          Administration
        </span>

        <h1>
          Project onboarding
        </h1>

        <p>
          Register a DAG, diagnostic SOP and target.
          Remediation mode can only reference an
          existing ACTIVE action.
        </p>
      </div>

      <span class="admin-badge">
        Admin activation
      </span>
    </div>

    <section class="assistant-card">
      <div>
        <span class="eyebrow">
          Form-assisted onboarding
        </span>

        <h2>
          Exact infrastructure values stay authoritative
        </h2>

        <p>
          The assistant organizes your free-text
          investigation logic. Passwords are never
          sent to the LLM.
        </p>
      </div>

      <span
        :class="[
          'state-badge',
          {
            ready: assistantReady,
          },
        ]"
      >
        {{
          assistantReady
            ? 'Ready to activate'
            : 'Draft incomplete'
        }}
      </span>
    </section>

    <div
      v-if="assistantError"
      class="feedback error"
    >
      {{ assistantError }}
    </div>

    <div
      v-if="assistantMessage"
      class="feedback success"
    >
      {{ assistantMessage }}
    </div>

    <nav class="stepper">
      <button
        v-for="item in steps"
        :key="item.number"
        type="button"
        :class="{
          active:
            step === item.number,

          complete:
            step > item.number,
        }"
        @click="goTo(item.number)"
      >
        <span>
          {{ item.number }}
        </span>

        {{ item.label }}
      </button>
    </nav>

    <div class="layout">
      <section class="form-card">
        <template v-if="step === 1">
          <header class="section-heading">
            <div>
              <span class="eyebrow">
                Step 01
              </span>

              <h2>
                DAG and SOP
              </h2>
            </div>
          </header>

          <div class="form-grid">
            <label>
              DAG/component ID

              <input
                v-model="form.dagId"
                maxlength="255"
                placeholder="aoiburr_monitor_table_data"
              />
            </label>

            <label>
              Exception types

              <textarea
                v-model="form.exceptionTypes"
                rows="3"
                placeholder="AirflowAlertException"
              ></textarea>
            </label>

            <label class="wide">
              What does the DAG monitor?

              <textarea
                v-model="form.monitoringDescription"
                rows="4"
                maxlength="5000"
                placeholder="Describe the monitored system and operational purpose."
              ></textarea>
            </label>

            <label class="wide">
              Investigation logic and exact diagnostic
              operations

              <textarea
                v-model="form.investigationLogic"
                rows="14"
                maxlength="50000"
                spellcheck="false"
                placeholder="Include tool, target, exact command/query/URL, order, branches and conclusions."
              ></textarea>

              <small>
                State-changing commands are not allowed
                in the investigation SOP.
              </small>
            </label>

            <label class="wide output-field">
              Generated investigation SOP

              <textarea
                v-model="form.investigationSop"
                rows="14"
                spellcheck="false"
                placeholder="The generated SOP appears here after Step 3."
              ></textarea>
            </label>
          </div>
        </template>

        <template v-else-if="step === 2">
          <header class="section-heading">
            <div>
              <span class="eyebrow">
                Step 02
              </span>

              <h2>
                Target and credentials
              </h2>
            </div>
          </header>

          <div class="mode-grid target-modes">
            <label
              v-for="mode in targetModes"
              :key="mode.value"
              :class="{
                selected:
                  form.targetMode ===
                  mode.value,
              }"
            >
              <input
                v-model="form.targetMode"
                type="radio"
                :value="mode.value"
                @change="changeTargetMode"
              />

              <span>
                <strong>
                  {{ mode.label }}
                </strong>

                <small>
                  {{ mode.description }}
                </small>
              </span>
            </label>
          </div>

          <div
            v-if="targetsError"
            class="feedback error"
          >
            {{ targetsError }}
          </div>

          <div
            v-if="targetsLoading"
            class="empty"
          >
            Loading targets…
          </div>

          <div
            v-else-if="
              form.targetMode ===
              'EXISTING'
            "
            class="target-grid"
          >
            <button
              v-for="target in sshTargets"
              :key="target.target_id"
              type="button"
              :class="{
                selected:
                  form.targetId ===
                  target.target_id,
              }"
              @click="
                selectTarget(
                  target.target_id,
                )
              "
            >
              <strong>
                {{
                  target.display_name ||
                  target.target_id
                }}
              </strong>

              <code>
                {{ target.target_id }}
              </code>

              <small>
                {{ target.hostname }}:{{
                  target.ssh_port
                }}
              </small>
            </button>

            <div
              v-if="!sshTargets.length"
              class="empty wide"
            >
              No enabled SSH targets are registered.
            </div>
          </div>

          <div
            v-else-if="
              form.targetMode ===
              'EXISTING_DATABASE'
            "
            class="target-grid"
          >
            <button
              v-for="target in databaseTargets"
              :key="
                target.database_target_id
              "
              type="button"
              :class="{
                selected:
                  form.targetId ===
                  target.database_target_id,
              }"
              @click="
                selectTarget(
                  target.database_target_id,
                )
              "
            >
              <strong>
                {{
                  target.display_name ||
                  target.database_target_id
                }}
              </strong>

              <code>
                {{
                  target.database_target_id
                }}
              </code>

              <small>
                {{ target.hostname }}:{{
                  target.database_port
                }}
                ·
                {{ target.database_name }}
              </small>

              <em
                v-if="
                  target.read_only_required
                "
              >
                Read only
              </em>
            </button>

            <div
              v-if="
                !databaseTargets.length
              "
              class="empty wide"
            >
              No enabled database targets are registered.
            </div>
          </div>

          <div
            v-else
            class="form-grid"
          >
            <label>
              Target ID

              <input
                v-model="form.targetId"
                maxlength="128"
              />
            </label>

            <label>
              Display name

              <input
                v-model="
                  form.targetDisplayName
                "
                maxlength="255"
              />
            </label>

            <label>
              Hostname or IP address

              <input
                v-model="form.hostname"
                maxlength="255"
              />
            </label>

            <template
              v-if="
                form.targetMode === 'NEW'
              "
            >
              <label>
                SSH port

                <input
                  v-model.number="
                    form.sshPort
                  "
                  type="number"
                  min="1"
                  max="65535"
                />
              </label>

              <div class="credential-box">
                <strong>
                  Verifier credential
                </strong>

                <label>
                  Credential name

                  <input
                    v-model="
                      form.verifierCredentialName
                    "
                    :placeholder="
                      generatedCredentialName(
                        'verifier',
                      )
                    "
                  />
                </label>

                <label>
                  Username

                  <input
                    v-model="
                      form.verifierUsername
                    "
                    autocomplete="off"
                  />
                </label>

                <label>
                  Password

                  <input
                    v-model="
                      form.verifierPassword
                    "
                    type="password"
                    autocomplete="new-password"
                  />
                </label>
              </div>

              <div
                v-if="
                  form.operatingMode ===
                  'APPROVAL_REQUIRED_ACTION'
                "
                class="credential-box"
              >
                <strong>
                  Executor credential
                </strong>

                <label>
                  Credential name

                  <input
                    v-model="
                      form.executorCredentialName
                    "
                    :placeholder="
                      generatedCredentialName(
                        'executor',
                      )
                    "
                  />
                </label>

                <label>
                  Username

                  <input
                    v-model="
                      form.executorUsername
                    "
                    autocomplete="off"
                  />
                </label>

                <label>
                  Password

                  <input
                    v-model="
                      form.executorPassword
                    "
                    type="password"
                    autocomplete="new-password"
                  />
                </label>
              </div>

              <div class="notice wide">
                During activation, the backend connects
                to the server, discovers its SSH host
                key and stores the pinned identity
                before enabling the target.
              </div>
            </template>

            <template v-else>
              <label>
                Database port

                <input
                  v-model.number="
                    form.databasePort
                  "
                  type="number"
                  min="1"
                  max="65535"
                />
              </label>

              <label>
                Database name

                <input
                  v-model="
                    form.databaseName
                  "
                  maxlength="255"
                />
              </label>

              <label>
                Credential name

                <input
                  v-model="
                    form.databaseCredentialName
                  "
                  :placeholder="
                    generatedCredentialName(
                      'database_read_only',
                    )
                  "
                />
              </label>

              <label>
                Read-only username

                <input
                  v-model="
                    form.databaseUsername
                  "
                  autocomplete="off"
                />
              </label>

              <label>
                Password

                <input
                  v-model="
                    form.databasePassword
                  "
                  type="password"
                  autocomplete="new-password"
                />
              </label>

              <div class="notice wide">
                During activation, the backend tests
                the connection and rejects accounts
                containing write privileges.
              </div>
            </template>
          </div>

          <p class="security-note">
            Passwords stay in browser memory. They are
            excluded from assistant requests, JSON
            downloads and visible previews. The backend
            encrypts them during activation.
          </p>
        </template>

        <template v-else-if="step === 3">
          <header class="section-heading">
            <div>
              <span class="eyebrow">
                Step 03
              </span>

              <h2>
                Operating mode
              </h2>
            </div>
          </header>

          <div class="mode-grid">
            <label
              :class="{
                selected:
                  form.operatingMode ===
                  'INVESTIGATE_ONLY',
              }"
            >
              <input
                v-model="
                  form.operatingMode
                "
                type="radio"
                value="INVESTIGATE_ONLY"
              />

              <span>
                <strong>
                  Investigate and report only
                </strong>

                <small>
                  The Verifier runs the diagnostic SOP
                  and reports evidence. No remediation
                  action is linked.
                </small>
              </span>
            </label>

            <label
              :class="{
                selected:
                  form.operatingMode ===
                  'APPROVAL_REQUIRED_ACTION',

                disabled:
                  isDatabase,
              }"
            >
              <input
                v-model="
                  form.operatingMode
                "
                type="radio"
                value="APPROVAL_REQUIRED_ACTION"
                :disabled="isDatabase"
              />

              <span>
                <strong>
                  Use an existing action
                </strong>

                <small>
                  Link an ACTIVE registered action.
                  Execution still requires separate
                  engineer approval.
                </small>
              </span>
            </label>
          </div>

          <div
            v-if="
              form.operatingMode ===
              'INVESTIGATE_ONLY'
            "
            class="notice"
          >
            The bundle will contain
            <code>
              selected_action_id: null
            </code>.
          </div>

          <div
            v-else
            class="action-browser"
          >
            <div class="browser-heading">
              <div>
                <strong>
                  Eligible registered actions
                </strong>

                <p>
                  Only ACTIVE, approval-required actions
                  matching the exact DAG and SSH target
                  are returned.
                </p>
              </div>

              <button
                class="button secondary compact"
                type="button"
                :disabled="actionsLoading"
                @click="loadActions"
              >
                {{
                  actionsLoading
                    ? 'Loading…'
                    : 'Refresh actions'
                }}
              </button>
            </div>

            <div
              v-if="actionsError"
              class="feedback error"
            >
              {{ actionsError }}
            </div>

            <div
              v-else-if="actionsLoading"
              class="empty"
            >
              Loading actions…
            </div>

            <div
              v-else-if="!actions.length"
              class="empty"
            >
              No ACTIVE approval-required action matches
              this DAG and target. Register the action
              separately before using this mode.
            </div>

            <template v-else>
              <label
                v-for="action in actions"
                :key="action.action_id"
                :class="[
                  'action-option',
                  {
                    selected:
                      form.selectedActionId ===
                      action.action_id,
                  },
                ]"
              >
                <input
                  v-model="
                    form.selectedActionId
                  "
                  type="radio"
                  :value="action.action_id"
                />

                <span>
                  <strong>
                    {{ action.display_name }}
                  </strong>

                  <code>
                    {{ action.action_id }}
                  </code>

                  <small>
                    {{ action.description }}
                  </small>

                  <em>
                    {{ action.risk_level }}
                    ·
                    {{
                      action.implementation_version
                    }}
                  </em>
                </span>
              </label>
            </template>

            <p
              v-if="selectedAction"
              class="selection"
            >
              Selected:

              <strong>
                {{
                  selectedAction.action_id
                }}
              </strong>
            </p>
          </div>
        </template>

        <template v-else>
          <header class="section-heading">
            <div>
              <span class="eyebrow">
                Step 04
              </span>

              <h2>
                Review and activate
              </h2>
            </div>
          </header>

          <div
            :class="[
              'validation',
              activationIssues.length
                ? 'bad'
                : 'good',
            ]"
          >
            <strong>
              {{
                activationIssues.length
                  ? `${activationIssues.length} item(s) require attention`
                  : 'Ready for activation'
              }}
            </strong>

            <ul
              v-if="
                activationIssues.length
              "
            >
              <li
                v-for="
                  issue in
                  activationIssues
                "
                :key="issue"
              >
                {{ issue }}
              </li>
            </ul>

            <p v-else>
              The backend will revalidate the target,
              credentials, SOP and selected action
              before committing the onboarding
              transaction.
            </p>
          </div>

          <div class="summary-grid">
            <div>
              <span>
                DAG
              </span>

              <strong>
                {{ form.dagId }}
              </strong>
            </div>

            <div>
              <span>
                Target
              </span>

              <strong>
                {{ form.targetId }}
              </strong>
            </div>

            <div>
              <span>
                Mode
              </span>

              <strong>
                {{ form.operatingMode }}
              </strong>
            </div>

            <div>
              <span>
                Action
              </span>

              <strong>
                {{
                  form.selectedActionId ||
                  'None'
                }}
              </strong>
            </div>
          </div>

          <div
            v-if="review.summary"
            class="review-card"
          >
            <p>
              {{ review.summary }}
            </p>

            <div class="review-columns">
              <div>
                <strong>
                  SOP review
                </strong>

                <ul>
                  <li
                    v-for="
                      item in
                      review.sop_review_points
                    "
                    :key="item"
                  >
                    {{ item }}
                  </li>
                </ul>
              </div>

              <div
                v-if="
                  review
                    .action_review_points
                    .length
                "
              >
                <strong>
                  Action review
                </strong>

                <ul>
                  <li
                    v-for="
                      item in
                      review.action_review_points
                    "
                    :key="item"
                  >
                    {{ item }}
                  </li>
                </ul>
              </div>

              <div>
                <strong>
                  Activation requirements
                </strong>

                <ul>
                  <li
                    v-for="
                      item in
                      review
                        .activation_requirements
                    "
                    :key="item"
                  >
                    {{ item }}
                  </li>
                </ul>
              </div>
            </div>
          </div>

          <label class="confirmation">
            <input
              v-model="
                activationConfirmed
              "
              type="checkbox"
            />

            <span>
              I reviewed the exact DAG ID, exception
              types, target, SOP and selected action.
              Activate this configuration.
            </span>
          </label>

          <div
            v-if="activationError"
            class="feedback error"
          >
            {{ activationError }}
          </div>

          <div
            v-if="activationResult"
            class="feedback success"
          >
            <strong>
              Onboarding activated
            </strong>

            <p>
              {{
                activationResult.message
              }}
            </p>

            <code>
              {{
                activationResult.dag_id
              }}
              ·
              {{
                activationResult.target_id
              }}
            </code>
          </div>

          <div class="final-actions">
            <button
              class="button secondary"
              type="button"
              @click="downloadDraft"
            >
              Download draft
            </button>

            <button
              class="button primary"
              type="button"
              :disabled="
                activationLoading ||
                activationIssues.length ||
                !activationConfirmed
              "
              @click="activate"
            >
              {{
                activationLoading
                  ? 'Activating…'
                  : 'Activate onboarding'
              }}
            </button>
          </div>
        </template>

        <footer class="navigation">
          <button
            class="button secondary"
            type="button"
            :disabled="step === 1"
            @click="goTo(step - 1)"
          >
            Previous
          </button>

          <button
            v-if="step < 3"
            class="button primary"
            type="button"
            @click="goTo(step + 1)"
          >
            Continue
          </button>

          <button
            v-else-if="step === 3"
            class="button primary"
            type="button"
            :disabled="
              assistantLoading ||
              formIssues.length
            "
            @click="generateDraft"
          >
            {{
              assistantLoading
                ? 'Generating…'
                : 'Generate review draft'
            }}
          </button>
        </footer>
      </section>

      <aside class="preview-card">
        <div class="preview-heading">
          <div>
            <span class="eyebrow">
              Generated output
            </span>

            <h2>
              Strict preview
            </h2>
          </div>

          <button
            class="button secondary compact"
            type="button"
            @click="copyPreview"
          >
            {{
              copied
                ? 'Copied'
                : 'Copy'
            }}
          </button>
        </div>

        <div class="tabs">
          <button
            type="button"
            :class="{
              active:
                previewTab ===
                'bundle',
            }"
            @click="
              previewTab = 'bundle'
            "
          >
            Bundle
          </button>

          <button
            type="button"
            :class="{
              active:
                previewTab ===
                'activation',
            }"
            @click="
              previewTab =
                'activation'
            "
          >
            Activation
          </button>

          <button
            type="button"
            :class="{
              active:
                previewTab ===
                'assistant',
            }"
            @click="
              previewTab =
                'assistant'
            "
          >
            Assistant
          </button>
        </div>

        <pre>{{ previewJson }}</pre>

        <p class="preview-note">
          Passwords are redacted and never sent
          to the LLM.
        </p>
      </aside>
    </div>
  </div>
</template>

<style scoped>
.onboarding-page {
  max-width: 1700px;
}

.page-heading,
.assistant-card,
.section-heading,
.browser-heading,
.preview-heading,
.navigation,
.final-actions {
  display: flex;
  align-items: center;
  justify-content: space-between;
  gap: 16px;
}

.page-heading p,
.assistant-card p {
  color: var(--muted);
  line-height: 1.55;
}

.admin-badge,
.state-badge {
  padding: 7px 10px;
  border-radius: 999px;
  font:
    600 10px
    'IBM Plex Mono',
    monospace;
  text-transform: uppercase;
  white-space: nowrap;
}

.admin-badge,
.state-badge.ready {
  color: var(--green);
  border:
    1px solid
    rgba(94, 226, 160, 0.25);
  background:
    rgba(94, 226, 160, 0.08);
}

.state-badge {
  color: var(--amber);
  border:
    1px solid
    rgba(255, 188, 102, 0.25);
  background:
    rgba(255, 188, 102, 0.08);
}

.assistant-card,
.form-card,
.preview-card {
  border:
    1px solid var(--line);
  border-radius:
    var(--radius);
  background:
    rgba(13, 26, 44, 0.86);
}

.assistant-card {
  margin-bottom: 18px;
  padding: 20px;
}

.assistant-card h2,
.section-heading h2,
.preview-heading h2 {
  margin: 5px 0 0;
  font-size: 20px;
}

.feedback {
  margin: 10px 0;
  padding: 13px 14px;
  border-radius: 11px;
  font-size: 12px;
}

.feedback.error {
  color: #ffabb3;
  border:
    1px solid
    rgba(255, 114, 128, 0.2);
  background:
    rgba(255, 114, 128, 0.08);
}

.feedback.success {
  color: #bfe9d3;
  border:
    1px solid
    rgba(94, 226, 160, 0.2);
  background:
    rgba(94, 226, 160, 0.06);
}

.feedback.success code {
  display: block;
  margin-top: 8px;
  color: var(--cyan);
}

.stepper {
  display: grid;
  grid-template-columns:
    repeat(4, 1fr);
  margin-bottom: 18px;
  overflow: hidden;
  border:
    1px solid var(--line);
  border-radius: 14px;
}

.stepper button {
  display: flex;
  align-items: center;
  gap: 9px;
  min-height: 58px;
  padding: 10px 14px;
  color: var(--muted);
  border: 0;
  border-right:
    1px solid var(--line);
  background:
    rgba(13, 26, 44, 0.72);
  cursor: pointer;
}

.stepper button:last-child {
  border-right: 0;
}

.stepper span {
  display: grid;
  place-items: center;
  width: 27px;
  height: 27px;
  border:
    1px solid var(--line);
  border-radius: 50%;
}

.stepper button.active {
  color: var(--text);
  background:
    rgba(75, 216, 208, 0.08);
}

.stepper button.active span,
.stepper button.complete span {
  color: #06111d;
  border-color: var(--cyan);
  background: var(--cyan);
}

.onboarding-page .button {
  width: auto;
  min-height: 34px;
  padding: 0 11px;
  border-radius: 8px;
  font-size: 12px;
}

.layout {
  display: grid;
  grid-template-columns:
    minmax(0, 1.45fr)
    minmax(360px, 0.75fr);
  gap: 18px;
  align-items: start;
}

.form-card,
.preview-card {
  padding: 22px;
}

.section-heading {
  margin-bottom: 20px;
}

.form-grid {
  display: grid;
  grid-template-columns:
    repeat(2, minmax(0, 1fr));
  gap: 15px;
}

.form-grid label,
.credential-box label {
  display: grid;
  gap: 7px;
  color: var(--muted);
  font-size: 12px;
}

.form-grid small {
  line-height: 1.5;
}

.wide {
  grid-column: 1 / -1;
}

.output-field {
  padding-top: 18px;
  border-top:
    1px solid var(--line);
}

.mode-grid {
  display: grid;
  grid-template-columns:
    repeat(2, 1fr);
  gap: 12px;
  margin-bottom: 18px;
}

.target-modes {
  grid-template-columns:
    repeat(4, 1fr);
}

.mode-grid {
  display: grid;
  grid-template-columns: repeat(2, minmax(180px, 280px));
  justify-content: start;
  gap: 8px;
  margin-bottom: 14px;
}

.mode-grid.four {
  grid-template-columns: repeat(4, minmax(120px, 165px));
}

.mode-grid label,
.action-option,
.confirmation {
  display: flex;
  align-items: flex-start;
  width: auto;
  min-height: 0;
  gap: 7px;
  padding: 8px 10px;
  color: var(--muted);
  border: 1px solid var(--line);
  border-radius: 8px;
  background: rgba(7, 20, 33, 0.55);
  cursor: pointer;
  font-size: 11px;
  line-height: 1.35;
}

.mode-grid label strong,
.action-option strong,
.confirmation strong {
  font-size: 15px;
}

.mode-grid label small,
.action-option small {
  font-size: 10px;
  line-height: 1.35;
}

.mode-grid input,
.action-option input,
.confirmation input {
  flex: 0 0 auto;
  width: 14px;
  height: 14px;
  margin: 1px 0 0;
}

.mode-grid label.selected,
.action-option.selected {
  color: var(--text);
  border-color: var(--cyan);
  background: rgba(75, 216, 208, 0.1);
}

.mode-grid label.disabled {
  cursor: not-allowed;
  opacity: 0.5;
}

.mode-grid strong,
.action-option strong {
  display: block;
  color: var(--text);
}

.mode-grid small,
.action-option small {
  display: block;
  margin-top: 4px;
  color: var(--muted);
}

.target-grid {
  display: grid;
  grid-template-columns:
    repeat(2, 1fr);
  gap: 10px;
}

.target-grid button {
  display: grid;
  gap: 5px;
  padding: 13px;
  color: var(--text);
  text-align: left;
  border:
    1px solid var(--line);
  border-radius: 11px;
  background:
    rgba(7, 20, 33, 0.55);
  cursor: pointer;
}

.target-grid button.selected {
  border-color: var(--cyan);
  background:
    rgba(75, 216, 208, 0.08);
}

.target-grid code,
.action-option code {
  color: var(--cyan);
  overflow-wrap: anywhere;
}

.target-grid small {
  color: var(--muted);
}

.target-grid em {
  width: max-content;
  color: var(--green);
  font:
    600 9px
    'IBM Plex Mono',
    monospace;
  font-style: normal;
  text-transform: uppercase;
}

.credential-box {
  display: grid;
  gap: 11px;
  padding: 15px;
  border:
    1px solid var(--line);
  border-radius: 12px;
  background:
    rgba(7, 20, 33, 0.55);
}

.notice,
.security-note,
.empty,
.selection {
  padding: 13px;
  border:
    1px solid var(--line);
  border-radius: 10px;
  background:
    rgba(7, 20, 33, 0.5);
}

.security-note {
  margin-top: 16px;
  color: var(--amber);
  border-color:
    rgba(255, 188, 102, 0.2);
  background:
    rgba(255, 188, 102, 0.06);
  font-size: 12px;
  line-height: 1.55;
}

.action-browser {
  display: grid;
  gap: 10px;
  padding: 15px;
  border:
    1px solid var(--line);
  border-radius: 12px;
}

.browser-heading {
  display: flex;
  align-items: flex-start;
  justify-content: space-between;
}

.browser-heading p {
  margin: 5px 0 0;
  color: var(--muted);
  font-size: 12px;
}

.action-option span {
  display: grid;
  gap: 5px;
}

.action-option em {
  color: var(--amber);
  font:
    600 9px
    'IBM Plex Mono',
    monospace;
  font-style: normal;
  text-transform: uppercase;
}

.validation {
  padding: 15px;
  border-radius: 12px;
}

.validation.bad {
  color: #ffabb3;
  border:
    1px solid
    rgba(255, 114, 128, 0.2);
  background:
    rgba(255, 114, 128, 0.08);
}

.validation.good {
  color: var(--green);
  border:
    1px solid
    rgba(94, 226, 160, 0.2);
  background:
    rgba(94, 226, 160, 0.08);
}

.validation ul {
  margin: 10px 0 0;
  padding-left: 20px;
  line-height: 1.7;
}

.validation p {
  margin: 7px 0 0;
  color: var(--muted);
}

.summary-grid {
  display: grid;
  grid-template-columns:
    repeat(2, 1fr);
  gap: 10px;
  margin: 18px 0;
}

.summary-grid div,
.review-card {
  padding: 14px;
  border:
    1px solid var(--line);
  border-radius: 11px;
  background:
    rgba(7, 20, 33, 0.55);
}

.summary-grid span,
.summary-grid strong {
  display: block;
}

.summary-grid span {
  margin-bottom: 6px;
  color: var(--muted);
  font-size: 11px;
}

.summary-grid strong {
  overflow-wrap: anywhere;
}

.review-card > p {
  color: #b7c9dc;
  line-height: 1.55;
}

.review-columns {
  display: grid;
  grid-template-columns:
    repeat(3, 1fr);
  gap: 10px;
}

.review-columns > div {
  padding: 12px;
  border:
    1px solid var(--line);
  border-radius: 10px;
}

.review-columns ul {
  padding-left: 18px;
  color: var(--muted);
  font-size: 12px;
  line-height: 1.55;
}

.confirmation {
  display: inline-flex;
  width: fit-content;
  max-width: 100%;
  margin: 12px 0;
}

.navigation {
  margin-top: 22px;
  padding-top: 18px;
  border-top:
    1px solid var(--line);
}

.final-actions {
  justify-content: flex-end;
  margin-top: 14px;
}

.preview-card {
  position: sticky;
  top: 18px;
}

.tabs {
  display: flex;
  gap: 5px;
  margin: 16px 0 10px;
  padding: 4px;
  border-radius: 9px;
  background: #071421;
}

.tabs button {
  padding: 8px 10px;
  color: var(--muted);
  border: 0;
  border-radius: 7px;
  background: transparent;
  cursor: pointer;
}

.tabs button.active {
  color: var(--cyan);
  background: var(--surface-2);
}

.preview-card pre {
  min-height: 480px;
  max-height: 720px;
  overflow: auto;
}

.preview-note {
  color: var(--green);
  font-size: 12px;
}

@media (max-width: 1200px) {
  .layout {
    grid-template-columns: 1fr;
  }

  .preview-card {
    position: static;
  }

  .target-modes {
    grid-template-columns:
      repeat(2, 1fr);
  }
}

@media (max-width: 760px) {
  .page-heading,
  .assistant-card,
  .section-heading,
  .browser-heading {
    align-items: flex-start;
    flex-direction: column;
  }

  .stepper,
  .form-grid,
  .mode-grid,
  .target-modes,
  .target-grid,
  .summary-grid,
  .review-columns {
    grid-template-columns: 1fr;
  }

  .wide {
    grid-column: auto;
  }

  .final-actions {
    align-items: stretch;
    flex-direction: column;
  }
}
</style>
