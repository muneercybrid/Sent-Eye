(() => {
  'use strict';

  const $ = (selector, root = document) => root.querySelector(selector);
  const $$ = (selector, root = document) => Array.from(root.querySelectorAll(selector));
  const state = {
    modules: [],
    jobs: [],
    health: null,
    activeJobId: null,
    reportJobId: null,
    pollHandle: null,
    currentUser: null,
    csrfToken: null,
    jobsInterval: null,
    healthInterval: null,
    adminOverview: null,
    adminUsers: [],
    adminInvestigations: [],
    adminAudit: [],
    selectedAdminUserId: ''
  };
  const TYPE_ORDER = ['image', 'username', 'email', 'phone', 'ip', 'domain', 'vin', 'mac', 'plate', 'coords'];
  const TYPE_LABELS = { image: 'Image', username: 'Username', email: 'Email address', phone: 'Phone number', ip: 'IP address', domain: 'Domain', vin: 'Vehicle VIN', mac: 'MAC address', plate: 'Vehicle plate', coords: 'Coordinates' };
  const TYPE_HINTS = {
    username: 'Enter the username or handle, without a platform URL unless required by the module.',
    email: 'Enter the email address you are authorized to investigate.',
    phone: 'Include the country code where possible, for example +234…',
    ip: 'Enter a public IPv4 or IPv6 address.',
    domain: 'Enter a domain name, for example example.com.',
    vin: 'Enter the vehicle identification number (VIN).',
    mac: 'Enter a MAC address in its standard notation.',
    plate: 'Enter the vehicle registration plate.',
    coords: 'Enter coordinates in the format expected by your enabled modules.'
  };

  function make(tag, className, text) {
    const node = document.createElement(tag);
    if (className) node.className = className;
    if (text !== undefined && text !== null) node.textContent = String(text);
    return node;
  }

  function typeLabel(type) { return TYPE_LABELS[type] || String(type || 'Unknown').replace(/[_-]/g, ' '); }
  function statusClass(status) {
    const value = String(status || 'pending').toLowerCase();
    if (value === 'completed') return 'status-completed';
    if (value === 'running') return 'status-running';
    if (value === 'failed' || value === 'cancelled') return 'status-failed';
    return 'status-pending';
  }
  function prettyStatus(status) { return String(status || 'pending').replace(/[_-]/g, ' ').toUpperCase(); }
  function dateLabel(value) {
    if (!value) return '—';
    let date;
    if (typeof value === 'number') date = new Date(value < 1e12 ? value * 1000 : value);
    else date = new Date(value);
    if (Number.isNaN(date.getTime())) return '—';
    return new Intl.DateTimeFormat(undefined, { month: 'short', day: 'numeric', hour: '2-digit', minute: '2-digit' }).format(date);
  }
  function progressOf(job) {
    const total = Number(job?.progress_total || 0);
    const current = Number(job?.progress_current || 0);
    if (String(job?.status).toLowerCase() === 'completed') return 100;
    if (total <= 0) return String(job?.status).toLowerCase() === 'running' ? 5 : 0;
    return Math.max(0, Math.min(99, Math.round((current / total) * 100)));
  }
  function safeJson(value) {
    try { return JSON.stringify(value, null, 2); } catch (_) { return String(value); }
  }

  async function ensureCsrfToken(force = false) {
    if (!force && state.csrfToken) return state.csrfToken;

    const response = await fetch('/api/auth/csrf', {
      method: 'GET',
      credentials: 'same-origin',
      cache: 'no-store'
    });

    if (!response.ok) {
      throw new Error(`Could not initialize security token (${response.status}).`);
    }

    const data = await response.json();
    if (!data.csrf_token || data.csrf_token.length < 32) {
      throw new Error('The server returned an invalid security token.');
    }

    state.csrfToken = data.csrf_token;
    return state.csrfToken;
  }

  async function request(url, options = {}) {
    const method = String(options.method || 'GET').toUpperCase();
    const headers = new Headers(options.headers || {});

    if (!['GET', 'HEAD', 'OPTIONS'].includes(method)) {
      if (!state.csrfToken) await ensureCsrfToken();
      headers.set('X-CSRF-Token', state.csrfToken);
    }

    const response = await fetch(url, {
      ...options,
      method,
      headers,
      credentials: 'same-origin'
    });

    const contentType = response.headers.get('content-type') || '';
    let data;
    if (contentType.includes('application/json')) data = await response.json();
    else data = await response.text();

    if (!response.ok) {
      if (response.status === 401 && state.currentUser) {
        state.currentUser = null;
        state.csrfToken = null;
        stopWorkspacePolling();
        showAuthScreen('Your session has expired. Please sign in again.', true);
      }

      const detail = data && typeof data === 'object'
        ? (data.detail || data.message)
        : data;
      const error = new Error(detail || `Request failed (${response.status})`);
      error.status = response.status;
      throw error;
    }

    return data;
  }


  function setAuthMessage(message, isError = false) {
    const box = $('#auth-message');
    box.textContent = message || '';
    box.classList.toggle('hidden', !message);
    box.classList.toggle('error', Boolean(isError));
  }

  function setAuthMode(registerMode) {
    $('#login-form').classList.toggle('hidden', registerMode);
    $('#register-form').classList.toggle('hidden', !registerMode);

    $('#auth-title').textContent = registerMode
      ? 'Request a Sent Eye account'
      : 'Sign in to Sent Eye';

    $('#auth-subtitle').textContent = registerMode
      ? 'Create an account. An administrator must approve it before you can sign in.'
      : 'Sign in with an administrator-approved account to access your workspace.';

    $('#auth-switch-text').textContent = registerMode
      ? 'Already have an account?'
      : 'New to Sent Eye?';

    $('#auth-mode-toggle').textContent = registerMode
      ? 'Sign in'
      : 'Request access';

    setAuthMessage('');
  }

  function showAuthScreen(message = '', isError = false) {
    $('.app-shell').classList.add('hidden');
    $('#auth-screen').classList.remove('hidden');
    setAuthMessage(message, isError);
  }

  function showWorkspace(user) {
    state.currentUser = user;
    $('#auth-screen').classList.add('hidden');
    $('.app-shell').classList.remove('hidden');

    $('#account-name').textContent = user.full_name || user.email || 'Sent Eye user';
    $('#account-role').textContent = String(user.role || 'user').toUpperCase();
    $('#admin-nav').classList.toggle('hidden', user.role !== 'admin');

    const initials = String(user.full_name || user.email || 'SE')
      .trim()
      .split(/\s+/)
      .slice(0, 2)
      .map(part => part[0] || '')
      .join('')
      .toUpperCase();

    $('#avatar-button').textContent = initials || 'SE';
    $('#avatar-button').setAttribute(
      'aria-label',
      `Signed in as ${user.full_name || user.email}`
    );
  }

  function stopWorkspacePolling() {
    if (state.jobsInterval !== null) {
      window.clearInterval(state.jobsInterval);
      state.jobsInterval = null;
    }
    if (state.healthInterval !== null) {
      window.clearInterval(state.healthInterval);
      state.healthInterval = null;
    }
  }

  async function activateWorkspace(user) {
    showWorkspace(user);

    await Promise.all([
      loadModules(),
      loadJobs()
    ]);

    if (user.role === 'admin') {
      await loadAdminData();
    }

    if (state.jobsInterval === null) {
      state.jobsInterval = window.setInterval(() => loadJobs(), 10000);
    }
    if (state.healthInterval === null) {
      state.healthInterval = window.setInterval(() => loadHealth(), 30000);
    }
  }

  async function submitLogin(event) {
    event.preventDefault();
    setAuthMessage('');

    const button = $('#login-submit');
    button.disabled = true;
    button.textContent = 'Signing in…';

    try {
      await ensureCsrfToken();

      const result = await request('/api/auth/login', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          email: $('#login-email').value.trim(),
          password: $('#login-password').value
        })
      });

      state.csrfToken = result.csrf_token;

      // Confirm the new session and read the cookie-backed CSRF token.
      const session = await request('/api/auth/me');
      if (!session.user || !session.csrf_token) {
        throw new Error('The authenticated session could not be verified.');
      }

      state.csrfToken = session.csrf_token;
      $('#login-form').reset();
      await activateWorkspace(session.user);
    } catch (error) {
      setAuthMessage(error.message || 'Sign-in failed.', true);
    } finally {
      button.disabled = false;
      button.textContent = 'Sign in';
    }
  }

  async function submitRegistration(event) {
    event.preventDefault();
    setAuthMessage('');

    const button = $('#register-submit');
    button.disabled = true;
    button.textContent = 'Submitting…';

    try {
      await ensureCsrfToken();

      const result = await request('/api/auth/register', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          full_name: $('#register-name').value.trim(),
          email: $('#register-email').value.trim(),
          password: $('#register-password').value
        })
      });

      $('#register-form').reset();
      setAuthMode(false);
      setAuthMessage(
        result.message ||
        'Registration received. An administrator must approve your account before you can sign in.'
      );
    } catch (error) {
      setAuthMessage(error.message || 'Registration failed.', true);
    } finally {
      button.disabled = false;
      button.textContent = 'Request an account';
    }
  }

  async function signOut() {
    const button = $('#logout-button');
    button.disabled = true;

    try {
      await request('/api/auth/logout', { method: 'POST' });
    } catch (error) {
      // A 401 means the server session is already invalid.
      if (error.status !== 401) {
        toast(`Could not sign out: ${error.message}`, true);
        button.disabled = false;
        return;
      }
    }

    stopWorkspacePolling();
    state.currentUser = null;
    state.csrfToken = null;
    state.jobs = [];
    state.modules = [];
    state.activeJobId = null;
    setAuthMode(false);
    showAuthScreen('You have been signed out.');

    try {
      await ensureCsrfToken(true);
    } catch (error) {
      setAuthMessage(error.message, true);
    } finally {
      button.disabled = false;
    }
  }

  function bindAuthEvents() {
    $('#auth-mode-toggle').addEventListener('click', () => {
      const registering = !$('#register-form').classList.contains('hidden');
      setAuthMode(!registering);
    });

    $('#login-form').addEventListener('submit', submitLogin);
    $('#register-form').addEventListener('submit', submitRegistration);
    $('#logout-button').addEventListener('click', signOut);
  }

  function toast(message, isError = false) {
    const region = $('#toast-region');
    const item = make('div', `toast${isError ? ' error' : ''}`, message);
    region.append(item);
    window.setTimeout(() => item.remove(), 4300);
  }

  function setHealth(ok, detail = '') {
    const dot = $('#sidebar-health-dot');
    const text = $('#sidebar-health-text');
    const sub = $('#sidebar-health-subtext');
    const indicator = $('#api-indicator');
    dot.className = `status-dot ${ok ? 'online' : 'offline'}`;
    text.textContent = ok ? 'All systems operational' : 'API unavailable';
    sub.textContent = detail || (ok ? 'Sent Eye backend responding' : 'Could not reach the local API');
    const apiDot = $('.status-dot', indicator);
    apiDot.className = `status-dot ${ok ? 'online' : 'offline'}`;
    indicator.lastElementChild.textContent = ok ? 'API connected' : 'API offline';
  }

  function showView(name) {
    if (name === 'admin' && state.currentUser?.role !== 'admin') {
      name = 'overview';
    }

    const section = $(`#view-${name}`);
    if (!section) return;

    if (name === 'admin') loadAdminData();
    $$('.view-section').forEach(node => node.classList.toggle('active', node === section));
    $$('.nav-link').forEach(node => node.classList.toggle('active', node.dataset.view === name));
    const labels = { overview: 'Overview', investigate: 'New investigation', history: 'Investigation history', modules: 'Intelligence modules', admin: 'Administration' };
    $('#breadcrumb-current').textContent = labels[name] || 'Workspace';
    window.scrollTo({ top: 0, behavior: 'smooth' });
  }

  function supportedTypes() {
    const types = new Set();
    state.modules.forEach(module => (module.target_types || []).forEach(type => types.add(type)));
    return Array.from(types).sort((a, b) => {
      const ai = TYPE_ORDER.indexOf(a), bi = TYPE_ORDER.indexOf(b);
      return (ai < 0 ? 99 : ai) - (bi < 0 ? 99 : bi) || String(a).localeCompare(String(b));
    });
  }

  function renderTargetTypes() {
    const select = $('#target-type');
    const previous = select.value;
    select.replaceChildren();
    const types = supportedTypes();
    if (!types.length) {
      const option = make('option', '', 'No supported target types');
      option.value = '';
      select.append(option);
      select.disabled = true;
      renderQuickTargets([]);
      updateTargetFields();
      return;
    }
    select.disabled = false;
    const prompt = make('option', '', 'Select a target type');
    prompt.value = '';
    select.append(prompt);
    types.forEach(type => {
      const option = make('option', '', typeLabel(type));
      option.value = type;
      select.append(option);
    });
    select.value = types.includes(previous) ? previous : (types.includes('image') ? 'image' : types[0]);
    renderQuickTargets(types);
    updateTargetFields();
  }

  function renderQuickTargets(types) {
    const box = $('#quick-targets');
    box.replaceChildren();
    if (!types.length) { box.append(make('div', 'empty-inline', 'No target types are currently registered.')); return; }
    const symbols = { image: '▧', username: '@', email: '✉', phone: '⌕', ip: '⌗', domain: '◇', vin: '▤', mac: '⌘', plate: '▣', coords: '◎' };
    types.forEach(type => {
      const button = make('button', 'quick-target');
      button.type = 'button';
      const icon = make('span', 'quick-target-icon', symbols[type] || '•');
      const label = make('span', '', typeLabel(type));
      button.append(icon, label);
      button.addEventListener('click', () => { $('#target-type').value = type; updateTargetFields(); showView('investigate'); });
      box.append(button);
    });
  }

  function updateTargetFields() {
    const type = $('#target-type').value;
    const isImage = type === 'image';
    $('#target-text-group').classList.toggle('hidden', isImage);
    $('#target-file-group').classList.toggle('hidden', !isImage);
    $('#face-option-group').classList.toggle('hidden', !isImage);
    $('#target-value').required = !isImage;
    $('#target-file').required = isImage;
    $('#target-help').textContent = TYPE_HINTS[type] || 'Enter the identifier you are authorized to investigate.';
    $('#target-value').placeholder = type === 'username' ? 'e.g. username123' : type === 'email' ? 'e.g. person@example.com' : type === 'phone' ? 'e.g. +2348012345678' : type === 'ip' ? 'e.g. 203.0.113.10' : type === 'domain' ? 'e.g. example.com' : 'Enter target value…';
    renderCompatibleModules(type);
  }

  function renderCompatibleModules(type) {
    const box = $('#compatible-modules');
    box.replaceChildren();
    const compatible = state.modules.filter(module => (module.target_types || []).includes(type));
    if (!type) { box.append(make('div', 'empty-inline', 'Select a target type to see compatible modules.')); return; }
    if (!compatible.length) { box.append(make('div', 'empty-inline', 'No registered modules support this target type.')); return; }
    compatible.forEach(module => {
      const row = make('div', 'compatible-item');
      row.append(make('span', '', module.name));
      row.append(make('small', '', module.available ? 'Available' : 'Unavailable'));
      box.append(row);
    });
  }

  function renderMetrics() {
    $('#metric-modules').textContent = state.modules.length;
    $('#metric-available').textContent = state.modules.filter(module => module.available).length;
    $('#metric-active').textContent = state.jobs.filter(job => ['pending', 'running'].includes(String(job.status).toLowerCase())).length;
    $('#metric-completed').textContent = state.jobs.filter(job => String(job.status).toLowerCase() === 'completed').length;
  }

  function renderJobRows(container, jobs, history = false) {
    container.replaceChildren();
    if (!jobs.length) {
      const row = make('tr');
      const cell = make('td', 'table-empty', 'No investigation jobs found.');
      cell.colSpan = history ? 6 : 5;
      row.append(cell); container.append(row); return;
    }
    jobs.forEach(job => {
      const row = make('tr');
      row.append(make('td', 'target-cell', job.target_display || 'Unknown target'));
      row.append(make('td', 'type-cell', typeLabel(job.target_type)));
      const statusCell = make('td');
      statusCell.append(make('span', `status-pill ${statusClass(job.status)}`, prettyStatus(job.status)));
      row.append(statusCell);
      if (history) {
        const progressCell = make('td');
        const track = make('div', 'progress-mini');
        const fill = make('span'); fill.style.width = `${progressOf(job)}%`; track.append(fill); progressCell.append(track);
        row.append(progressCell);
      }
      row.append(make('td', '', dateLabel(job.created_at)));
      const actionCell = make('td');
      const completed = String(job.status).toLowerCase() === 'completed';
      const hasReport = Boolean(job.report_available);
      const action = make(
        'button',
        'table-action',
        completed ? (hasReport ? 'View report' : 'Import report') : 'View job'
      );
      action.type = 'button';

      if (completed && !hasReport) {
        const picker = make('input');
        picker.type = 'file';
        picker.accept = '.json,application/json';
        picker.className = 'hidden';
        picker.setAttribute('aria-label', 'Select a previously exported Sent Eye JSON report');

        picker.addEventListener('change', async () => {
          const file = picker.files && picker.files[0];
          picker.value = '';
          if (!file) return;

          if (file.size > 5 * 1024 * 1024) {
            toast('Report file exceeds the 5 MB limit.', true);
            return;
          }

          const formData = new FormData();
          formData.append('file', file, file.name);

          action.disabled = true;
          action.textContent = 'Importing…';

          try {
            await request(
              `/api/jobs/${encodeURIComponent(job.job_id)}/report.json`,
              { method: 'POST', body: formData }
            );
            toast('Previous report imported and archived successfully.');
            await loadJobs();
          } catch (error) {
            toast(`Could not import report: ${error.message}`, true);
          } finally {
            action.disabled = false;
            action.textContent = 'Import report';
          }
        });

        action.addEventListener('click', () => picker.click());
        actionCell.append(action, picker);
      } else {
        action.addEventListener('click', () => {
          if (completed) {
            openReport(job.job_id).catch(
              error => toast(`Could not load report: ${error.message}`, true)
            );
          } else {
            state.activeJobId = job.job_id;
            updateActiveJob(job);
            showView('investigate');
            $('#active-job-panel').classList.remove('hidden');
          }
        });
        actionCell.append(action);
      }

      row.append(actionCell);
      container.append(row);
    });
  }

  function renderJobs() {
    const jobs = [...state.jobs].sort((a, b) => Number(b.created_at || 0) - Number(a.created_at || 0));
    renderJobRows($('#recent-jobs'), jobs.slice(0, 5), false);
    renderJobRows($('#history-jobs'), jobs, true);
    $('#history-count').textContent = `${jobs.length} ${jobs.length === 1 ? 'job' : 'jobs'}`;
    renderMetrics();
  }

  function renderModules() {
    const available = state.modules.filter(module => module.available).length;
    $('#module-summary').replaceChildren();
    [['Registered', state.modules.length], ['Dependencies available', available], ['Need dependency setup', state.modules.length - available]].forEach(([label, value]) => {
      const chip = make('span', 'summary-chip'); chip.append(make('strong', '', value), document.createTextNode(label)); $('#module-summary').append(chip);
    });
    const grid = $('#module-grid'); grid.replaceChildren();
    if (!state.modules.length) { grid.append(make('div', 'panel module-loading', 'No modules were returned by the API.')); return; }
    state.modules.forEach(module => {
      const card = make('article', 'module-card');
      const top = make('div', 'module-card-top');
      top.append(make('div', 'module-name', module.name || 'Unnamed module'));
      top.append(make('span', `status-pill ${module.available ? 'status-completed' : 'status-failed'}`, module.available ? 'AVAILABLE' : 'UNAVAILABLE'));
      card.append(top);
      card.append(make('p', 'module-desc', module.description || 'No description provided by this module.'));
      const tags = make('div', 'module-targets');
      (module.target_types || []).forEach(type => tags.append(make('span', 'type-tag', typeLabel(type))));
      card.append(tags);
      const flags = make('div', 'module-flags');
      flags.append(make('span', 'module-flag', module.requires_key ? 'API key required' : 'No API key declared'));
      flags.append(make('span', 'module-flag', module.available ? 'Runtime dependencies detected' : 'Runtime dependency missing'));
      card.append(flags); grid.append(card);
    });
  }

  async function loadHealth() {
    try {
      state.health = await request('/health');
      setHealth(true, `Backend v${state.health.version || 'unknown'}`);
      if (state.health.version) $('#app-version').textContent = `v${state.health.version}`;
    } catch (error) { setHealth(false, error.message); }
  }

  async function loadModules() {
    try {
      state.modules = await request('/api/modules');
      renderTargetTypes(); renderModules(); renderMetrics();
    } catch (error) {
      $('#module-grid').replaceChildren(make('div', 'panel module-loading', `Could not load module registry: ${error.message}`));
      $('#quick-targets').replaceChildren(make('div', 'empty-inline', 'Module registry unavailable.'));
      $('#target-type').replaceChildren(Object.assign(make('option', '', 'Module registry unavailable'), { value: '' }));
      $('#target-type').disabled = true;
    }
  }

  async function loadJobs(showMessage = false) {
    try {
      state.jobs = await request('/api/jobs');
      renderJobs();
      if (state.activeJobId) {
        const active = state.jobs.find(job => job.job_id === state.activeJobId);
        if (active) updateActiveJob(active);
      }
    } catch (error) { if (showMessage) toast(`Could not refresh jobs: ${error.message}`, true); }
  }

  function setFormError(message) {
    const box = $('#form-error');
    box.textContent = message || '';
    box.classList.toggle('hidden', !message);
  }

  async function submitInvestigation(event) {
    event.preventDefault();
    setFormError('');
    const type = $('#target-type').value;
    const consent = $('#acknowledge-consent').checked;
    if (!type) return setFormError('Select a supported target type.');
    if (!consent) return setFormError('Confirm that you have permission and a lawful basis to investigate this target.');
    const form = new FormData();
    form.append('target_type', type);
    form.append('acknowledge_consent', 'true');
    form.append('analyze_faces', type === 'image' && $('#analyze-faces').checked ? 'true' : 'false');
    form.append('engines', $('#engines').value.trim());
    if (type === 'image') {
      const file = $('#target-file').files[0];
      if (!file) return setFormError('Choose an image file to investigate.');
      if (!file.type.startsWith('image/')) return setFormError('The selected file does not appear to be an image.');
      if (file.size > 20 * 1024 * 1024) return setFormError('The selected image exceeds the 20 MB request limit.');
      form.append('file', file, file.name);
    } else {
      const target = $('#target-value').value.trim();
      if (!target) return setFormError('Enter a target value.');
      if (target.length > 512) return setFormError('Target value must be 512 characters or fewer.');
      form.append('target', target);
    }
    const button = $('#submit-investigation');
    button.disabled = true;
    button.firstElementChild.textContent = 'Submitting…';
    try {
      const result = await request('/api/investigate', { method: 'POST', body: form });
      state.activeJobId = result.job_id;
      $('#active-job-panel').classList.remove('hidden');
      $('#active-job-target').textContent = type === 'image' ? `Uploaded image: ${$('#target-file').files[0].name}` : $('#target-value').value.trim();
      $('#active-job-status').className = 'status-pill status-pending';
      $('#active-job-status').textContent = 'PENDING';
      $('#active-job-progress').style.width = '0%';
      $('#active-job-step').textContent = 'Waiting for a worker…';
      $('#active-job-percent').textContent = '0%';
      $('#active-job-actions').classList.add('hidden');
      toast('Investigation submitted successfully.');
      await loadJobs();
      pollJob(result.job_id);
      $('#active-job-panel').scrollIntoView({ behavior: 'smooth', block: 'nearest' });
    } catch (error) {
      setFormError(error.message || 'Could not submit the investigation.');
    } finally {
      button.disabled = false;
      button.firstElementChild.textContent = 'Run investigation';
    }
  }

  function updateActiveJob(job) {
    if (!job || job.job_id !== state.activeJobId) return;
    const status = String(job.status || 'pending').toLowerCase();
    const progress = progressOf(job);
    $('#active-job-panel').classList.remove('hidden');
    $('#active-job-target').textContent = job.target_display || 'Investigation';
    $('#active-job-status').className = `status-pill ${statusClass(status)}`;
    $('#active-job-status').textContent = prettyStatus(status);
    $('#active-job-progress').style.width = `${progress}%`;
    $('#active-job-percent').textContent = `${progress}%`;
    const step = job.progress_module ? `Running module: ${job.progress_module} (${job.progress_current || 0}/${job.progress_total || 0})` : status === 'completed' ? 'All compatible modules finished.' : status === 'failed' ? (job.error || 'Investigation failed.') : status === 'running' ? 'Investigation is running…' : 'Waiting for a worker…';
    $('#active-job-step').textContent = step;
    const actions = $('#active-job-actions');
    actions.classList.toggle('hidden', status !== 'completed');
    if (status === 'failed') toast(job.error || 'Investigation failed.', true);
  }

  async function pollJob(jobId) {
    if (state.pollHandle) window.clearTimeout(state.pollHandle);
    const poll = async () => {
      try {
        const job = await request(`/api/jobs/${encodeURIComponent(jobId)}`);
        updateActiveJob(job);
        await loadJobs();
        const status = String(job.status || '').toLowerCase();
        if (status === 'completed') {
          toast('Investigation completed. Your report is ready.');
          openReport(jobId).catch(error => toast(`Could not load report: ${error.message}`, true));
          return;
        }
        if (status === 'failed' || status === 'cancelled') { toast(job.error || `Investigation ${status}.`, true); return; }
        state.pollHandle = window.setTimeout(poll, 1400);
      } catch (error) {
        toast(`Could not refresh investigation status: ${error.message}`, true);
        state.pollHandle = window.setTimeout(poll, 3000);
      }
    };
    await poll();
  }

  function appendReportBlock(parent, title, value) {
    if (
      value === undefined ||
      value === null ||
      value === '' ||
      (Array.isArray(value) && !value.length)
    ) return;

    const block = make('section', 'result-block');
    const humanize = key => String(key)
      .replace(/_/g, ' ')
      .replace(/\b\w/g, char => char.toUpperCase());

    const addText = (container, tag, cls, text) => {
      if (text === undefined || text === null || text === '') return;
      container.append(make(tag, cls, String(text)));
    };

    const addField = (container, label, value) => {
      if (value === undefined || value === null || value === '') return;

      const field = make('div', 'finding-field');
      field.append(make('span', 'finding-field-label', label));

      if (Array.isArray(value)) {
        const list = make('div', 'finding-value-list');
        value.forEach(item => {
          if (item === null || item === undefined) return;
          list.append(make('span', 'finding-chip',
            typeof item === 'object' ? JSON.stringify(item) : String(item)
          ));
        });
        field.append(list);
      } else if (typeof value === 'object') {
        const nested = make('div', 'finding-nested-card');
        Object.entries(value).forEach(([key, item]) => {
          if (item === null || item === undefined || item === '') return;
          addText(nested, 'p', 'finding-nested-line',
            `${humanize(key)}: ${Array.isArray(item) ? item.join(', ') : item}`
          );
        });
        field.append(nested);
      } else {
        field.append(make('span', 'finding-field-value', String(value)));
      }

      container.append(field);
    };

    const addStatus = (container, status) => {
      if (!status) return;
      const value = String(status).toLowerCase();
      const labels = {
        ok: 'Passed',
        breached: 'Exposure detected',
        none: 'Not found',
        warning: 'Warning',
        error: 'Error',
        skipped: 'Skipped'
      };
      const cls = ['ok', 'breached', 'none', 'warning', 'error', 'skipped']
        .includes(value) ? value : 'neutral';

      container.append(make(
        'span',
        `finding-status finding-status-${cls}`,
        labels[value] || humanize(value)
      ));
    };

    const findings = Array.isArray(value) ? value : [];
    const isEmailReport = title === 'Findings' &&
      findings.some(item => item?.check === 'xposedornot');

    block.append(make(
      'h4',
      '',
      title === 'Findings' ? 'Investigation findings' : humanize(title)
    ));

    if (title === 'Findings' && Array.isArray(value)) {
      findings.forEach((finding, index) => {
        if (!finding || typeof finding !== 'object') {
          addText(block, 'p', 'finding-detail', finding);
          return;
        }

        const check = String(finding.check || finding.name || '').toLowerCase();

        // Dedicated XposedOrNot breach intelligence report.
        if (check === 'xposedornot') {
          const card = make('article', 'finding-card breach-report-card');
          const heading = make('div', 'finding-card-heading');

          heading.append(make('strong', 'finding-title', 'Data breach intelligence'));
          addStatus(heading, finding.status);
          card.append(heading);

          addText(card, 'p', 'finding-detail', finding.detail);

          if (finding.status === 'breached') {
            const breaches = Array.isArray(finding.breaches)
              ? finding.breaches : [];

            const summary = make('div', 'finding-fields');
            addField(summary, 'Breach records found', finding.breach_count);
            addField(summary, 'Provider', finding.provider || 'XposedOrNot');
            card.append(summary);

            breaches.forEach(breach => {
              const item = make('div', 'finding-nested-card');

              addText(item, 'h4', 'finding-title',
                breach.title || breach.name || 'Reported data breach'
              );

              const details = make('div', 'finding-fields');
              addField(details, 'Reported year', breach.date);
              addField(details, 'Industry', breach.industry);
              addField(details, 'Password exposure type',
                breach.password_risk === 'plaintext'
                  ? 'Plaintext passwords'
                  : breach.password_risk
              );
              addField(details, 'Verification status', breach.verified);
              item.append(details);

              if (breach.description) {
                addText(item, 'p', 'finding-detail', breach.description);
              }

              if (Array.isArray(breach.data_classes) && breach.data_classes.length) {
                addText(item, 'p', 'finding-field-label', 'Information exposed');
                const chips = make('div', 'finding-value-list');
                breach.data_classes.forEach(type => {
                  chips.append(make('span', 'finding-chip', type));
                });
                item.append(chips);
              }

              if (Number.isFinite(Number(breach.pwn_count))) {
                addText(
                  item,
                  'p',
                  'finding-detail',
                  `Total records in this dataset: ${Number(breach.pwn_count).toLocaleString()}. This is the dataset-wide count, not the number of records belonging to the investigated email.`
                );
              }

              if (breach.reference_url) {
                const link = document.createElement('a');
                link.href = breach.reference_url;
                link.target = '_blank';
                link.rel = 'noopener noreferrer';
                link.textContent = 'View breach reference';
                item.append(link);
              }

              card.append(item);
            });

            if (finding.password_strength) {
              const password = make('div', 'finding-nested-card');
              addText(password, 'h4', 'finding-title', 'Password exposure analysis');

              const labels = {
                EasyToCrack: 'Easy-to-crack passwords',
                PlainText: 'Plaintext passwords',
                StrongHash: 'Strongly hashed passwords',
                Unknown: 'Unknown password format'
              };

              Object.entries(labels).forEach(([key, label]) => {
                addField(password, label, finding.password_strength[key] ?? 0);
              });

              card.append(password);
            }

            if (finding.risk) {
              const risk = make('div', 'finding-nested-card');
              addText(risk, 'h4', 'finding-title', 'Provider risk assessment');
              addField(risk, 'Risk classification', finding.risk.label);
              addField(risk, 'Risk score', finding.risk.score);
              card.append(risk);
            }

            addField(card, 'Paste records reported', finding.paste_count ?? 0);
          } else if (finding.status === 'ok') {
            addText(card, 'p', 'finding-detail',
              'No matching breach records were returned by the provider.'
            );
          } else if (finding.status === 'warning' || finding.status === 'error') {
            addText(card, 'p', 'finding-detail',
              'The breach intelligence lookup could not be completed successfully.'
            );
          }

          addText(card, 'p', 'finding-detail',
            finding.attribution || 'Breach intelligence provided by XposedOrNot.'
          );

          block.append(card);
          return;
        }

        // Friendly labels for other email checks.
        const names = {
          format: 'Email address validation',
          mx: 'Mail server configuration',
          gravatar: 'Public profile lookup'
        };

        const card = make('article', 'finding-card');
        const heading = make('div', 'finding-card-heading');

        heading.append(make(
          'strong',
          'finding-title',
          names[check] || humanize(finding.check || finding.name || `Finding ${index + 1}`)
        ));

        addStatus(heading, finding.status);
        card.append(heading);

        addText(card, 'p', 'finding-detail', finding.detail);

        if (check === 'mx' && Array.isArray(finding.records)) {
          addText(card, 'p', 'finding-field-label', 'Mail servers');

          finding.records.forEach(record => {
            addText(
              card,
              'p',
              'finding-nested-line',
              `${record.host || 'Unknown server'} · Priority ${record.priority ?? '—'}`
            );
          });
        }

        if (check === 'gravatar' && finding.url) {
          addText(card, 'p', 'finding-detail',
            'No public Gravatar profile was found for this address.'
          );
        }

        Object.entries(finding).forEach(([key, item]) => {
          if ([
            'check', 'name', 'status', 'category', 'detail',
            'records', 'url', 'provider'
          ].includes(key)) return;

          if (item === null || item === undefined || item === '') return;
          addField(card, humanize(key), item);
        });

        block.append(card);
      });
    } else if (value && typeof value === 'object' && !Array.isArray(value)) {
      const grid = make('div', 'finding-fields metadata-grid');

      Object.entries(value).forEach(([key, item]) => {
        if (item === null || item === undefined || item === '') return;

        const labels = {
          email: 'Email address',
          domain: 'Email domain',
          local: 'Account name',
          checks_run: 'Checks performed',
          is_role_account: 'Role-based address',
          is_disposable: 'Disposable address',
          breach_intel_provider: 'Breach intelligence provider'
        };

        let display = item;
        if (key === 'is_role_account' || key === 'is_disposable') {
          display = item ? 'Yes' : 'No';
        }

        addField(grid, labels[key] || humanize(key), display);
      });

      block.append(grid);
    } else if (Array.isArray(value)) {
      value.forEach((item, index) => addField(block, `Item ${index + 1}`, item));
    } else {
      addText(block, 'p', 'finding-detail', value);
    }

    parent.append(block);
  }

  function renderReport(report, jobId) {
    const content = $('#report-content'); content.replaceChildren();
    const results = report && report.results && typeof report.results === 'object' ? report.results : {};
    const entries = Object.entries(results);
    const summary = make('div', 'report-summary');
    [[ 'Target', report?.target || '—' ], [ 'Target type', typeLabel(report?.target_type) ], [ 'Modules run', Array.isArray(report?.modules_run) ? report.modules_run.length : entries.length ]].forEach(([label, value]) => {
      const item = make('div', 'report-summary-card'); item.append(make('small', '', label), make('strong', '', value)); summary.append(item);
    });
    content.append(summary);
    if (!entries.length) {
      const empty = make('div', 'report-empty', 'The report was returned, but it contains no module result entries. You can still download the raw JSON report.');
      content.append(empty);
    }
    entries.forEach(([name, result]) => {
      const card = make('article', 'result-card');
      const head = make('div', 'result-card-head');
      head.append(make('strong', '', name));
      head.append(make('span', `status-pill ${String(result?.status || '').toLowerCase() === 'success' || String(result?.status || '').toLowerCase() === 'completed' ? 'status-completed' : String(result?.status || '').toLowerCase() === 'error' || String(result?.status || '').toLowerCase() === 'failed' ? 'status-failed' : 'status-running'}`, prettyStatus(result?.status || 'result')));
      card.append(head);
      const body = make('div', 'result-card-body');
      if (result?.description) body.append(make('p', 'result-description', result.description));
      appendReportBlock(body, 'Findings', result?.findings);
      appendReportBlock(body, 'Metadata', result?.metadata);
      appendReportBlock(body, 'Warnings', result?.warnings);
      appendReportBlock(body, 'Errors', result?.errors);
      if (!body.childNodes.length) appendReportBlock(body, 'Result', result);
      card.append(body); content.append(card);
    });
    if (!entries.length && report && typeof report === 'object') appendReportBlock(content, 'Raw report', report);
    state.reportJobId = jobId;
    $('#report-subtitle').textContent = `Target: ${report?.target || 'Investigation'} · ${typeLabel(report?.target_type)}`;
    $('#report-title').textContent = 'Investigation report';
    $('#report-status').textContent = 'COMPLETED';
    $('#report-status').className = 'status-pill status-completed';
    $('#report-modal').classList.remove('hidden');
    document.body.style.overflow = 'hidden';
  }

  async function openReport(jobId) {
    const report = await request(`/api/jobs/${encodeURIComponent(jobId)}/report.json`);
    renderReport(report, jobId);
  }

  function closeReport() {
    $('#report-modal').classList.add('hidden');
    document.body.style.overflow = '';
  }

  function downloadReport(format) {
    if (!state.reportJobId) return;
    const anchor = document.createElement('a');
    anchor.href = `/api/jobs/${encodeURIComponent(state.reportJobId)}/report.${format}`;
    anchor.target = format === 'html' ? '_blank' : '_self';
    if (format === 'json') anchor.download = `sent-eye-${state.reportJobId}.json`;
    document.body.append(anchor); anchor.click(); anchor.remove();
  }


  // ----------------------------------------------------------
  // ADMINISTRATION WORKSPACE
  // ----------------------------------------------------------

  function adminStatusClass(status) {
    const value = String(status || '').toLowerCase();
    if (value === 'approved' || value === 'completed') return 'status-completed';
    if (value === 'pending' || value === 'running') return 'status-pending';
    return 'status-failed';
  }

  function adminStatusPill(status) {
    return make(
      'span',
      `status-pill ${adminStatusClass(status)}`,
      prettyStatus(status)
    );
  }

  function adminCell(row, value, className = '') {
    row.append(make('td', className, value ?? '—'));
  }

  function adminAction(label, callback, extraClass = '') {
    const button = make('button', `admin-row-action ${extraClass}`.trim(), label);
    button.type = 'button';
    button.addEventListener('click', async () => {
      button.disabled = true;
      try {
        await callback();
      } catch (error) {
        toast(error.message || 'Administrator action failed.', true);
      } finally {
        button.disabled = false;
      }
    });
    return button;
  }

  function renderAdminOverview() {
    const overview = state.adminOverview;
    if (!overview) return;

    const metrics = [
      ['REGISTERED USERS', overview.users.total],
      ['PENDING APPROVALS', overview.users.pending],
      ['INVESTIGATIONS', overview.investigations.total],
      ['ACTIVE SESSIONS', overview.active_sessions]
    ];

    const container = $('#admin-metrics');
    container.replaceChildren();

    metrics.forEach(([label, value]) => {
      const card = make('article', 'metric-card');
      card.append(
        make('div', 'metric-label', label),
        make('div', 'metric-value', value ?? 0)
      );
      container.append(card);
    });

    const login = overview.login_attempts_24h || {};
    const usage = overview.module_usage_24h || {};
    const summary = $('#admin-security-summary');
    summary.replaceChildren();

    [
      ['Failed sign-ins · 24h', login.failed || 0],
      ['Successful sign-ins · 24h', login.succeeded || 0],
      ['Module executions · 24h', usage.total || 0],
      ['Failed module executions · 24h', usage.failed || 0],
      ['Completed investigations', overview.investigations.completed || 0],
      ['Failed investigations', overview.investigations.failed || 0]
    ].forEach(([label, value]) => {
      const item = make('div', 'admin-security-item');
      item.append(
        make('span', 'admin-security-label', label),
        make('strong', '', value)
      );
      summary.append(item);
    });
  }

  async function adminChangeStatus(user, status) {
    const verb = status === 'approved'
      ? 'approve or reactivate'
      : status;

    if (!window.confirm(`Are you sure you want to ${verb} ${user.email}?`)) return;

    await request(
      `/api/admin/users/${encodeURIComponent(user.user_id)}/status`,
      {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ status })
      }
    );

    toast(`Account status updated: ${status}.`);
    await loadAdminData();
  }

  async function adminChangeRole(user) {
    if (user.user_id === state.currentUser?.user_id) {
      toast('You cannot change your own administrator role.', true);
      return;
    }

    const role = user.role === 'admin' ? 'user' : 'admin';
    if (!window.confirm(
      `Change ${user.email} to ${role}? Their active sessions will be revoked.`
    )) return;

    await request(
      `/api/admin/users/${encodeURIComponent(user.user_id)}/role`,
      {
        method: 'PUT',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ role })
      }
    );

    toast(`Account role changed to ${role}.`);
    await loadAdminData();
  }

  function renderAdminUsers() {
    const body = $('#admin-users-table');
    const search = $('#admin-user-search').value.trim().toLowerCase();
    const statusFilter = $('#admin-user-status-filter').value;

    const filtered = state.adminUsers.filter(user => {
      const matchesSearch = !search ||
        String(user.full_name || '').toLowerCase().includes(search) ||
        String(user.email || '').toLowerCase().includes(search);

      return matchesSearch &&
        (!statusFilter || user.status === statusFilter);
    });

    $('#admin-user-count').textContent =
      `${filtered.length} of ${state.adminUsers.length} accounts`;

    body.replaceChildren();

    if (!filtered.length) {
      const row = make('tr');
      const cell = make('td', 'table-empty', 'No matching accounts found.');
      cell.colSpan = 6;
      row.append(cell);
      body.append(row);
    }

    filtered.forEach(user => {
      const row = make('tr');

      const account = make('td', 'admin-account-cell');
      account.append(
        make('strong', '', user.full_name || 'Unnamed account'),
        make('small', '', user.email || 'No email')
      );
      row.append(account);

      adminCell(row, String(user.role || 'user').toUpperCase());

      const status = make('td');
      status.append(adminStatusPill(user.status));
      row.append(status);

      adminCell(row, dateLabel(user.last_login_at));
      adminCell(row, dateLabel(user.created_at));

      const controls = make('td');
      const group = make('div', 'admin-control-group');
      const isAdmin = user.role === 'admin';
      const isSelf = user.user_id === state.currentUser?.user_id;

      if (!isAdmin) {
        if (user.status !== 'approved') {
          group.append(adminAction(
            user.status === 'pending' ? 'Approve' : 'Reactivate',
            () => adminChangeStatus(user, 'approved'),
            'admin-action-positive'
          ));
        }

        if (user.status === 'approved') {
          group.append(adminAction(
            'Suspend',
            () => adminChangeStatus(user, 'suspended'),
            'admin-action-danger'
          ));
        } else if (user.status === 'pending') {
          group.append(adminAction(
            'Reject',
            () => adminChangeStatus(user, 'rejected'),
            'admin-action-danger'
          ));
        }
      }

      if (!isSelf) {
        group.append(adminAction(
          isAdmin ? 'Make user' : 'Make admin',
          () => adminChangeRole(user),
          isAdmin ? 'admin-action-danger' : ''
        ));
      }

      if (!group.childNodes.length) {
        group.append(make('span', 'admin-muted', 'Protected account'));
      }

      controls.append(group);
      row.append(controls);
      body.append(row);
    });

    renderAdminPermissionUserSelect();
  }

  function renderAdminPermissionUserSelect() {
    const select = $('#admin-permission-user');
    const previous = state.selectedAdminUserId || select.value;

    select.replaceChildren();
    const prompt = make('option', '', 'Select a standard user account');
    prompt.value = '';
    select.append(prompt);

    state.adminUsers
      .filter(user => user.role !== 'admin')
      .forEach(user => {
        const option = make(
          'option',
          '',
          `${user.full_name || user.email} · ${user.status}`
        );
        option.value = user.user_id;
        select.append(option);
      });

    const valid = state.adminUsers.some(
      user => user.user_id === previous && user.role !== 'admin'
    );

    select.value = valid ? previous : '';
    state.selectedAdminUserId = select.value;
    renderAdminPermissionEditor(select.value);
  }

  function renderAdminPermissionEditor(userId) {
    const editor = $('#admin-permission-editor');
    const grid = $('#admin-permission-grid');
    const user = state.adminUsers.find(item => item.user_id === userId);

    grid.replaceChildren();
    editor.classList.toggle('hidden', !user);
    if (!user) return;

    $('#admin-permission-title').textContent =
      `Module permissions · ${user.full_name || user.email}`;
    $('#admin-permission-description').textContent =
      `Configure access for ${user.email}. Existing consent requirements still apply.`;

    const permissions = new Map(
      (user.module_permissions || []).map(item => [item.module_name, item])
    );

    state.modules.forEach(module => {
      const permission = permissions.get(module.name) || {};
      const card = make('article', 'admin-permission-card');
      card.dataset.moduleName = module.name;
      card.setAttribute('data-permission-card', '');

      const heading = make('div', 'admin-permission-card-head');
      heading.append(
        make('strong', '', String(module.name).replace(/[_-]/g, ' '))
      );

      const toggleLabel = make('label', 'admin-permission-toggle');
      const enabled = make('input');
      enabled.type = 'checkbox';
      enabled.checked = Boolean(permission.enabled);
      enabled.setAttribute('data-permission-enabled', '');
      toggleLabel.append(enabled, make('span', '', 'Enabled'));
      heading.append(toggleLabel);
      card.append(heading);

      card.append(make(
        'p',
        'admin-permission-description',
        module.description || 'No module description available.'
      ));

      if (module.sensitive) {
        card.append(make(
          'span',
          'admin-sensitive-label',
          'Sensitive capability · existing consent controls apply'
        ));
      }

      const quotas = make('div', 'admin-quota-grid');

      [
        ['daily', 'Daily quota', permission.daily_limit],
        ['monthly', 'Monthly quota', permission.monthly_limit]
      ].forEach(([key, label, value]) => {
        const field = make('label', 'admin-quota-field');
        field.append(make('span', '', label));

        const input = make('input');
        input.type = 'number';
        input.min = '0';
        input.step = '1';
        input.placeholder = 'Unlimited';
        input.value = value === null || value === undefined ? '' : value;
        input.dataset.quota = key;

        field.append(input);
        quotas.append(field);
      });

      card.append(quotas);
      grid.append(card);
    });
  }

  async function saveAdminPermissions() {
    const userId = state.selectedAdminUserId;
    if (!userId) {
      toast('Select a user account first.', true);
      return;
    }

    const cards = $$('[data-permission-card]', $('#admin-permission-grid'));
    const updates = [];

    for (const card of cards) {
      const enabled = card.querySelector('[data-permission-enabled]');
      const dailyInput = card.querySelector('[data-quota="daily"]');
      const monthlyInput = card.querySelector('[data-quota="monthly"]');

      function readQuota(input, label) {
        const raw = input.value.trim();
        if (!raw) return null;

        const value = Number(raw);
        if (!Number.isSafeInteger(value) || value < 0) {
          throw new Error(`${label} must be a whole non-negative number.`);
        }
        return value;
      }

      updates.push({
        module: card.dataset.moduleName,
        payload: {
          enabled: enabled.checked,
          daily_limit: readQuota(dailyInput, 'Daily quota'),
          monthly_limit: readQuota(monthlyInput, 'Monthly quota')
        }
      });
    }

    const button = $('#admin-save-permissions');
    button.disabled = true;
    button.textContent = 'Saving permissions…';

    try {
      // Sequential SQLite writes avoid concurrent permission updates.
      for (const update of updates) {
        await request(
          `/api/admin/users/${encodeURIComponent(userId)}/modules/${encodeURIComponent(update.module)}`,
          {
            method: 'PUT',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify(update.payload)
          }
        );
      }

      toast('Module permissions and quotas saved.');
      await loadAdminData();
    } finally {
      button.disabled = false;
      button.textContent = 'Save module permissions';
    }
  }

  function renderAdminInvestigations() {
    const body = $('#admin-investigations-table');
    const records = state.adminInvestigations || [];

    body.replaceChildren();
    $('#admin-investigation-count').textContent =
      `${records.length} investigations`;

    if (!records.length) {
      const row = make('tr');
      const cell = make('td', 'table-empty', 'No investigations found.');
      cell.colSpan = 6;
      row.append(cell);
      body.append(row);
      return;
    }

    records.forEach(item => {
      const row = make('tr');
      adminCell(row, item.target_display, 'target-cell');
      adminCell(row, item.email || item.full_name || 'Unknown account');
      adminCell(row, typeLabel(item.target_type));

      const status = make('td');
      status.append(adminStatusPill(item.status));
      row.append(status);

      adminCell(row, dateLabel(item.created_at));

      const report = make('td');
      if (item.report_available) {
        report.append(adminAction(
          'View report',
          () => openReport(item.job_id)
        ));
      } else {
        report.append(make('span', 'admin-muted', 'Not archived'));
      }

      row.append(report);
      body.append(row);
    });
  }

  function sanitizeAuditDetails(value) {
    if (Array.isArray(value)) {
      return value.map(sanitizeAuditDetails);
    }

    if (!value || typeof value !== 'object') return value;

    const clean = {};
    Object.entries(value).forEach(([key, item]) => {
      if (/password|token|secret|hash|_key/i.test(key)) return;
      clean[key] = sanitizeAuditDetails(item);
    });
    return clean;
  }

  function renderAdminAudit() {
    const body = $('#admin-audit-table');
    const records = state.adminAudit || [];

    body.replaceChildren();
    $('#admin-audit-count').textContent = `${records.length} events`;

    if (!records.length) {
      const row = make('tr');
      const cell = make('td', 'table-empty', 'No audit events found.');
      cell.colSpan = 5;
      row.append(cell);
      body.append(row);
      return;
    }

    records.forEach(item => {
      const row = make('tr');
      adminCell(row, dateLabel(item.created_at));
      adminCell(row, String(item.event_type || '').replace(/[._]/g, ' '));
      adminCell(row, item.actor_email || 'System');
      adminCell(row, item.subject_email || '—');

      const details = sanitizeAuditDetails(item.details || {});
      const detailText = Object.keys(details).length
        ? safeJson(details)
        : 'No additional details';

      adminCell(
        row,
        detailText.length > 180
          ? detailText.slice(0, 177) + '…'
          : detailText
      );

      body.append(row);
    });
  }

  async function loadAdminData() {
    if (state.currentUser?.role !== 'admin') return;

    try {
      const [overview, users, investigations, audit] = await Promise.all([
        request('/api/admin/overview'),
        request('/api/admin/users'),
        request('/api/admin/investigations?limit=200'),
        request('/api/admin/audit?limit=200')
      ]);

      state.adminOverview = overview;
      state.adminUsers = Array.isArray(users) ? users : [];
      state.adminInvestigations = Array.isArray(investigations)
        ? investigations : [];
      state.adminAudit = Array.isArray(audit) ? audit : [];

      renderAdminOverview();
      renderAdminUsers();
      renderAdminInvestigations();
      renderAdminAudit();
    } catch (error) {
      toast(`Could not load administrator data: ${error.message}`, true);
    }
  }

  function selectAdminTab(name) {
    $$('[data-admin-tab]').forEach(button => {
      const active = button.dataset.adminTab === name;
      button.classList.toggle('active', active);
      button.setAttribute('aria-selected', String(active));
    });

    $$('.admin-tab-panel').forEach(panel => {
      panel.classList.toggle(
        'active',
        panel.id === `admin-panel-${name}`
      );
    });

    if (name === 'permissions') {
      renderAdminPermissionEditor(state.selectedAdminUserId);
    }
  }

  function bindEvents() {
    $$('.nav-link').forEach(button => button.addEventListener('click', () => showView(button.dataset.view)));
    $$('[data-go]').forEach(button => button.addEventListener('click', () => showView(button.dataset.go)));
    $('#target-type').addEventListener('change', updateTargetFields);
    $('#target-file').addEventListener('change', () => {
      const file = $('#target-file').files[0];
      $('#file-name').textContent = file ? `${file.name} · ${(file.size / 1024 / 1024).toFixed(2)} MB` : 'Maximum request size: 20 MB';
    });
    $('#investigation-form').addEventListener('submit', submitInvestigation);
    $('#refresh-history').addEventListener('click', () => loadJobs(true));
    $('#refresh-modules').addEventListener('click', async () => { await loadModules(); toast('Module registry refreshed.'); });
    $('#view-active-report').addEventListener('click', () => state.activeJobId && openReport(state.activeJobId).catch(error => toast(error.message, true)));
    $('#download-active-json').addEventListener('click', () => { state.reportJobId = state.activeJobId; downloadReport('json'); });
    $('#open-active-html').addEventListener('click', () => { state.reportJobId = state.activeJobId; downloadReport('html'); });
    $('#close-report').addEventListener('click', closeReport);
    $('#report-modal').addEventListener('click', event => { if (event.target === $('#report-modal')) closeReport(); });
    $('#report-download-json').addEventListener('click', () => downloadReport('json'));
    $('#report-open-html').addEventListener('click', () => downloadReport('html'));

    $('#admin-refresh').addEventListener('click', loadAdminData);

    $$('[data-admin-tab]').forEach(button => {
      button.addEventListener('click', () => {
        selectAdminTab(button.dataset.adminTab);
      });
    });

    $('#admin-user-search').addEventListener('input', renderAdminUsers);
    $('#admin-user-status-filter').addEventListener('change', renderAdminUsers);

    $('#admin-permission-user').addEventListener('change', event => {
      state.selectedAdminUserId = event.target.value;
      renderAdminPermissionEditor(state.selectedAdminUserId);
    });

    $('#admin-save-permissions').addEventListener('click', () => {
      saveAdminPermissions().catch(error => {
        toast(`Could not save module permissions: ${error.message}`, true);
      });
    });

    document.addEventListener('keydown', event => { if (event.key === 'Escape') closeReport(); });
  }

  async function init() {
    bindEvents();
    bindAuthEvents();
    await loadHealth();

    try {
      // Check for an existing session before showing the workspace.
      const session = await request('/api/auth/me');

      if (!session.user || !session.csrf_token || session.csrf_token.length < 32) {
        throw new Error('Session security data is missing. Please sign in again.');
      }

      state.csrfToken = session.csrf_token;
      await activateWorkspace(session.user);
    } catch (error) {
      if (error.status === 401) {
        try {
          await ensureCsrfToken(true);
          showAuthScreen();
        } catch (csrfError) {
          showAuthScreen(csrfError.message, true);
        }
      } else {
        showAuthScreen(error.message || 'Could not verify your session.', true);
      }
    }

    if (state.healthInterval === null) {
      state.healthInterval = window.setInterval(() => loadHealth(), 30000);
    }
  }

  document.addEventListener('DOMContentLoaded', init);
})();
