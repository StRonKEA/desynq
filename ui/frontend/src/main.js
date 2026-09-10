import {
  Load, Check, TestOne, RemoveHost, ActivateHost, SetScope,
  Install, Start, Stop, Refresh, Remove, PinDNS, UnpinDNS, ApplyDNSMode, CancelJob,
  Options, SaveOptions, SetAutostart, InstalledStrategy, Quit, LogError, ApplyPreset,
} from '../wailsjs/go/main/App';
import {
  EventsOn, WindowMinimise, WindowToggleMaximise, WindowHide,
} from '../wailsjs/runtime/runtime';
import { t, currentLang, setLanguage, initLanguage } from './i18n';

initLanguage();

/* Safe DOM builder */
const el = (tag, props = {}, kids = []) => {
  const n = document.createElement(tag);
  for (const [k, v] of Object.entries(props)) {
    if (k === 'class') n.className = v;
    else if (k === 'text') n.textContent = v;
    else if (k === 'on') for (const [ev, fn] of Object.entries(v)) n.addEventListener(ev, fn);
    else if (v !== null && v !== undefined && v !== false) n.setAttribute(k, v);
  }
  for (const kid of [].concat(kids)) if (kid) n.append(kid);
  return n;
};

const $ = (id) => document.getElementById(id);

const svg = (d, size = 16, strokeWidth = '1.5', fill = 'none') => {
  const s = document.createElementNS('http://www.w3.org/2000/svg', 'svg');
  s.setAttribute('viewBox', '0 0 24 24');
  s.setAttribute('width', size);
  s.setAttribute('height', size);
  s.setAttribute('fill', fill);
  s.setAttribute('stroke', 'currentColor');
  s.setAttribute('stroke-width', strokeWidth);
  s.setAttribute('stroke-linecap', 'round');
  s.setAttribute('stroke-linejoin', 'round');
  s.setAttribute('aria-hidden', 'true');
  const p = document.createElementNS('http://www.w3.org/2000/svg', 'path');
  p.setAttribute('d', d);
  s.append(p);
  return s;
};

/* URL & Hostname Normalizer */
function cleanHost(val) {
  if (!val) return '';
  let h = val.trim().toLowerCase();
  h = h.replace(/^[a-zA-Z]+:\/\//, ''); // strip protocol (http://, https://, etc.)
  h = h.split('/')[0]; // strip path
  h = h.split('?')[0]; // strip query
  h = h.split('#')[0]; // strip fragment
  h = h.split(':')[0]; // strip port
  return h;
}

/* Application State */
let snap = null;
let options = null;
let view = 'home'; // 'home' | 'settings'
let busy = false;
let busyTitle = 'Çalışıyor...';
let busySub = '';
let busyLogs = [];
let fullBusy = false; // true when blocking whole UI (Install, Search), false for mini job banner
let showLogDetail = false;
let addOpen = false;
let installedStrategyName = '';
let isOnline = typeof navigator !== 'undefined' ? navigator.onLine : true;

const JOB_TITLES = {
  installing: 'Engel yöntemi aranıyor ve kuruluyor',
  refreshing: 'Adresler güncelleniyor',
  removing: 'Kaldırılıyor',
  'pinning DNS': 'Adresler düzeltiliyor',
  'unpinning DNS': 'Adres düzeltmesi kaldırılıyor',
};

let dohProvider = 'cf';
let customDohUrl = '';
let customDohIP = '';
try {
  dohProvider = localStorage.getItem('dpi.dohProvider') || 'cf';
  customDohUrl = localStorage.getItem('dpi.customDohUrl') || '';
  customDohIP = localStorage.getItem('dpi.customDohIP') || '';
} catch (_) { /* ignore */ }

function saveDohPrefs() {
  try {
    localStorage.setItem('dpi.dohProvider', dohProvider);
    localStorage.setItem('dpi.customDohUrl', customDohUrl);
    localStorage.setItem('dpi.customDohIP', customDohIP);
  } catch (_) { /* ignore */ }
}

/* Error logging helper */
function logErr(source, err) {
  const msg = (err && err.message) ? err.message : String(err);
  console.error(`[${source}]`, err);
  if (isWails && window.go && window.go.main && window.go.main.App && window.go.main.App.LogError) {
    try {
      LogError(source, msg);
    } catch (_) { /* ignore */ }
  }
  return msg;
}

/* Unified Bottom Notification Banner */
let bannerTimeout = null;

function showBanner(text, type = 'info', onAction = null) {
  const b = $('jobBanner');
  const t = $('jobBannerText');
  const spin = $('jobSpinner');
  const icon = $('jobIcon');
  const btn = $('jobActionBtn');
  if (!b || !t) return;

  if (bannerTimeout) {
    clearTimeout(bannerTimeout);
    bannerTimeout = null;
  }

  t.textContent = text;
  b.className = `job-banner ${type}`;

  if (type === 'progress') {
    if (spin) spin.style.display = 'block';
    if (icon) icon.style.display = 'none';
    if (btn) {
      btn.textContent = 'İptal';
      btn.style.display = onAction ? 'inline-block' : 'none';
      btn.onclick = onAction;
    }
  } else {
    if (spin) spin.style.display = 'none';
    if (icon) {
      icon.innerHTML = '';
      icon.style.display = 'block';
      if (type === 'error') {
        const errSvg = svg('M12 9v2m0 4h.01m-6.938 4h13.856c1.54 0 2.502-1.667 1.732-3L13.732 4c-.77-1.333-2.694-1.333-3.464 0L3.34 16c-.77 1.333.192 3 1.732 3z', 15, '2');
        errSvg.style.stroke = '#ef4444';
        icon.append(errSvg);
      } else {
        const okSvg = svg('M3 8.5l3.5 3.5L13 4', 14, '2.5');
        okSvg.setAttribute('viewBox', '0 0 16 16');
        okSvg.style.stroke = '#4ade80';
        icon.append(okSvg);
      }
    }
    if (btn) {
      btn.textContent = 'Kapat';
      btn.style.display = 'inline-block';
      btn.onclick = () => hideBanner();
    }
    bannerTimeout = setTimeout(() => {
      hideBanner();
    }, type === 'error' ? 8000 : 3200);
  }

  b.hidden = false;
}

function hideBanner() {
  const b = $('jobBanner');
  if (b) b.hidden = true;
  if (bannerTimeout) {
    clearTimeout(bannerTimeout);
    bannerTimeout = null;
  }
}

// Unified alias for toast & jobBanner
function toast(msg, isError = false) {
  showBanner(msg, isError ? 'error' : 'success');
}

function showJobBanner(text, cancelFn = null) {
  showBanner(text, 'progress', cancelFn);
}

function hideJobBanner() {
  const b = $('jobBanner');
  if (b && b.classList.contains('progress')) {
    hideBanner();
  }
}

if (typeof window !== 'undefined') {
  window.addEventListener('error', (ev) => {
    const msg = ev.message || (ev.error && ev.error.message) || 'Bilinmeyen hata';
    logErr('window.error', `${msg} (${ev.filename || 'app'}:${ev.lineno || 0})`);
    showBanner(`Hata: ${msg}`, 'error');
  });
  window.addEventListener('unhandledrejection', (ev) => {
    const msg = (ev.reason && ev.reason.message) || String(ev.reason) || 'İşlem hatası';
    logErr('unhandledrejection', msg);
    showBanner(`Hata: ${msg}`, 'error');
  });
}

/* State helpers & Mock fallback for preview */
const isWails = typeof window !== 'undefined' && !!(window.go && window.go.main && window.go.main.App);

const mockSnap = {
  installed: true,
  running: true,
  allTraffic: false,
  dnsMode: 'hosts',
  configured: true,
  sites: [
    { host: 'discord.com', measured: true, system: 'OK' },
    { host: 'github.com', measured: true, system: 'OK' },
    { host: 'medium.com', measured: true, system: 'OK' },
  ],
  report: { chosen: 'split2+disorder' },
};
const mockOptions = {
  dnsMode: 'hosts',
  allTraffic: false,
  serviceName: 'dpi',
  autostart: true,
};

function safeEventsOn(name, cb) {
  if (typeof window !== 'undefined' && window.runtime && window.runtime.EventsOnMultiple) {
    EventsOn(name, cb);
  }
}

function isOn() {
  if (!snap) return false;
  return !!snap.installed || !!snap.dnsDiverter || (snap.sites && snap.sites.some((s) => s.pinned));
}

function isFirstRun() {
  if (!snap) return false;
  if (snap.installed || snap.running) return false;
  return !snap.configured;
}

function getBadSites() {
  if (!snap || !snap.sites) return [];
  return snap.sites.filter((s) => s.measured && s.system && s.system !== 'OK');
}

/* Load snapshots & strategy */
let lastRenderDigest = '';

async function reload(check = false) {
  if (!isWails) {
    snap = mockSnap;
    options = mockOptions;
    installedStrategyName = 'split2+disorder';
    render();
    return;
  }
  try {
    snap = check ? await Check() : await Load();
    try {
      options = await Options();
    } catch (_) { /* ignore */ }
    try {
      const stages = await InstalledStrategy();
      if (stages && stages.length > 0) {
        installedStrategyName = stages.join('+');
      } else if (snap && snap.report && snap.report.chosen) {
        installedStrategyName = snap.report.chosen;
      }
    } catch (_) { /* ignore */ }
  } catch (err) {
    const msg = logErr('reload', err);
    toast('Durum okunamadı: ' + msg, true);
  }

  // Dirty check: if visual state is identical and not forced check, do not destroy active DOM
  const digest = JSON.stringify({
    inst: snap?.installed,
    run: snap?.running,
    all: snap?.allTraffic,
    dns: snap?.dnsMode,
    div: snap?.dnsDiverter,
    sites: snap?.sites?.map((s) => s.host + ':' + s.system + ':' + s.pinned),
    strat: installedStrategyName,
    on: isOnline,
    view,
  });

  if (!check && !busy && view === 'home' && digest === lastRenderDigest) {
    return;
  }
  lastRenderDigest = digest;
  render();
}

/* Main Render Dispatcher */
function render() {
  const page = $('page');
  if (!page) return;

  const setBtn = $('settingsBtn');
  if (setBtn) {
    setBtn.style.display = (isFirstRun() || (busy && fullBusy)) ? 'none' : '';
  }

  if (busy && fullBusy) {
    page.innerHTML = '';
    page.append(renderBusyView());
    return;
  }

  if (view === 'settings') {
    page.innerHTML = '';
    page.append(renderSettingsView());
    return;
  }

  if (isFirstRun()) {
    const alreadyFirstRun = page.querySelector('.first-run-content');
    if (alreadyFirstRun) {
      // User is on first-run screen; never wipe DOM or active input!
      return;
    }
    page.innerHTML = '';
    page.append(renderFirstRunView());
    return;
  }

  page.innerHTML = '';
  page.append(renderHomeView());
}

/* 1. First Run View (Dropdown / Select Architecture) */
let selectedProfile = 'vodafone';
let firstRunHost = '';

function renderFirstRunView() {
  const container = el('div', { class: 'first-run-content' });
  const h1 = el('h1', { class: 'heading', text: t('first_run_title') });
  const p = el('p', { class: 'sub', text: t('first_run_sub') });

  const label = el('div', {
    class: 'scope-label',
    style: 'align-self:flex-start;margin-bottom:.375rem;font-size:.75rem',
    text: t('select_isp_label'),
  });

  const select = el('select', {
    class: 'field',
    style: 'cursor:pointer;font-weight:600;margin-bottom:1rem',
    on: {
      change: (e) => {
        selectedProfile = e.target.value;
        updatePreview();
      },
    },
  }, [
    el('option', { value: 'vodafone', text: t('profile_vodafone_title') }),
    el('option', { value: 'turkcell', text: t('profile_turkcell_title') }),
    el('option', { value: 'turknet', text: t('profile_turknet_title') }),
    el('option', { value: 'custom', text: t('custom_scan_title') }),
  ]);
  select.value = selectedProfile;

  const descBox = el('div', { class: 'profile-desc-box' });
  const badge = el('div', { class: 'desc-badge' });
  const descText = el('div', { class: 'desc-text' });
  descBox.append(badge, descText);

  // Deploy button for instant profiles
  const profileBtn = el('button', {
    class: 'btn-primary full',
    text: t('apply_profile_btn'),
    on: {
      click: async () => {
        if (busy) return;
        const profileName = selectedProfile === 'vodafone' ? 'Vodafone Mobil' : (selectedProfile === 'turkcell' ? 'Turkcell Mobil' : 'TurkNet');
        showBanner(`${profileName}...`, 'progress');
        busy = true;
        try {
          const err = await ApplyPreset(selectedProfile);
          if (err) {
            logErr('ApplyPreset', err);
            toast(err, true);
          } else {
            toast(t('prot_on'));
          }
        } catch (e) {
          const msg = logErr('ApplyPreset', e);
          toast(msg, true);
        } finally {
          busy = false;
          hideJobBanner();
          await reload(false);
        }
      },
    },
  });

  // Custom scan input & elements
  const customInput = el('input', {
    type: 'text',
    class: 'field',
    placeholder: t('first_run_input_placeholder'),
    value: firstRunHost,
    on: { input: (e) => { firstRunHost = e.target.value; } },
  });
  const customHint = el('div', {
    style: 'font-size:.8125rem;color:var(--ink-3);margin-top:-.25rem;margin-bottom:1rem;text-align:left;width:100%',
    text: t('scan_hint'),
  });
  const customBtn = el('button', {
    class: 'btn-primary full',
    text: t('scan_and_install_btn'),
    on: {
      click: async () => {
        if (busy) return;
        const host = cleanHost(customInput.value);
        if (!host) {
          toast(t('valid_domain_warn'), true);
          customInput.focus();
          return;
        }
        fullBusy = true;
        busy = true;
        busyTitle = t('first_run_title');
        busySub = t('uac_hint');
        busyLogs = [`probing ${host}...`];
        render();
        try {
          await ActivateHost(host);
          const res = await Install();
          if (res) {
            logErr('Install', res);
            toast(res, true);
          }
        } catch (e) {
          const msg = logErr('FirstRun', e);
          toast(msg, true);
        } finally {
          fullBusy = false;
          busy = false;
          await reload(true);
        }
      },
    },
  });
  customInput.addEventListener('keydown', (e) => {
    if (e.key === 'Enter') customBtn.click();
  });

  const customContainer = el('div', { style: 'width:100%;display:none' }, [customInput, customHint, customBtn]);

  function updatePreview() {
    if (selectedProfile === 'vodafone' || selectedProfile === 'turkcell') {
      badge.textContent = 'DPI + DNS (multidisorder)';
      descText.textContent = selectedProfile === 'vodafone' ? t('profile_vodafone_desc') : t('profile_turkcell_desc');
      descBox.style.display = 'flex';
      profileBtn.style.display = 'inline-flex';
      customContainer.style.display = 'none';
    } else if (selectedProfile === 'turknet') {
      badge.textContent = 'DNS (Transparent DoH)';
      descText.textContent = t('profile_turknet_desc');
      descBox.style.display = 'flex';
      profileBtn.style.display = 'inline-flex';
      customContainer.style.display = 'none';
    } else {
      badge.textContent = 'Custom Scan';
      descText.textContent = t('custom_scan_desc');
      descBox.style.display = 'flex';
      profileBtn.style.display = 'none';
      customContainer.style.display = 'block';
      setTimeout(() => customInput.focus(), 50);
    }
  }

  updatePreview();

  const selectWrap = el('div', { class: 'profile-select-box' }, [label, select]);
  container.append(h1, p, selectWrap, descBox, profileBtn, customContainer);
  return container;
}

/* 2. Full Busy View */
function renderBusyView() {
  const container = el('div', { class: 'busy-center' });
  const spinner = el('div', { class: 'spinner-ring' });

  // Parse logs for user-friendly progress
  let stepText = t('preparing');
  let progressDetail = '';
  for (const line of busyLogs) {
    if (line.includes('step 1/3')) {
      stepText = t('step1');
    } else if (line.includes('step 2/3')) {
      stepText = t('step2');
    } else if (line.includes('step 3/3')) {
      stepText = t('step3');
    }

    const mScreen = line.match(/screened\s+(\d+)\s+candidates/i);
    if (mScreen) {
      progressDetail = `${mScreen[1]} ${t('candidates_tested')}`;
    }
    const mChosen = line.match(/chosen:\s+([^\s]+)/i);
    if (mChosen) {
      progressDetail = `${t('chosen_method')} ${mChosen[1]}`;
    }
  }

  const titleText = JOB_TITLES[busyTitle] || busyTitle;
  const textDiv = el('div', {}, [
    el('h2', { style: 'margin:0 0 .25rem;font-size:1.25rem;font-weight:700', text: titleText }),
    el('p', {
      style: 'margin:0 0 .5rem;color:var(--ink-2);font-size:.875rem;max-width:340px',
      text: busySub || t('uac_hint'),
    }),
    el('div', { class: 'busy-progress-box' }, [
      el('div', { class: 'busy-step-badge', text: stepText }),
      progressDetail ? el('div', { class: 'busy-detail-text', text: progressDetail }) : null,
    ]),
  ]);

  const logBox = el('div', { class: 'log-preview', text: busyLogs.join('\n') });
  if (!showLogDetail) logBox.style.display = 'none';

  const actions = el('div', { class: 'busy-actions' }, [
    el('button', {
      class: 'btn-ghost',
      text: showLogDetail ? t('hide_details') : t('show_details'),
      on: {
        click: () => {
          showLogDetail = !showLogDetail;
          render();
        },
      },
    }),
    el('button', {
      class: 'btn-ghost',
      style: 'color:var(--bad)',
      text: t('cancel'),
      on: {
        click: async () => {
          try {
            await CancelJob();
          } catch (_) { /* ignore */ }
          fullBusy = false;
          busy = false;
          render();
        },
      },
    }),
  ]);

  container.append(spinner, textDiv, logBox, actions);
  return container;
}

/* 3. Home View (Handles: Stopped, Running Sites, Running All PC, Degraded Issues) */
function renderHomeView() {
  const frag = document.createDocumentFragment();
  const on = isOn();
  const badSites = getBadSites();
  const isFullPC = !!(snap && snap.allTraffic);

  // Status Card
  let statusTitle = on ? t('prot_on') : t('prot_off');
  let statusSub = on ? t('all_conn_sub') : t('prot_off_sub');
  if (!isOnline) {
    statusTitle = t('no_internet');
    statusSub = t('no_internet_sub');
  } else if (on && isFullPC) {
    statusTitle = t('prot_on');
    statusSub = t('all_traffic_sub');
  } else if (on && badSites.length > 0) {
    statusTitle = `${badSites.length} ${t('sites_failing')}`;
    statusSub = t('sites_failing_sub');
  } else if (on && snap && snap.sites && snap.sites.length > 0) {
    statusSub = `${snap.sites.length} ${t('sites_ok')}`;
  }

  const titleH2 = el('h2', {
    class: on ? 'on' : '',
    style: (!isOnline || (on && !isFullPC && badSites.length > 0)) ? 'color:var(--bad)' : '',
    text: statusTitle,
  });

  const textWrap = el('div', { class: 'status-text' }, [
    titleH2,
    el('p', { text: statusSub }),
  ]);

  let methodPill = '';
  let pillMuted = false;
  if (on) {
    if (isFullPC) {
      methodPill = installedStrategyName
        ? `${t('all_pc_label')} ${installedStrategyName} + DoH`
        : `${t('scope_title')}: ${t('scope_all')} (DoH)`;
    } else {
      methodPill = installedStrategyName
        ? `${t('sites_label')} ${installedStrategyName}`
        : `${t('method_prefix')} ${t('local_hosts')}`;
    }
  } else {
    methodPill = isFullPC ? t('general_off') : t('site_off');
    pillMuted = true;
  }
  textWrap.append(el('div', { class: `strategy-pill ${pillMuted ? 'muted' : ''}`, text: methodPill }));

  const toggleBtn = el('div', {
    class: `toggle ${on ? 'on' : ''}`,
    on: {
      click: async () => {
        if (busy) return;
        busy = true;
        toggleBtn.classList.add('loading');
        showJobBanner(t('preparing'));
        try {
          if (on) {
            const err = await Stop();
            if (err) {
              logErr('Stop', err);
              toast(err, true);
            } else {
              toast(t('prot_off'));
            }
            await reload(false);
          } else {
            if (!isFullPC && (!snap || !snap.sites || snap.sites.length === 0)) {
              toast(t('delete_min_warn'), true);
              return;
            }
            const err = await Start();
            if (err) {
              logErr('Start', err);
              toast(err, true);
            } else {
              toast(t('prot_on'));
            }
            await reload(false);
            reload(true); // background live probe without blocking UI
          }
        } catch (e) {
          const msg = logErr(on ? 'Stop' : 'Start', e);
          toast(msg, true);
          await reload(false);
        } finally {
          busy = false;
          hideJobBanner();
        }
      },
    },
  }, [el('div', { class: 'toggle-knob' })]);

  const statusCard = el('div', { class: 'card status-card' }, [
    textWrap,
    el('div', { class: 'status-right' }, [
      toggleBtn,
      el('div', { class: 'label', text: on ? t('on_label') : t('off_label') }),
    ]),
  ]);
  frag.append(statusCard, el('div', { class: 'gap' }));

  // Degraded Warning Banner (with overflow & IP-block protection)
  if (on && !isFullPC && badSites.length > 0 && isOnline) {
    const hasIPBlock = badSites.some((s) => s.system === 'IP-BLOCK' || s.path === 'IP-BLOCK');
    const badText = badSites.length <= 2
      ? badSites.map((s) => s.host).join(', ')
      : `${badSites[0].host} ve ${badSites.length - 1} site daha`;

    const bannerText = hasIPBlock
      ? `${badText} (${t('status_ip_block')})`
      : `${badText} (${t('sites_failing')})`;

    const warnBanner = el('div', { class: 'warn-banner' }, [
      el('span', { text: bannerText }),
      el('button', {
        class: 'btn-primary',
        text: t('update_method'),
        on: {
          click: async () => {
            if (busy) return;
            fullBusy = true;
            busy = true;
            busyTitle = t('first_run_title');
            busySub = t('uac_hint');
            busyLogs = [];
            render();
            try {
              const err = await Install();
              if (err) {
                logErr('RefreshBanner', err);
                toast(err, true);
              } else {
                toast(t('update_method'));
              }
            } catch (e) {
              const msg = logErr('RefreshBanner', e);
              toast(msg, true);
            } finally {
              fullBusy = false;
              busy = false;
              await reload(true);
            }
          },
        },
      }),
    ]);
    frag.append(warnBanner, el('div', { class: 'gap' }));
  } else if (!isOnline) {
    const warnBanner = el('div', { class: 'warn-banner' }, [
      el('span', { text: t('net_lost') }),
      el('button', {
        class: 'btn-secondary sm',
        text: t('retry_btn'),
        on: {
          click: () => {
            isOnline = navigator.onLine;
            reload(true);
          },
        },
      }),
    ]);
    frag.append(warnBanner, el('div', { class: 'gap' }));
  }

  // Scope Card: Locked to active mode when ON, fully selectable when OFF
  const segSites = el('button', {
    class: `seg-btn ${!isFullPC ? 'on' : ''} ${on && isFullPC ? 'disabled' : ''}`,
    text: t('scope_sites'),
    on: {
      click: async () => {
        if (on) {
          if (isFullPC) toast(t('scope_locked_warn'), true);
          return;
        }
        if (!isFullPC) return;
        try {
          const err = await SetScope(false);
          if (err) {
            logErr('SetScope(false)', err);
            toast(err, true);
          } else {
            await reload(false);
          }
        } catch (e) {
          const msg = logErr('SetScope(false)', e);
          toast(msg, true);
        }
      },
    },
  });

  const segPC = el('button', {
    class: `seg-btn ${isFullPC ? 'on' : ''} ${on && !isFullPC ? 'disabled' : ''}`,
    text: t('scope_all'),
    on: {
      click: async () => {
        if (on) {
          if (!isFullPC) toast(t('scope_locked_warn'), true);
          return;
        }
        if (isFullPC) return;
        try {
          const err = await SetScope(true);
          if (err) {
            logErr('SetScope(true)', err);
            toast(err, true);
          } else {
            await reload(false);
          }
        } catch (e) {
          const msg = logErr('SetScope(true)', e);
          toast(msg, true);
        }
      },
    },
  });

  const scopeNoteText = on
    ? (isFullPC ? t('scope_note_on_all') : t('scope_note_on_sites'))
    : (isFullPC ? t('scope_note_off_all') : t('scope_note_off_sites'));

  const scopeCard = el('div', { class: 'card scope-card' }, [
    el('div', { class: 'scope-label', text: t('scope_title') }),
    el('div', { class: 'seg' }, [segSites, segPC]),
    el('div', {
      class: 'scope-note',
      style: on ? 'color:var(--ink-3)' : '',
      text: scopeNoteText,
    }),
  ]);
  frag.append(scopeCard, el('div', { class: 'gap' }));

  // Main Content (Full PC shield or Sites List)
  if (isFullPC) {
    const fullBox = el('div', { class: 'card', style: 'padding:0' }, [
      el('div', { class: 'full-mode-box' }, [
        el('div', { class: 'shield-icon' }, [
          svg('M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z', 32, '1.5'),
        ]),
        el('h3', { text: t('all_conn_protected') }),
        el('p', { text: t('all_conn_sub') }),
      ]),
    ]);
    frag.append(fullBox);
  } else {
    // Sites Card
    const sitesHead = el('div', { class: 'sites-head' }, [
      el('h3', { text: t('sites_title') }),
      el('button', {
        class: 'btn-secondary sm',
        text: addOpen ? t('close_form') : t('add_site'),
        on: {
          click: () => {
            addOpen = !addOpen;
            render();
          },
        },
      }),
    ]);

    const sitesCard = el('div', { class: 'card sites-card' }, [sitesHead]);

    // Inline Add Box
    if (addOpen) {
      const addInput = el('input', {
        type: 'text',
        class: 'field sm',
        placeholder: t('site_placeholder'),
      });
      const submitBtn = el('button', {
        class: 'btn-primary sm',
        text: t('add_btn'),
        on: {
          click: async () => {
            if (busy) return;
            const h = cleanHost(addInput.value);
            if (!h) {
              toast(t('valid_domain_warn'), true);
              addInput.focus();
              return;
            }
            if (snap && snap.sites && snap.sites.some((s) => s.host === h)) {
              toast(`${h} ${t('site_already_exists')}`, true);
              addInput.focus();
              return;
            }
            showJobBanner(`${h}...`);
            try {
              const err = await ActivateHost(h);
              if (err) {
                logErr('ActivateHost', err);
                toast(err, true);
              } else {
                addOpen = false;
                await reload(true);
                toast(`${h} ${t('site_added_toast')}`);
              }
            } catch (e) {
              const msg = logErr('ActivateHost', e);
              toast(msg, true);
            } finally {
              hideJobBanner();
            }
          },
        },
      });

      addInput.addEventListener('keydown', (e) => {
        if (e.key === 'Enter') submitBtn.click();
        if (e.key === 'Escape') { addOpen = false; render(); }
      });

      const addBox = el('div', { class: 'add-box' }, [
        el('div', { style: 'font-size:.8125rem;font-weight:600;color:var(--accent)', text: t('new_site_title') }),
        el('div', { class: 'add-box-row' }, [
          addInput,
          submitBtn,
          el('button', {
            class: 'btn-ghost sm',
            text: t('cancel'),
            on: { click: () => { addOpen = false; render(); } },
          }),
        ]),
        el('div', {
          style: 'font-size:.75rem;color:var(--ink-2);margin-top:.25rem;line-height:1.3',
          text: t('subdomain_hint'),
        }),
      ]);
      sitesCard.append(addBox);
      setTimeout(() => addInput.focus(), 50);
    }

    // Site rows or empty box
    const sites = (snap && snap.sites) ? snap.sites : [];
    if (sites.length === 0) {
      sitesCard.append(el('div', { class: 'empty-box' }, [
        el('p', { text: t('empty_sites') }),
        el('button', {
          class: 'btn-secondary sm',
          text: t('add_first_site'),
          on: { click: () => { addOpen = true; render(); } },
        }),
      ]));
    } else {
      sites.forEach((s) => {
        const isBad = on && s.measured && s.system && s.system !== 'OK';
        const isMuted = !on || !s.measured;
        let stateText = t('status_checking');
        if (!on) {
          stateText = t('status_offline');
        } else if (!s.measured) {
          stateText = t('status_checking');
        } else if (s.measured) {
          if (s.system === 'OK') {
            stateText = t('status_working');
          } else if (s.system === 'IP-BLOCK' || s.path === 'IP-BLOCK') {
            stateText = t('status_ip_block');
          } else if (s.system === 'CERT-BAD' || (s.systemErr && s.systemErr.includes('x509'))) {
            stateText = t('status_dns_hijack');
          } else {
            stateText = s.systemErr || s.system || t('status_untested');
          }
        }

        const badgeClass = isBad ? 'bad' : (isMuted ? 'muted' : 'ok');
        const badgeDiv = el('div', { class: `badge ${badgeClass}` });
        if (badgeClass === 'ok') {
          badgeDiv.append(svg('M5 13l4 4L19 7', 12, '2'));
        } else if (badgeClass === 'bad') {
          badgeDiv.append(svg('M6 18L18 6M6 6l12 12', 12, '2'));
        } else {
          badgeDiv.style.backgroundColor = '#8c8c88';
        }

        const row = el('div', {
          class: 'site-row',
          style: isBad ? 'background:var(--bad-soft)' : '',
        }, [
          el('div', { class: 'site-info' }, [
            el('div', { class: 'site-host', text: s.host }),
            el('div', {
              class: `site-state ${isBad ? 'bad' : (isMuted ? 'muted' : '')}`,
              text: stateText,
            }),
          ]),
          badgeDiv,
          el('div', { class: 'site-actions' }, [
            el('button', {
              class: 'btn-ghost',
              disabled: busy,
              style: 'color:var(--bad)',
              text: t('delete_btn'),
              on: {
                click: async () => {
                  if (busy) return;
                  if (!isFullPC && sites.length <= 1) {
                    toast(t('delete_min_warn'), true);
                    return;
                  }
                  showJobBanner(`${s.host}...`);
                  try {
                    const err = await RemoveHost(s.host);
                    if (err) {
                      logErr('RemoveHost', err);
                      toast(err, true);
                    } else {
                      await reload(false);
                      toast(`${s.host} ${t('site_deleted_toast')}`);
                    }
                  } catch (e) {
                    const msg = logErr('RemoveHost', e);
                    toast(msg, true);
                  } finally {
                    hideJobBanner();
                  }
                },
              },
            }),
          ]),
        ]);
        sitesCard.append(row);
      });
    }

    frag.append(sitesCard);
  }

  return frag;
}

/* 4. Settings View (Compact) */
function renderSettingsView() {
  const container = el('div', { class: 'settings-page' });

  // Top header
  const topBar = el('div', { class: 'settings-top' }, [
    el('button', {
      class: 'settings-back',
      on: { click: () => { view = 'home'; render(); } },
    }, [
      svg('M15 19l-7-7 7-7', 14, '2.5'),
      document.createTextNode(' ' + t('back')),
    ]),
    el('div', { style: 'font-size:1.125rem;font-weight:700', text: t('settings') }),
    el('div', { style: 'width:50px' }),
  ]);

  const card = el('div', { class: 'settings-card' });

  // 1. Language Row
  const isTR = currentLang === 'tr';
  const langItem = el('div', { class: 'set-item' }, [
    el('div', {}, [
      el('div', { class: 'set-label', text: t('lang_title') }),
      el('div', { class: 'set-desc', text: t('lang_desc') }),
    ]),
    el('div', { class: 'seg' }, [
      el('button', {
        class: `seg-btn ${isTR ? 'on' : ''}`,
        text: 'Türkçe',
        on: {
          click: () => {
            if (isTR) return;
            setLanguage('tr');
            render();
          },
        },
      }),
      el('button', {
        class: `seg-btn ${!isTR ? 'on' : ''}`,
        text: 'English',
        on: {
          click: () => {
            if (!isTR) return;
            setLanguage('en');
            render();
          },
        },
      }),
    ]),
  ]);
  card.append(langItem);

  // 2. Method / Strategy Row
  const methodItem = el('div', { class: 'set-item' }, [
    el('div', {}, [
      el('div', { class: 'set-label', text: t('active_method') }),
      el('div', {
        class: 'set-desc',
        text: installedStrategyName ? `${installedStrategyName} ${t('installed_suffix')}` : t('auto_strategy'),
      }),
    ]),
    el('button', {
      class: 'btn-secondary sm',
      text: t('rescan_btn'),
      on: {
        click: async () => {
          fullBusy = true;
          busy = true;
          busyTitle = t('first_run_title');
          busySub = t('uac_hint');
          busyLogs = [];
          render();
          try {
            const err = await Install();
            if (err) {
              logErr('Install', err);
              toast(err, true);
            } else {
              toast(t('update_method'));
            }
          } catch (e) {
            const msg = logErr('Install', e);
            toast(msg, true);
          } finally {
            fullBusy = false;
            busy = false;
            await reload(true);
          }
        },
      },
    }),
  ]);
  card.append(methodItem);

  // 3. DNS Segmented & DoH Expandable Row
  const curMode = (options && options.dnsMode) ? options.dnsMode : (snap && snap.dnsMode ? snap.dnsMode : '');
  const modeKey = (curMode === 'resolver') ? 'doh' : (curMode === 'hosts' ? 'hosts' : 'none');

  let descText = t('dns_desc_none');
  if (modeKey === 'hosts') descText = t('dns_desc_hosts');
  if (modeKey === 'doh') descText = t('dns_desc_doh');

  const dnsDescEl = el('div', {
    class: 'set-desc',
    style: 'font-size:.75rem;line-height:1.4;margin-top:.25rem;color:var(--ink-2)',
    text: descText,
  });

  const dohOptionsDiv = el('div', {
    style: `display:${modeKey === 'doh' ? 'flex' : 'none'};flex-direction:column;gap:.375rem;padding-top:.25rem`,
  });

  const customDohBox = el('div', {
    style: `display:${dohProvider === 'custom' ? 'flex' : 'none'};flex-direction:column;gap:.375rem;background:var(--line-soft);padding:.5rem;border-radius:4px;margin-top:.25rem`,
  });
  const customUrlInput = el('input', {
    type: 'text',
    class: 'field sm',
    placeholder: 'DoH URL: https://...',
    value: customDohUrl || 'https://cloudflare-dns.com/dns-query',
    on: {
      input: (e) => {
        customDohUrl = e.target.value.trim();
        saveDohPrefs();
      },
    },
  });
  const customIpInput = el('input', {
    type: 'text',
    class: 'field sm',
    placeholder: 'IP Adresi: 1.1.1.1',
    value: customDohIP || '1.1.1.1',
    on: {
      input: (e) => {
        customDohIP = e.target.value.trim();
        saveDohPrefs();
      },
    },
  });
  customDohBox.append(customUrlInput, customIpInput);

  const dohSelect = el('select', {
    class: 'field sm',
    style: 'width:auto;min-width:200px',
    on: {
      change: (e) => {
        dohProvider = e.target.value;
        customDohBox.style.display = (dohProvider === 'custom') ? 'flex' : 'none';
        saveDohPrefs();
      },
    },
  }, [
    el('option', { value: 'cf', text: 'Cloudflare (1.1.1.1)' }),
    el('option', { value: 'google', text: 'Google (8.8.8.8)' }),
    el('option', { value: 'adguard', text: 'AdGuard (Reklam / Ads)' }),
    el('option', { value: 'quad9', text: 'Quad9 (Güvenlik / Security)' }),
    el('option', { value: 'nextdns', text: 'NextDNS' }),
    el('option', { value: 'custom', text: 'Özel / Custom...' }),
  ]);
  dohSelect.value = dohProvider;

  dohOptionsDiv.append(
    el('div', { style: 'display:flex;align-items:center;justify-content:space-between;gap:.5rem' }, [
      el('span', { style: 'font-size:.75rem;color:var(--ink-2);font-weight:600', text: t('doh_service_label') }),
      dohSelect,
    ]),
    customDohBox,
  );

  const saveDNS = async (targetMode) => {
    const backendVal = (targetMode === 'doh') ? 'resolver' : (targetMode === 'hosts' ? 'hosts' : '');
    showJobBanner(t('preparing'));
    try {
      const err1 = await SaveOptions(backendVal, !!(options && options.allTraffic), (options && options.serviceName) || '');
      if (err1) {
        logErr('SaveOptions', err1);
        toast(err1, true);
        return;
      }
      const err2 = await ApplyDNSMode();
      if (err2) {
        logErr('ApplyDNSMode', err2);
        toast(err2, true);
        return;
      }
      await reload(false);
      toast(t('prot_on'));
    } catch (e) {
      const msg = logErr('saveDNS', e);
      toast(msg, true);
    } finally {
      hideJobBanner();
    }
  };

  const dnsItem = el('div', { class: 'set-item col' }, [
    el('div', { style: 'display:flex;justify-content:space-between;align-items:center' }, [
      el('div', { class: 'set-label', text: t('dns_mode_title') }),
    ]),
    el('div', { class: 'seg seg-3' }, [
      el('button', {
        class: `seg-btn ${modeKey === 'none' ? 'on' : ''}`,
        text: t('dns_mode_none'),
        on: {
          click: () => {
            dnsDescEl.textContent = t('dns_desc_none');
            dohOptionsDiv.style.display = 'none';
            saveDNS('none');
          },
        },
      }),
      el('button', {
        class: `seg-btn ${modeKey === 'hosts' ? 'on' : ''}`,
        text: t('dns_mode_hosts'),
        on: {
          click: () => {
            dnsDescEl.textContent = t('dns_desc_hosts');
            dohOptionsDiv.style.display = 'none';
            saveDNS('hosts');
          },
        },
      }),
      el('button', {
        class: `seg-btn ${modeKey === 'doh' ? 'on' : ''}`,
        text: t('dns_mode_doh'),
        on: {
          click: () => {
            dnsDescEl.textContent = t('dns_desc_doh');
            dohOptionsDiv.style.display = 'flex';
            saveDNS('doh');
          },
        },
      }),
    ]),
    dnsDescEl,
    dohOptionsDiv,
  ]);
  card.append(dnsItem);

  // 4. Autostart Row
  const autostartOn = !!(options && options.autostart);
  const autostartItem = el('div', { class: 'set-item' }, [
    el('div', {}, [
      el('div', { class: 'set-label', text: t('autostart_title') }),
      el('div', { class: 'set-desc', text: t('autostart_desc') }),
    ]),
    el('div', {
      class: `toggle ${autostartOn ? 'on' : ''}`,
      on: {
        click: async () => {
          const next = !autostartOn;
          showJobBanner(t('preparing'));
          try {
            const err = await SetAutostart(next);
            if (err) {
              logErr('SetAutostart', err);
              toast(err, true);
            } else {
              await reload();
              toast(next ? '✓ ' + t('autostart_title') : t('prot_off'));
            }
          } catch (e) {
            const msg = logErr('SetAutostart', e);
            toast(msg, true);
          } finally {
            hideJobBanner();
          }
        },
      },
    }, [el('div', { class: 'toggle-knob' })]),
  ]);
  card.append(autostartItem);
  container.append(topBar, card);

  // Maintenance buttons
  const maintDiv = el('div', { style: 'margin-top:1rem' }, [
    el('div', {
      style: 'font-size:.75rem;font-weight:600;color:var(--ink-3);letter-spacing:.04em;text-transform:uppercase;margin-bottom:.5rem',
      text: t('quick_maint_title'),
    }),
    el('div', { class: 'set-actions-row' }, [
      el('button', {
        class: 'btn-secondary sm',
        text: t('refresh_addrs_btn'),
        on: {
          click: async () => {
            showJobBanner(t('preparing'));
            try {
              const err = await Refresh();
              if (err) {
                logErr('QuickRefresh', err);
                toast(err, true);
              } else {
                await reload(false);
                toast(t('refresh_addrs_btn'));
              }
            } catch (e) {
              const msg = logErr('QuickRefresh', e);
              toast(msg, true);
            } finally {
              hideJobBanner();
            }
          },
        },
      }),
      el('button', {
        class: 'btn-secondary sm',
        text: t('reset_dns_btn'),
        on: {
          click: async () => {
            showJobBanner(t('preparing'));
            try {
              const err = await UnpinDNS();
              if (err) {
                logErr('UnpinDNS', err);
                toast(err, true);
              } else {
                await reload(false);
                toast(t('reset_dns_btn'));
              }
            } catch (e) {
              const msg = logErr('UnpinDNS', e);
              toast(msg, true);
            } finally {
              hideJobBanner();
            }
          },
        },
      }),
      el('button', {
        class: 'btn-secondary sm',
        text: t('test_conn_btn'),
        on: {
          click: async () => {
            showJobBanner(t('preparing'));
            try {
              await reload(true);
              toast(t('test_conn_btn'));
            } catch (e) {
              const msg = logErr('QuickCheck', e);
              toast(msg, true);
            } finally {
              hideJobBanner();
            }
          },
        },
      }),
    ]),
  ]);
  container.append(maintDiv);

  // Prominent Factory Reset Button with double confirmation
  const resetDiv = el('div', { style: 'margin-top:1.25rem' }, [
    el('button', {
      class: 'btn-factory-reset',
      text: t('factory_reset_btn'),
      on: {
        click: async () => {
          if (!confirm(t('factory_reset_confirm1'))) return;
          if (!confirm(t('factory_reset_confirm2'))) return;
          fullBusy = true;
          busy = true;
          busyTitle = t('factory_reset_btn');
          busySub = t('uac_hint');
          busyLogs = [];
          render();
          try {
            const err = await Remove();
            if (err) {
              logErr('Remove', err);
              toast(err, true);
            } else {
              toast('Sıfırlandı / Reset done');
            }
          } catch (e) {
            const msg = logErr('Remove', e);
            toast(msg, true);
          } finally {
            fullBusy = false;
            busy = false;
            await reload(true);
          }
        },
      },
    }),
  ]);
  container.append(resetDiv);

  return container;
}

/* Event listeners & Initial wiring */
function initEvents() {
  // Titlebar controls
  $('winMin')?.addEventListener('click', () => {
    if (typeof WindowMinimise === 'function' && window.runtime) WindowMinimise();
  });
  $('winMax')?.addEventListener('click', () => {
    if (typeof WindowToggleMaximise === 'function' && window.runtime) WindowToggleMaximise();
  });
  $('winClose')?.addEventListener('click', () => {
    if (typeof WindowHide === 'function' && window.runtime) WindowHide();
  });

  $('settingsBtn')?.addEventListener('click', () => {
    view = (view === 'settings') ? 'home' : 'settings';
    render();
  });

  $('jobCancelBtn')?.addEventListener('click', async () => {
    try {
      await CancelJob();
    } catch (_) { /* ignore */ }
    hideJobBanner();
  });

  // Global Keyboard Shortcuts
  window.addEventListener('keydown', (e) => {
    if (e.key === 'Escape') {
      if (addOpen) {
        addOpen = false;
        render();
      } else if (view === 'settings') {
        view = 'home';
        render();
      }
    }
  });

  // Network status listeners
  window.addEventListener('online', () => {
    if (!isOnline) {
      isOnline = true;
      reload(false);
    }
  });
  window.addEventListener('offline', () => {
    if (isOnline) {
      isOnline = false;
      render();
    }
  });

  // Wails Backend Events
  safeEventsOn('job:start', (title) => {
    busy = true;
    busyTitle = JOB_TITLES[title] || title || 'İşlem yapılıyor';
    busyLogs = [];
    if (fullBusy) render();
  });

  safeEventsOn('job:line', (line) => {
    const sLine = String(line);
    busyLogs.push(sLine);
    if (fullBusy) {
      const box = document.querySelector('.log-preview');
      if (box) {
        box.textContent = busyLogs.join('\n');
        box.scrollTop = box.scrollHeight;
      }
      const stepBadge = document.querySelector('.busy-step-badge');
      const detailText = document.querySelector('.busy-detail-text');
      if (stepBadge) {
        if (sLine.includes('step 1/3')) stepBadge.textContent = 'Adım 1/3: Engel türü inceleniyor...';
        else if (sLine.includes('step 2/3')) stepBadge.textContent = 'Adım 2/3: Engel aşma yöntemleri taranıyor...';
        else if (sLine.includes('step 3/3')) stepBadge.textContent = 'Adım 3/3: Servis kuruluyor ve doğrulanıyor...';
      }
      if (detailText) {
        const mScreen = sLine.match(/screened\s+(\d+)\s+candidates/i);
        if (mScreen) detailText.textContent = `${mScreen[1]} yöntem test edildi`;
        const mChosen = sLine.match(/chosen:\s+([^\s]+)/i);
        if (mChosen) detailText.textContent = `Seçilen yöntem: ${mChosen[1]}`;
      }
    }
  });

  safeEventsOn('job:done', (msg) => {
    busy = false;
    fullBusy = false;
    if (msg) toast(String(msg));
    reload();
  });

  safeEventsOn('app:error', (err) => {
    if (err) toast(String(err));
  });

  safeEventsOn('tray:check', () => {
    view = 'home';
    reload(true);
  });

  // Periodic subtle background sync (every 12s when visible)
  setInterval(() => {
    if (!busy && !document.hidden && view === 'home') {
      reload(false);
    }
  }, 12000);
}

// Initial Boot
document.addEventListener('DOMContentLoaded', () => {
  initEvents();
  reload(false);
});
