// i18n Dictionary for dpi UI (Turkish & English)

export const DICT = {
  tr: {
    // Window & Title
    settings: 'Ayarlar',
    minimize: 'Simge durumuna küçült',
    maximize: 'Büyüt',
    close: 'Kapat (Tepsiye küçülür)',
    back: 'Geri Dön',

    // Status Card
    prot_on: 'Koruma açık',
    prot_off: 'Koruma kapalı',
    sites_ok: 'site sorunsuz açılıyor.',
    all_traffic_sub: 'Tüm internet bağlantıları korunuyor.',
    prot_off_sub: 'Arka plan servisi durduruldu.',
    no_internet: 'İnternet bağlantısı yok',
    no_internet_sub: 'Lütfen bilgisayarınızın ağ bağlantısını kontrol edin.',
    sites_failing: 'site açılmıyor',
    sites_failing_sub: 'Servis sağlayıcının engelleme yöntemi değişmiş olabilir.',
    on_label: 'Açık',
    off_label: 'Kapalı',
    method_prefix: 'Yöntem:',
    all_pc_label: 'Tüm PC:',
    sites_label: 'Siteler:',
    doh_transparent: 'Şeffaf DNS (DoH)',
    local_hosts: 'Yerel DNS (hosts)',
    general_off: 'Genel koruma kapalı',
    site_off: 'Site koruması kapalı',

    // Scope Card
    scope_title: 'Kapsam',
    scope_sites: 'Sadece siteler',
    scope_all: 'Tüm bilgisayar',
    scope_note_on_all: 'Tüm internet şifreli tünelle korunuyor. Değiştirmek için yukarıdan kapatın.',
    scope_note_on_sites: 'Listeli siteler açılıyor. Alt alan adları için Tüm Bilgisayar moduna geçin.',
    scope_note_off_all: 'Tüm internet trafiği şifreli tünelle korunur. Oyunlara ve anti-hile yazılımlarına etki edebilir.',
    scope_note_off_sites: 'Listeli siteler ve www varyantları açılır. Diğer alt alan adları için Tüm Bilgisayar modunu seçin.',
    scope_locked_warn: 'Modu değiştirmek için önce korumayı durdurun',

    // Full Mode Card
    all_conn_protected: 'Tüm bağlantılar korunuyor',
    all_conn_sub: 'Engelli siteler otomatik aşılır. Tek tek site eklemenize gerek yoktur.',

    // Sites Card
    sites_title: 'Siteler',
    add_site: '+ Site ekle',
    close_form: '- Formu Kapat',
    new_site_title: 'Yeni Site Ekle',
    site_placeholder: 'alanadı.com veya https://...',
    add_btn: 'Ekle',
    cancel: 'Vazgeç',
    close_btn: 'Kapat',
    subdomain_hint: 'İpucu: www varyantı otomatik eklenir. Farklı alt alan adları (subdomain) için Tüm Bilgisayar modunu kullanın.',
    empty_sites: 'Henüz kayıtlı bir site yok.',
    add_first_site: 'İlk siteyi ekle',
    delete_btn: 'Sil',
    delete_min_warn: 'En az bir site listede kalmalıdır',
    site_already_exists: 'zaten listede var',
    site_added_toast: 'eklendi ve doğrulandı',
    site_deleted_toast: 'silindi',
    valid_domain_warn: 'Lütfen geçerli bir alan adı girin',

    // Site row statuses
    status_checking: 'Doğrulanıyor...',
    status_offline: 'Koruma kapalı',
    status_working: 'Açılıyor',
    status_ip_block: 'Doğrudan IP engeli (DPI yetersiz)',
    status_dns_hijack: 'ISS engel sayfası (DNS zehirlenmesi)',
    status_untested: 'Henüz test edilmedi',

    // Warning Banner
    update_method: 'Yöntemi Güncelle',
    retry_btn: 'Tekrar Dene',
    net_lost: 'İnternet bağlantısı kesildi',

    // First Run / Profiles
    first_run_title: 'Engelleme Yöntemi Kurulumu',
    first_run_sub: 'Servis sağlayıcınıza uygun hazır profili seçin veya engelli bir site üzerinden otomatik tarama yapın.',
    select_isp_label: 'OPERATÖR / SERVİS SAĞLAYICI:',
    apply_profile_btn: 'Bu Profili Kur ve Başlat',
    quick_profiles_label: 'HIZLI PROFİLLER (ÖNERİLEN)',
    profile_turknet_title: 'TurkNet (Ev / VDSL / Fiber)',
    profile_turknet_desc: 'Sadece DNS engellemesi. 0 saniyede şeffaf DoH ile anında hazır.',
    profile_turkcell_title: 'Turkcell Mobil (Hücresel)',
    profile_turkcell_desc: 'DPI TCP Reset engellemesi. Doğrulanmış yöntemle taramasız anında hazır.',
    profile_vodafone_title: 'Vodafone Mobil (Hücresel)',
    profile_vodafone_desc: 'DPI + DNS engellemesi. Doğrulanmış yöntemle taramasız anında hazır.',
    custom_scan_title: 'Özel Tarama (Diğer Operatörler)',
    custom_scan_desc: 'Engelli bir site adı yazarak operatörün engelleme yöntemini otomatik tespit edin.',
    first_run_input_placeholder: 'örnek: discord.com',
    scan_and_install_btn: 'Engeli bul ve kur',
    scan_hint: 'İpucu: Yöntemin tespit edilebilmesi için erişemediğiniz (engelli) bir site girin.',

    // Busy / Progress
    step1: 'Adım 1/3: Engel türü inceleniyor...',
    step2: 'Adım 2/3: Engel aşma yöntemleri taranıyor...',
    step3: 'Adım 3/3: Servis kuruluyor ve doğrulanıyor...',
    preparing: 'Hazırlanıyor...',
    candidates_tested: 'yöntem test edildi',
    chosen_method: 'Seçilen yöntem:',
    show_details: 'Ayrıntıyı göster',
    hide_details: 'Ayrıntıyı gizle',
    uac_hint: 'Yönetici onayı istenebilir — görev çubuğunda yanıp sönen bir onay penceresi çıkarsa onay verin.',

    // Settings View
    active_method: 'Aktif Yöntem',
    auto_strategy: 'Otomatik strateji',
    installed_suffix: '(Kurulu)',
    rescan_btn: 'Yeniden Bul',
    dns_mode_title: 'DNS Koruma Modu',
    dns_mode_none: 'Dokunma',
    dns_mode_hosts: 'Hosts Dosyası',
    dns_mode_doh: 'Şifreli DoH',
    dns_desc_none: 'Sistem DNS ayarlarına dokunulmaz. ISS DNS engelleri aşılmaz.',
    dns_desc_hosts: 'Sadece engelli sitelerin gerçek IP adresleri yerel hosts dosyasına yazılır. En hızlı ve risksiz yöntemdir.',
    dns_desc_doh: 'Tüm DNS sorguları şifreli tünelle (DoH) ISS\'den gizlenir. ISS hiçbir DNS sorgunuzu göremez veya zehirleyemez.',
    doh_service_label: 'DoH Sağlayıcı:',
    autostart_title: 'Windows ile Başlat (Arka Plan Servisi)',
    autostart_desc: 'Sistem açılışında arka planda Windows Servisi olarak başlar. Uygulama veya saatin yanında simge açılmasına gerek kalmaz.',
    lang_title: 'Uygulama Dili (Language)',
    lang_desc: 'Arayüz dilini değiştirin',
    quick_maint_title: 'HIZLI BAKIM',
    refresh_addrs_btn: 'Adresleri Yenile',
    reset_dns_btn: 'DNS Sıfırla',
    test_conn_btn: 'Bağlantı Testi',
    factory_reset_btn: 'Tüm Servisleri ve Ayarları Kaldır',
    factory_reset_confirm1: 'Tüm servisler durdurulacak, hosts dosyası temizlenecek ve ayarlar sıfırlanacak. Devam edilsin mi?',
    factory_reset_confirm2: 'Bu işlem geri alınamaz. Kesinlikle tüm kurulumu sıfırlamak istiyor musunuz?',
  },

  en: {
    // Window & Title
    settings: 'Settings',
    minimize: 'Minimize',
    maximize: 'Maximize',
    close: 'Close (Minimizes to tray)',
    back: 'Go Back',

    // Status Card
    prot_on: 'Protection active',
    prot_off: 'Protection disabled',
    sites_ok: 'site(s) accessible.',
    all_traffic_sub: 'All network connections are protected.',
    prot_off_sub: 'Background service is stopped.',
    no_internet: 'No internet connection',
    no_internet_sub: 'Please check your network connection.',
    sites_failing: 'site(s) unreachable',
    sites_failing_sub: 'ISP blocking method may have changed.',
    on_label: 'On',
    off_label: 'Off',
    method_prefix: 'Method:',
    all_pc_label: 'Full PC:',
    sites_label: 'Sites:',
    doh_transparent: 'Transparent DNS (DoH)',
    local_hosts: 'Local DNS (hosts)',
    general_off: 'Full PC protection disabled',
    site_off: 'Sites protection disabled',

    // Scope Card
    scope_title: 'Scope',
    scope_sites: 'Only sites',
    scope_all: 'Full computer',
    scope_note_on_all: 'All internet traffic is secured with encrypted tunnel. Turn off above to change.',
    scope_note_on_sites: 'Targeted sites are active. Use Full Computer mode for all subdomains.',
    scope_note_off_all: 'All internet traffic is covered. May interfere with anti-cheat software.',
    scope_note_off_sites: 'Only listed sites and www variants are handled. Use Full Computer mode for all subdomains.',
    scope_locked_warn: 'Turn off protection first to change mode',

    // Full Mode Card
    all_conn_protected: 'All connections protected',
    all_conn_sub: 'Blocked websites are bypassed automatically. No need to add sites manually.',

    // Sites Card
    sites_title: 'Sites',
    add_site: '+ Add site',
    close_form: '- Close form',
    new_site_title: 'Add New Site',
    site_placeholder: 'domain.com or https://...',
    add_btn: 'Add',
    cancel: 'Cancel',
    close_btn: 'Close',
    subdomain_hint: 'Hint: www variant is added automatically. Use Full Computer mode for wildcard subdomains.',
    empty_sites: 'No sites registered yet.',
    add_first_site: 'Add first site',
    delete_btn: 'Delete',
    delete_min_warn: 'At least one site must remain in the list',
    site_already_exists: 'is already in the list',
    site_added_toast: 'added and verified',
    site_deleted_toast: 'deleted',
    valid_domain_warn: 'Please enter a valid domain name',

    // Site row statuses
    status_checking: 'Verifying...',
    status_offline: 'Protection off',
    status_working: 'Accessible',
    status_ip_block: 'Direct IP block (DPI bypass insufficient)',
    status_dns_hijack: 'ISP block page (DNS poisoning)',
    status_untested: 'Not tested yet',

    // Warning Banner
    update_method: 'Update Method',
    retry_btn: 'Retry',
    net_lost: 'Internet connection lost',

    // First Run / Profiles
    first_run_title: 'Bypass Method Setup',
    first_run_sub: 'Choose an instant profile for your ISP or run an automatic scan using a blocked site.',
    select_isp_label: 'OPERATOR / SERVICE PROVIDER:',
    apply_profile_btn: 'Deploy Selected Profile',
    quick_profiles_label: 'INSTANT PROFILES (RECOMMENDED)',
    profile_turknet_title: 'TurkNet (Home / VDSL / Fiber)',
    profile_turknet_desc: 'DNS-only blocking. Ready instantly in 0s using transparent DoH.',
    profile_turkcell_title: 'Turkcell Mobile (Cellular)',
    profile_turkcell_desc: 'DPI TCP Reset blocking. Pre-configured with multidisorder strategy, zero wait.',
    profile_vodafone_title: 'Vodafone Mobile (Cellular)',
    profile_vodafone_desc: 'DPI + DNS blocking. Pre-configured with multidisorder strategy, zero wait.',
    custom_scan_title: 'Custom Scan (Other ISPs)',
    custom_scan_desc: 'Enter any blocked domain to automatically detect and deploy your ISP\'s bypass method.',
    first_run_input_placeholder: 'e.g. discord.com',
    scan_and_install_btn: 'Find and deploy bypass',
    scan_hint: 'Hint: Enter a site you currently cannot access so the tool can detect the block.',

    // Busy / Progress
    step1: 'Step 1/3: Analyzing block type...',
    step2: 'Step 2/3: Scanning bypass methods...',
    step3: 'Step 3/3: Installing and verifying service...',
    preparing: 'Preparing...',
    candidates_tested: 'candidates tested',
    chosen_method: 'Chosen method:',
    show_details: 'Show details',
    hide_details: 'Hide details',
    uac_hint: 'Administrator consent may be requested — accept the flashing taskbar prompt if shown.',

    // Settings View
    active_method: 'Active Method',
    auto_strategy: 'Automatic strategy',
    installed_suffix: '(Installed)',
    rescan_btn: 'Rescan',
    dns_mode_title: 'DNS Protection Mode',
    dns_mode_none: 'System Default',
    dns_mode_hosts: 'Hosts File',
    dns_mode_doh: 'Encrypted DoH',
    dns_desc_none: 'System resolver is left untouched. ISP DNS blocks will not be bypassed.',
    dns_desc_hosts: 'Only blocked domain IPs are pinned to Windows hosts file. Fastest, zero-risk method.',
    dns_desc_doh: 'All DNS queries are tunneled via encrypted DoH (Cloudflare). ISP cannot inspect or forge DNS.',
    doh_service_label: 'DoH Provider:',
    autostart_title: 'Start with Windows (Background Service)',
    autostart_desc: 'Starts in the background as a Windows Service on system boot. The application or tray icon does not need to be open.',
    lang_title: 'Interface Language',
    lang_desc: 'Change application display language',
    quick_maint_title: 'QUICK MAINTENANCE',
    refresh_addrs_btn: 'Refresh Addresses',
    reset_dns_btn: 'Reset DNS',
    test_conn_btn: 'Connection Test',
    factory_reset_btn: 'Remove All Services & Settings',
    factory_reset_confirm1: 'All services will be stopped, hosts file cleaned, and all settings reset. Proceed?',
    factory_reset_confirm2: 'This action cannot be undone. Are you sure you want to reset everything?',
  },
};

// Active language state
export let currentLang = 'en';

export function initLanguage() {
  try {
    const saved = localStorage.getItem('dpi.lang');
    if (saved === 'tr' || saved === 'en') {
      currentLang = saved;
      return currentLang;
    }
  } catch (_) { /* ignore */ }

  const nav = (typeof navigator !== 'undefined' && (navigator.language || navigator.userLanguage) || '').toLowerCase();
  currentLang = nav.startsWith('tr') ? 'tr' : 'en';
  return currentLang;
}

export function setLanguage(lang) {
  if (lang !== 'tr' && lang !== 'en') return;
  currentLang = lang;
  try {
    localStorage.setItem('dpi.lang', lang);
  } catch (_) { /* ignore */ }
}

export function t(key) {
  const d = DICT[currentLang] || DICT.en;
  return d[key] || DICT.en[key] || key;
}
