export namespace main {
	
	export class Diagnosis {
	    headline: string;
	    detail: string;
	    layers: number;
	    measured: boolean;
	    tone: string;
	
	    static createFrom(source: any = {}) {
	        return new Diagnosis(source);
	    }
	
	    constructor(source: any = {}) {
	        if ('string' === typeof source) source = JSON.parse(source);
	        this.headline = source["headline"];
	        this.detail = source["detail"];
	        this.layers = source["layers"];
	        this.measured = source["measured"];
	        this.tone = source["tone"];
	    }
	}
	export class NextStep {
	    title: string;
	    detail: string;
	    action: string;
	    label: string;
	    tone: string;
	
	    static createFrom(source: any = {}) {
	        return new NextStep(source);
	    }
	
	    constructor(source: any = {}) {
	        if ('string' === typeof source) source = JSON.parse(source);
	        this.title = source["title"];
	        this.detail = source["detail"];
	        this.action = source["action"];
	        this.label = source["label"];
	        this.tone = source["tone"];
	    }
	}
	export class OptionsView {
	    dnsMode: string;
	    allTraffic: boolean;
	    serviceName: string;
	    autostart: boolean;
	    configPath: string;
	    defaultName: string;
	
	    static createFrom(source: any = {}) {
	        return new OptionsView(source);
	    }
	
	    constructor(source: any = {}) {
	        if ('string' === typeof source) source = JSON.parse(source);
	        this.dnsMode = source["dnsMode"];
	        this.allTraffic = source["allTraffic"];
	        this.serviceName = source["serviceName"];
	        this.autostart = source["autostart"];
	        this.configPath = source["configPath"];
	        this.defaultName = source["defaultName"];
	    }
	}
	export class ProfileView {
	    strategy: string;
	    hosts: string[];
	    rotating: boolean;
	    unreadable: boolean;
	
	    static createFrom(source: any = {}) {
	        return new ProfileView(source);
	    }
	
	    constructor(source: any = {}) {
	        if ('string' === typeof source) source = JSON.parse(source);
	        this.strategy = source["strategy"];
	        this.hosts = source["hosts"];
	        this.rotating = source["rotating"];
	        this.unreadable = source["unreadable"];
	    }
	}
	export class ReportEntryView {
	    strategy: string;
	    tier: string;
	    medianMs: number;
	    spreadMs: number;
	    successes: number;
	    attempts: number;
	    chosen: boolean;
	
	    static createFrom(source: any = {}) {
	        return new ReportEntryView(source);
	    }
	
	    constructor(source: any = {}) {
	        if ('string' === typeof source) source = JSON.parse(source);
	        this.strategy = source["strategy"];
	        this.tier = source["tier"];
	        this.medianMs = source["medianMs"];
	        this.spreadMs = source["spreadMs"];
	        this.successes = source["successes"];
	        this.attempts = source["attempts"];
	        this.chosen = source["chosen"];
	    }
	}
	export class ReportView {
	    takenAt: string;
	    chosen: string;
	    describes: boolean;
	    medianMs: number;
	    spreadMs: number;
	    successes: number;
	    attempts: number;
	    tied: number;
	    ranked: number;
	    screened: number;
	    unverified: number;
	    noiseMs: number;
	    group: ReportEntryView[];
	
	    static createFrom(source: any = {}) {
	        return new ReportView(source);
	    }
	
	    constructor(source: any = {}) {
	        if ('string' === typeof source) source = JSON.parse(source);
	        this.takenAt = source["takenAt"];
	        this.chosen = source["chosen"];
	        this.describes = source["describes"];
	        this.medianMs = source["medianMs"];
	        this.spreadMs = source["spreadMs"];
	        this.successes = source["successes"];
	        this.attempts = source["attempts"];
	        this.tied = source["tied"];
	        this.ranked = source["ranked"];
	        this.screened = source["screened"];
	        this.unverified = source["unverified"];
	        this.noiseMs = source["noiseMs"];
	        this.group = this.convertValues(source["group"], ReportEntryView);
	    }
	
		convertValues(a: any, classs: any, asMap: boolean = false): any {
		    if (!a) {
		        return a;
		    }
		    if (a.slice && a.map) {
		        return (a as any[]).map(elem => this.convertValues(elem, classs));
		    } else if ("object" === typeof a) {
		        if (asMap) {
		            for (const key of Object.keys(a)) {
		                a[key] = new classs(a[key]);
		            }
		            return a;
		        }
		        return new classs(a);
		    }
		    return a;
		}
	}
	export class SiteView {
	    host: string;
	    dns: string;
	    path: string;
	    system: string;
	    systemErr: string;
	    addrs: string[];
	    missing: string[];
	    covered: boolean;
	    v6Unknown: boolean;
	    pinned: boolean;
	    pinStale: boolean;
	    measured: boolean;
	    measuredAt: string;
	
	    static createFrom(source: any = {}) {
	        return new SiteView(source);
	    }
	
	    constructor(source: any = {}) {
	        if ('string' === typeof source) source = JSON.parse(source);
	        this.host = source["host"];
	        this.dns = source["dns"];
	        this.path = source["path"];
	        this.system = source["system"];
	        this.systemErr = source["systemErr"];
	        this.addrs = source["addrs"];
	        this.missing = source["missing"];
	        this.covered = source["covered"];
	        this.v6Unknown = source["v6Unknown"];
	        this.pinned = source["pinned"];
	        this.pinStale = source["pinStale"];
	        this.measured = source["measured"];
	        this.measuredAt = source["measuredAt"];
	    }
	}
	export class Snapshot {
	    serviceName: string;
	    service: string;
	    driver: string;
	    strays: number;
	    scope: string;
	    installed: boolean;
	    running: boolean;
	    addresses: string[];
	    ipv6Count: number;
	    profiles: ProfileView[];
	    sites: SiteView[];
	    dnsMode: string;
	    allTraffic: boolean;
	    configured: boolean;
	    checkedAt: string;
	    cliPath: string;
	    report?: ReportView;
	    next: NextStep;
	    diagnosis: Diagnosis;
	    note: string;
	
	    static createFrom(source: any = {}) {
	        return new Snapshot(source);
	    }
	
	    constructor(source: any = {}) {
	        if ('string' === typeof source) source = JSON.parse(source);
	        this.serviceName = source["serviceName"];
	        this.service = source["service"];
	        this.driver = source["driver"];
	        this.strays = source["strays"];
	        this.scope = source["scope"];
	        this.installed = source["installed"];
	        this.running = source["running"];
	        this.addresses = source["addresses"];
	        this.ipv6Count = source["ipv6Count"];
	        this.profiles = this.convertValues(source["profiles"], ProfileView);
	        this.sites = this.convertValues(source["sites"], SiteView);
	        this.dnsMode = source["dnsMode"];
	        this.allTraffic = source["allTraffic"];
	        this.configured = source["configured"];
	        this.checkedAt = source["checkedAt"];
	        this.cliPath = source["cliPath"];
	        this.report = this.convertValues(source["report"], ReportView);
	        this.next = this.convertValues(source["next"], NextStep);
	        this.diagnosis = this.convertValues(source["diagnosis"], Diagnosis);
	        this.note = source["note"];
	    }
	
		convertValues(a: any, classs: any, asMap: boolean = false): any {
		    if (!a) {
		        return a;
		    }
		    if (a.slice && a.map) {
		        return (a as any[]).map(elem => this.convertValues(elem, classs));
		    } else if ("object" === typeof a) {
		        if (asMap) {
		            for (const key of Object.keys(a)) {
		                a[key] = new classs(a[key]);
		            }
		            return a;
		        }
		        return new classs(a);
		    }
		    return a;
		}
	}

}

