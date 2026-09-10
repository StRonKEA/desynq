package main

import "fmt"

// NextStep is the single thing worth doing right now.
//
// It exists because the window shipped without it and was unusable for exactly
// that reason: adding a site, measuring it and installing a strategy are three
// separate steps, and nothing on screen said which one you were on or what came
// next. A user should never have to know the order.
//
// The precedence below is not cosmetic — it is the same order `dpi doctor`
// reports in, and for the same reason. Scope drift comes before effectiveness
// because a host outside the kernel filter fails exactly as a dead strategy
// does, and the remedies are opposite: refresh the addresses, or search again.
// Getting that order wrong sends the user to rebuild a strategy that was never
// broken.
type NextStep struct {
	Title  string `json:"title"`
	Detail string `json:"detail"`
	// Action names the button, empty when there is nothing to press.
	Action string `json:"action"`
	Label  string `json:"label"`
	// Tone is ok, warn, bad or neutral.
	Tone string `json:"tone"`
}

// Action values the window knows how to run.
const (
	actionAdd     = "add"
	actionCheck   = "check"
	actionInstall = "install"
	actionRefresh = "refresh"
	actionPin     = "pin"
)

func nextStep(s Snapshot) NextStep {
	if len(s.Sites) == 0 {
		return NextStep{
			Title:  "Engellenen bir site ekleyin",
			Detail: "Önce bir site yazın. Test edilince engelin nerede olduğu bulunur.",
			Action: actionAdd,
			Label:  "Site ekle",
			Tone:   "neutral",
		}
	}

	// A stray engine is reported before anything else because it silently
	// alters traffic and makes every measurement that follows a lie.
	if s.Strays > 0 {
		return NextStep{
			Title: fmt.Sprintf("Başka bir araç hâlâ çalışıyor (%d süreç)", s.Strays),
			Detail: "Ölçüm yanlış çıkar. Görev Yöneticisi’nden winws2.exe’yi kapatın " +
				"veya yönetici olarak: taskkill /IM winws2.exe /F",
			Tone: "bad",
		}
	}

	var unmeasured, blocked, dnsForged, uncovered, working int
	var firstBlocked, firstForged string
	for _, site := range s.Sites {
		if !site.Measured {
			unmeasured++
			continue
		}
		if s.Installed && !site.Covered {
			uncovered++
		}
		// A desync strategy is the answer only to a path-layer failure; DNS is
		// fixed elsewhere and an IP-level block is out of reach of both.
		if site.Path == "RESET" || site.Path == "TIMEOUT" || site.Path == "UNKNOWN" {
			blocked++
			if firstBlocked == "" {
				firstBlocked = site.Host
			}
		}
		// The browser layer is the one the user experiences. A name that
		// resolves to a block page fails here while the other two look fine.
		if site.System != "OK" && site.System != "" && site.DNS != "OK" && !site.Pinned {
			dnsForged++
			if firstForged == "" {
				firstForged = site.Host
			}
		}
		if site.System == "OK" {
			working++
		}
	}

	if unmeasured == len(s.Sites) {
		return NextStep{
			Title:  "Siteler henüz test edilmedi",
			Detail: "Her site için kısa bir kontrol yapılır. Bilgisayara bir şey kurulmaz.",
			Action: actionCheck,
			Label:  "Test et",
			Tone:   "neutral",
		}
	}
	if unmeasured > 0 {
		return NextStep{
			Title:  fmt.Sprintf("%d site henüz test edilmedi", unmeasured),
			Detail: "Yeni eklenen siteler de kontrol edilmeli; operatör değişince sonuç değişebilir.",
			Action: actionCheck,
			Label:  "Test et",
			Tone:   "neutral",
		}
	}

	// Before effectiveness: a host the filter no longer covers looks exactly
	// like a strategy that stopped working, and reinstalling the strategy is
	// the wrong repair.
	if uncovered > 0 {
		return NextStep{
			Title:  fmt.Sprintf("%d site koruma dışında kaldı", uncovered),
			Detail: "Yöntem aynı; adres listesi eskidi. Listeyi yenilemek yeterli.",
			Action: actionRefresh,
			Label:  "Listeyi yenile",
			Tone:   "warn",
		}
	}

	if blocked > 0 && !s.Installed {
		return NextStep{
			Title:  firstBlocked + " bağlantısı kesiliyor",
			Detail: "Gerçek adrese gidiliyor ama bağlantı kopuyor. Bunun için bir yöntem bulunur; bir kez yönetici onayı ister.",
			Action: actionInstall,
			Label:  "Çözümü bul ve kur",
			Tone:   "bad",
		}
	}

	if dnsForged > 0 {
		return NextStep{
			Title:  firstForged + " yanlış adrese yönlendiriliyor",
			Detail: "Bağlantı düzeltmesi yetmez; tarayıcı yanlış sunucuya gidiyor. Sadece listedeki sitelerin gerçek adresleri yazılır.",
			Action: actionPin,
			Label:  "Adresleri düzelt",
			Tone:   "bad",
		}
	}

	if blocked > 0 {
		return NextStep{
			Title:  firstBlocked + " hâlâ açılmıyor",
			Detail: "Kurulu yöntem bu hatta işe yaramıyor olabilir (operatör değişince olur). Yeniden aranır.",
			Action: actionInstall,
			Label:  "Yeniden ara",
			Tone:   "bad",
		}
	}

	if working < len(s.Sites) {
		return NextStep{
			Title:  "Bazı siteler açılıyor, bazıları açılmıyor",
			Detail: "Bu araçtan bilinen bir engel görünmüyor. Her satırın durumuna bakın.",
			Tone:   "warn",
		}
	}

	return NextStep{
		Title:  fmt.Sprintf("%d site de açılıyor", len(s.Sites)),
		Detail: "Tarayıcının gördüğü gibi doğrulandı. Operatör ayarı değişirse site yine kapanabilir; o zaman yeniden test edin.",
		Action: actionCheck,
		Label:  "Yeniden test et",
		Tone:   "ok",
	}
}

// Diagnosis is what the provider is doing, in one sentence, for the headline.
//
// It is about the LINK, not a site: the same DPI box inspects every name, so a
// block found on one is the block the user has. That is why the window leads
// with this rather than with whichever site happens to be selected.
type Diagnosis struct {
	Headline string `json:"headline"`
	Detail   string `json:"detail"`
	// Layers is how many of the two are censored: 0, 1 or 2. The window uses
	// it to decide whether a single scope control can honestly stand for both.
	Layers int `json:"layers"`
	// Measured is false until something has actually been probed. The window
	// must not claim a connection is cheap to cover machine-wide before it has
	// any evidence for that - an unproven claim in the interface is the exact
	// failure this tool keeps guarding against.
	Measured bool   `json:"measured"`
	Tone     string `json:"tone"`
}

func diagnose(s Snapshot) Diagnosis {
	var dnsBad, pathBad, measured int
	for _, site := range s.Sites {
		if !site.Measured {
			continue
		}
		measured++
		// SUSPECT alone is not proof, but when the browser path fails while the
		// real-address path is fine, the resolver is lying in a way the window
		// used to summarise as "nothing blocked".
		if site.DNS == "HIJACKED" || site.DNS == "ABSENT" || site.System == "CERT-BAD" ||
			(site.DNS == "SUSPECT" && site.System != "OK" && site.System != "" && site.Path == "OK") {
			dnsBad++
		}
		if site.Path == "RESET" || site.Path == "TIMEOUT" {
			pathBad++
		}
	}

	switch {
	case measured == 0:
		return Diagnosis{
			Headline: "Henüz test yok",
			Detail:   "Açamadığınız bir site ekleyin; engelin nerede olduğu bulunur.",
			Tone:     "neutral",
		}
	case dnsBad > 0 && pathBad > 0:
		return Diagnosis{
			Measured: true,
			Headline: "İki yerde birden engelleniyor",
			Detail:   "Hem yanlış adres veriliyor hem bağlantı kesiliyor. İkisini de düzeltmek gerekir.",
			Layers:   2, Tone: "bad",
		}
	case dnsBad > 0:
		return Diagnosis{
			Measured: true,
			Headline: "Sadece adres yönlendirmesi bozuk",
			Detail:   "Bağlantının kendisine dokunulmuyor; sürücü gerekmez, oyunlara da karışmaz.",
			Layers:   1, Tone: "bad",
		}
	case pathBad > 0:
		return Diagnosis{
			Measured: true,
			Headline: "Bağlantı yolda kesiliyor",
			Detail:   "Adres doğru; site adı geçince bağlantı kopuyor. Bunun için yöntem bulunur.",
			Layers:   1, Tone: "bad",
		}
	default:
		return Diagnosis{
			Measured: true,
			Headline: "Şu an engel görünmüyor",
			Detail:   "Kontrol edilen siteler tarayıcıda da açılıyor.",
			Tone:     "ok",
		}
	}
}
